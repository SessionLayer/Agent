//! SessionLayer Agent binary.
//!
//! Session Twelve: the Agent joins the platform and maintains a renewable mTLS
//! identity. Startup order is security-load-bearing:
//!   1. version query short-circuit (no side effects);
//!   2. telemetry;
//!   3. install the single TLS crypto provider (fail closed);
//!   4. **refuse to run as root** (fail closed) — BEFORE any credential work;
//!   5. `run`: open the data-dir (single-writer lock), load-or-enroll the
//!      identity, then drive the renew-ahead loop until shutdown.
//!
//! The dial-back data path arrives in Session Thirteen.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use sessionlayer_agent::config::{
    parse_splice_addr, AgentConfig, GatewayConfig, GatewayEndpoint, JoinConfig, RenewConfig,
    DEFAULT_CP_ENDPOINT, DEFAULT_CP_SERVER_NAME, DEFAULT_DATA_DIR, DEFAULT_MAX_CONCURRENT_SPLICES,
    DEFAULT_MIN_CONTROL_CHANNELS, DEFAULT_SPLICE_ADDR,
};
use sessionlayer_agent::gateway::GatewayClient;
use sessionlayer_agent::identity::{self, IdentityStore, RenewAhead, RenewAheadConfig};
use sessionlayer_agent::mtls::ChannelParams;
use sessionlayer_agent::{
    hardening, init_process, privilege, supervisor, telemetry, version, LONG_VERSION,
};

/// Default Gateway enrolled name (dev; overridden in every real deploy).
const DEFAULT_GATEWAY_SERVER_NAME: &str = "gateway";

#[derive(Debug, Parser)]
#[command(
    name = "sessionlayer-agent",
    version = env!("CARGO_PKG_VERSION"),
    long_version = LONG_VERSION,
    about = "SessionLayer Agent — per-node outbound connector (join + renewable mTLS identity).",
    disable_help_subcommand = true
)]
struct Cli {
    /// Print the version descriptor as JSON and exit.
    #[arg(long, global = true)]
    version_json: bool,

    /// Tracing filter (e.g. `debug`, `sessionlayer_agent=trace`). Overrides
    /// `RUST_LOG`.
    #[arg(long, value_name = "FILTER", global = true)]
    log: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Join the platform and maintain the renewable mTLS identity.
    Run(RunArgs),
}

#[derive(Debug, Parser)]
struct RunArgs {
    /// The stable node identity this Agent joins as (the enrollment key).
    #[arg(long)]
    node_name: String,

    /// Join method: how the Agent bootstraps.
    #[arg(long, value_enum, default_value_t = JoinMethodArg::Token)]
    join_method: JoinMethodArg,

    /// TokenJoin/OidcJoin: inline credential value (prefer the *-file form).
    #[arg(long)]
    join_token: Option<String>,
    /// TokenJoin/OidcJoin: path to a file holding the credential.
    #[arg(long)]
    join_token_file: Option<PathBuf>,
    /// MtlsJoin: operator certificate PEM path.
    #[arg(long)]
    operator_cert_file: Option<PathBuf>,
    /// MtlsJoin: operator ECDSA P-256 key PEM (PKCS#8) path.
    #[arg(long)]
    operator_key_file: Option<PathBuf>,

    /// CP mTLS gRPC endpoint (`https://host:port`).
    #[arg(long, default_value = DEFAULT_CP_ENDPOINT)]
    cp_endpoint: String,
    /// The server name the CP certificate must carry (SNI + SAN).
    #[arg(long, default_value = DEFAULT_CP_SERVER_NAME)]
    cp_server_name: String,
    /// Operator-pinned CP bootstrap trust anchor (PEM path) — no TOFU.
    #[arg(long)]
    bootstrap_ca_file: PathBuf,
    /// Credential data-dir (+ single-writer lock).
    #[arg(long, default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    /// Connect timeout (seconds).
    #[arg(long, default_value_t = 10)]
    connect_timeout_secs: u64,
    /// Per-RPC timeout (seconds).
    #[arg(long, default_value_t = 30)]
    rpc_timeout_secs: u64,

    /// Gateway `wss://host:port` to dial OUT to. Repeatable: an Agent holds ≥2
    /// control channels to failure-domain-diverse Gateways (FR-HA-6). Omit to run
    /// identity-only.
    #[arg(long, value_name = "WSS_URL")]
    gateway_endpoint: Vec<String>,
    /// Failure-domain label for the corresponding `--gateway-endpoint` (rack / AZ),
    /// zipped positionally. Provide one per endpoint, or none (each defaults to its
    /// endpoint host). Two channels must span ≥2 domains (FR-HA-6).
    #[arg(long, value_name = "LABEL")]
    gateway_failure_domain: Vec<String>,
    /// The enrolled name whose serverAuth SAN the Agent verifies for the
    /// corresponding `--gateway-endpoint`, zipped positionally. Provide one per
    /// endpoint (distinct real Gateways carry distinct SANs), or exactly one to apply
    /// to all, or none to default every endpoint to `gateway`.
    #[arg(long, value_name = "NAME")]
    gateway_server_name: Vec<String>,
    /// Degrade-warn threshold: warn when live control channels drop below this
    /// (FR-HA-6). Default 1 = single-instance (only the all-lost signal); an HA
    /// operator sets 2+. Diversity of ≥2 endpoints is enforced independently.
    #[arg(long, default_value_t = DEFAULT_MIN_CONTROL_CHANNELS)]
    min_control_channels: usize,
    /// The node-local address a dial-back is spliced to. MUST be loopback: the
    /// Agent refuses to start otherwise (the confused-deputy defence).
    #[arg(long, default_value = DEFAULT_SPLICE_ADDR, value_parser = parse_splice_addr)]
    splice_addr: SocketAddr,
    /// Cap on simultaneous spliced sessions (shared across all control channels).
    #[arg(long, default_value_t = DEFAULT_MAX_CONCURRENT_SPLICES)]
    max_concurrent_splices: usize,
    /// How long live spliced sessions may drain after the Agent stops taking new
    /// work (shutdown, or a terminal identity outcome).
    #[arg(long, default_value_t = 30)]
    drain_deadline_secs: u64,

    /// Enroll/renew once and exit (no renew-ahead loop, no control channel).
    /// Used by CI/E2E.
    #[arg(long)]
    once: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum JoinMethodArg {
    Token,
    Oidc,
    Mtls,
}

impl RunArgs {
    fn into_config(self) -> anyhow::Result<AgentConfig> {
        let join = match self.join_method {
            JoinMethodArg::Token => JoinConfig::Token {
                token: self.join_token.map(Zeroizing::new),
                token_file: self.join_token_file,
            },
            JoinMethodArg::Oidc => JoinConfig::Oidc {
                token: self.join_token.map(Zeroizing::new),
                token_file: self.join_token_file,
            },
            JoinMethodArg::Mtls => JoinConfig::Mtls {
                certificate_file: self
                    .operator_cert_file
                    .context("MtlsJoin requires --operator-cert-file")?,
                key_file: self
                    .operator_key_file
                    .context("MtlsJoin requires --operator-key-file")?,
            },
        };
        Ok(AgentConfig {
            data_dir: self.data_dir,
            cp_endpoint: self.cp_endpoint,
            cp_server_name: self.cp_server_name,
            connect_timeout: Duration::from_secs(self.connect_timeout_secs),
            rpc_timeout: Duration::from_secs(self.rpc_timeout_secs),
            bootstrap_ca_file: self.bootstrap_ca_file,
            node_name: self.node_name,
            join,
            renew: RenewConfig::default(),
        })
    }

    /// The connectivity role, if a Gateway was configured. Absent = identity-only
    /// (the S12 posture), which stays a supported way to run. `validate()` (called
    /// by `GatewayClient::new`) enforces the ≥2-diverse-domain rule.
    fn gateway_config(&self) -> anyhow::Result<Option<GatewayConfig>> {
        if self.gateway_endpoint.is_empty() {
            return Ok(None);
        }
        let endpoints = build_endpoints(
            &self.gateway_endpoint,
            &self.gateway_failure_domain,
            &self.gateway_server_name,
        )?;
        Ok(Some(GatewayConfig {
            endpoints,
            splice_addr: self.splice_addr,
            max_concurrent_splices: self.max_concurrent_splices,
            min_control_channels: self.min_control_channels,
            connect_timeout: Duration::from_secs(self.connect_timeout_secs),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            drain_deadline: Duration::from_secs(self.drain_deadline_secs),
        }))
    }
}

/// Zip endpoints with their failure-domain labels and verified server names.
///
/// A positional list (`--gateway-failure-domain`, `--gateway-server-name`) must have
/// either one entry per endpoint, exactly one (applied to all), or none. A mismatched
/// count is a startup error, not a silent guess. Defaults: failure domain = the
/// endpoint host (fail-closed — two Gateways on one host are one domain); server name
/// = `gateway`.
fn build_endpoints(
    urls: &[String],
    domains: &[String],
    server_names: &[String],
) -> anyhow::Result<Vec<GatewayEndpoint>> {
    check_zip("--gateway-failure-domain", urls.len(), domains.len())?;
    check_zip("--gateway-server-name", urls.len(), server_names.len())?;

    let mut out = Vec::with_capacity(urls.len());
    for (i, url) in urls.iter().enumerate() {
        let failure_domain = match zipped(domains, i) {
            Some(label) => label.clone(),
            None => sessionlayer_agent::gateway::default_failure_domain(url).with_context(|| {
                format!("{url:?} is not a valid wss:// endpoint (needed to derive a failure domain)")
            })?,
        };
        let server_name = zipped(server_names, i)
            .cloned()
            .unwrap_or_else(|| DEFAULT_GATEWAY_SERVER_NAME.to_string());
        out.push(GatewayEndpoint {
            url: url.clone(),
            failure_domain,
            server_name,
        });
    }
    Ok(out)
}

/// A positional list is valid at 0, 1, or `endpoints` entries.
fn check_zip(flag: &str, endpoints: usize, given: usize) -> anyhow::Result<()> {
    if given > 1 && given != endpoints {
        anyhow::bail!(
            "{endpoints} --gateway-endpoint but {given} {flag}: provide one per endpoint, \
             exactly one (applied to all), or none"
        );
    }
    Ok(())
}

/// The value for endpoint `i` from a positional list: the i-th if per-endpoint, the
/// single value if one-applies-to-all, else `None`.
fn zipped(values: &[String], i: usize) -> Option<&String> {
    match values.len() {
        0 => None,
        1 => Some(&values[0]),
        _ => values.get(i),
    }
}

/// Startup order is security-load-bearing. The Agent is deliberately **not** a
/// `#[tokio::main]` binary: Tier-0 hardening (Landlock + seccomp) must be applied
/// while the process is single-threaded so every tokio worker inherits it (Landlock
/// has no TSYNC), so the multi-thread runtime is built by hand **after** hardening.
fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    // `--version-json` is a pure query: no logging side effects, no init.
    if cli.version_json {
        let json = serde_json::to_string_pretty(&version::version_info())
            .context("serialising version descriptor")?;
        println!("{json}");
        return Ok(ExitCode::SUCCESS);
    }

    // Early, before hardening, so startup logs (incl. the root refusal + the
    // hardening report) are captured. The optional OTLP exporter runs on its own
    // runtime held by this guard (telemetry::init).
    let _telemetry = telemetry::init(cli.log.as_deref());

    // Fail closed if the single explicit TLS backend cannot be installed.
    init_process().context("process initialisation")?;

    // Fail closed if running as root — BEFORE any credential is loaded or issued
    // (FR-CONN-6). A root agent could read the node host key and impersonate it.
    privilege::require_non_root()?;

    match cli.command {
        Some(Command::Run(args)) => {
            let once = args.once;
            // Built (and loopback-validated) BEFORE any credential work, so a bad
            // splice target or too-few diverse channels fails startup closed rather
            // than after enrolling. Also gives hardening the concrete paths/ports.
            let gateway = args.gateway_config()?;
            let config = args.into_config()?;

            // Tier-0 hardening (Landlock + seccomp + coredump), fail-closed, while
            // still single-threaded — every worker of the runtime built below
            // inherits it. The OTLP collector (if any) is permitted egress.
            let otlp_port = telemetry::otlp_endpoint()
                .as_deref()
                .and_then(hardening::otlp_port);
            hardening::apply(&config, &gateway, otlp_port)
                .context("applying Tier-0 runtime hardening")?;

            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("building the tokio runtime")?;
            runtime.block_on(run(config, gateway, once))
        }
        None => {
            let info = version::component_info();
            tracing::info!(
                component = %info.name,
                semver = %info.semver,
                "SessionLayer Agent ready. Use the `run` subcommand to join and maintain identity."
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The numeric exit status for a renew-ahead stop reason. A clean shutdown is 0;
/// a terminal/security stop is a DISTINCT non-zero code so an orchestrator alerts
/// (and does not silently restart into a crash-loop) rather than treating it as
/// success — the process exit status is S12's only health signal (FR-JOIN-5). See
/// `RUNBOOK.md` for the response per code.
fn exit_status(outcome: &identity::RenewOutcome) -> u8 {
    match outcome {
        identity::RenewOutcome::Shutdown => 0,
        identity::RenewOutcome::GenerationMismatch { .. } => 3,
        identity::RenewOutcome::RepairNeeded => 4,
    }
}

fn exit_code(outcome: identity::RenewOutcome) -> ExitCode {
    ExitCode::from(exit_status(&outcome))
}

/// Open the data-dir (single-writer lock), load-or-enroll the identity, then run
/// the renew-ahead loop **and** the Gateway control channel concurrently until
/// shutdown (unless `once`). Returns the process exit code: `SUCCESS` on clean
/// shutdown / `--once`, a distinct non-zero code on a terminal/security loop stop
/// (see [`exit_code`]).
async fn run(
    config: AgentConfig,
    gateway: Option<GatewayConfig>,
    once: bool,
) -> anyhow::Result<ExitCode> {
    let store = IdentityStore::open(&config.data_dir)
        .with_context(|| format!("opening credential data-dir {:?}", config.data_dir))?;
    let params = config.channel_params();

    let cred = match store.load().context("loading persisted identity")? {
        Some(existing) => {
            tracing::info!(
                agent_id = %existing.agent_id,
                generation = existing.generation,
                "loaded persisted mTLS identity"
            );
            maybe_startup_renew(&store, &params, &config, existing).await?
        }
        None => {
            let join = config.join.build().context("building join method")?;
            tracing::info!(
                node_name = %config.node_name,
                join_method = join.method_name(),
                "no persisted identity — joining the platform"
            );
            let anchors = config.bootstrap_anchors_der().context("bootstrap CA")?;
            // Flatten the IdentityError to its code-only Display and drop the
            // `#[from] tonic::Status` source: `.context()` would keep the Status as
            // the error `source()`, and `fn main`'s Termination Debug-print of a
            // returned `Err` walks the chain and emits the CP-controlled Status
            // message (untrusted wire text) to startup stderr (§8.4 / NFR-2).
            identity::enroll(&store, &params, &anchors, join.as_ref(), &config.node_name)
                .await
                .map_err(|e| anyhow::anyhow!("agent enrollment failed: {e}"))?
        }
    };

    tracing::info!(
        agent_id = %cred.agent_id,
        node_id = %cred.node_id,
        generation = cred.generation,
        "mTLS identity active"
    );

    if once {
        return Ok(ExitCode::SUCCESS);
    }

    let renew = RenewAhead::new(
        store,
        RenewAheadConfig {
            renew_ahead_fraction: config.renew.renew_ahead_fraction,
            renew_jitter_fraction: config.renew.renew_jitter_fraction,
            retry_backoff: config.renew.retry_backoff,
            channel: params,
        },
        cred,
    );

    // Grab the handle BEFORE `run` consumes the driver: the control channel needs
    // it to observe credential rotation and reconnect with the new certificate.
    let drain_deadline = gateway
        .as_ref()
        .map(|g| g.drain_deadline)
        .unwrap_or_default();
    let client = match gateway {
        Some(cfg) => Some(GatewayClient::new(cfg, renew.handle())?),
        None => {
            tracing::info!("no --gateway-endpoint configured — running identity-only");
            None
        }
    };

    let outcome = supervisor::run(renew, client, drain_deadline, shutdown_signal()).await;
    Ok(exit_code(outcome))
}

/// If the loaded credential is at/below the configured remaining-TTL fraction,
/// renew immediately at startup (§8.1 startup trigger). A transient failure is
/// tolerated (the loop will retry); a repair-needed/mismatch rejection fails
/// closed (propagated).
async fn maybe_startup_renew(
    store: &IdentityStore,
    params: &ChannelParams,
    config: &AgentConfig,
    existing: identity::Credential,
) -> anyhow::Result<identity::Credential> {
    let remaining =
        identity::remaining_fraction(SystemTime::now(), existing.not_before, existing.not_after);
    if remaining > config.renew.startup_renew_below_fraction {
        return Ok(existing);
    }
    tracing::info!(remaining, "identity near expiry at startup — renewing now");
    match identity::renew(store, params, &existing).await {
        Ok(renewed) => Ok(renewed),
        // Classify identically to the loop (single source of truth): a transient
        // failure keeps the current still-valid credential and lets the loop retry.
        Err(e) if identity::classify_renew_error(&e) == identity::RenewalDisposition::Transient => {
            tracing::warn!(error = %e, "startup renew failed transiently — keeping current, loop will retry");
            Ok(existing)
        }
        // RepairNeeded / Mismatch: fail closed. Flatten to the code-only Display;
        // do NOT carry the `tonic::Status` source into the anyhow chain
        // (F-identity-1 — else `fn main`'s Termination print leaks the CP message).
        Err(e) => Err(anyhow::anyhow!("startup renewal failed: {e}")),
    }
}

/// Resolve on SIGTERM (orchestrator stop) or SIGINT (Ctrl-C).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_and_security_stops_are_distinct_non_zero_exit_codes() {
        // FR-JOIN-5 / F1: a clone-detection or repair-needed stop must NOT look
        // like a clean shutdown (exit 0), or an orchestrator silently restarts
        // into a crash-loop with no operator signal.
        assert_eq!(exit_status(&identity::RenewOutcome::Shutdown), 0);
        assert_eq!(
            exit_status(&identity::RenewOutcome::GenerationMismatch {
                expected: 3,
                got: 7
            }),
            3
        );
        assert_eq!(exit_status(&identity::RenewOutcome::RepairNeeded), 4);
    }
}
