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

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use sessionlayer_agent::config::{
    AgentConfig, JoinConfig, RenewConfig, DEFAULT_CP_ENDPOINT, DEFAULT_CP_SERVER_NAME,
    DEFAULT_DATA_DIR,
};
use sessionlayer_agent::identity::{self, IdentityStore, RenewAhead, RenewAheadConfig};
use sessionlayer_agent::mtls::ChannelParams;
use sessionlayer_agent::{init_process, privilege, telemetry, version, LONG_VERSION};

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

    /// Enroll/renew once and exit (no renew-ahead loop). Used by CI/E2E.
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
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    // `--version-json` is a pure query: no logging side effects, no init.
    if cli.version_json {
        let json = serde_json::to_string_pretty(&version::version_info())
            .context("serialising version descriptor")?;
        println!("{json}");
        return Ok(ExitCode::SUCCESS);
    }

    telemetry::init(cli.log.as_deref());

    // Fail closed if the single explicit TLS backend cannot be installed.
    init_process().context("process initialisation")?;

    // Fail closed if running as root — BEFORE any credential is loaded or issued
    // (FR-CONN-6). A root agent could read the node host key and impersonate it.
    privilege::require_non_root()?;

    match cli.command {
        Some(Command::Run(args)) => {
            let once = args.once;
            let config = args.into_config()?;
            run(config, once).await
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
/// the renew-ahead loop until shutdown (unless `once`). Returns the process exit
/// code: `SUCCESS` on clean shutdown / `--once`, a distinct non-zero code on a
/// terminal/security loop stop (see [`exit_code`]).
async fn run(config: AgentConfig, once: bool) -> anyhow::Result<ExitCode> {
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
    let outcome = renew.run(Box::pin(shutdown_signal())).await;
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
