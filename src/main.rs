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
use sessionlayer_agent::supply_chain::{self, Bundle, TrustRoot, VerificationPolicy};
use sessionlayer_agent::update::SelfUpdater;
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
    #[arg(long, global = true)]
    version_json: bool,

    #[arg(long, value_name = "FILTER", global = true)]
    log: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    Run(RunArgs),
    Verify(VerifyArgs),
    Update(UpdateArgs),
}

#[derive(Debug, Parser)]
struct VerifyArgs {
    #[arg(long)]
    binary: PathBuf,
    #[arg(long)]
    blob_bundle: PathBuf,
    #[arg(long)]
    provenance: PathBuf,
    #[arg(long)]
    trusted_root: PathBuf,
    #[arg(long)]
    expect_source_repo: Option<String>,
    #[arg(long)]
    expect_workflow_ref_prefix: Option<String>,
    #[arg(long)]
    expect_oidc_issuer: Option<String>,
}

impl VerifyArgs {
    fn policy(&self) -> VerificationPolicy {
        let mut p = VerificationPolicy::sessionlayer_agent();
        let overridden = self.expect_source_repo.is_some()
            || self.expect_workflow_ref_prefix.is_some()
            || self.expect_oidc_issuer.is_some();
        if let Some(x) = &self.expect_source_repo {
            p.source_repo_uri = x.clone();
        }
        if let Some(x) = &self.expect_workflow_ref_prefix {
            p.workflow_ref_prefix = x.clone();
        }
        if let Some(x) = &self.expect_oidc_issuer {
            p.oidc_issuer = x.clone();
        }
        if overridden {
            p.require_certificate_transparency = false;
        }
        p
    }
}

#[derive(Debug, Parser)]
struct UpdateArgs {
    #[arg(long)]
    candidate: PathBuf,
    #[arg(long)]
    blob_bundle: PathBuf,
    #[arg(long)]
    provenance: PathBuf,
    #[arg(long)]
    trusted_root: PathBuf,
    #[arg(long)]
    install_to: PathBuf,
    #[arg(long)]
    current_version: Option<String>,
    #[arg(long)]
    allow_downgrade: bool,
}

#[derive(Debug, Parser)]
struct RunArgs {
    #[arg(long)]
    node_name: String,

    #[arg(long, value_enum, default_value_t = JoinMethodArg::Token)]
    join_method: JoinMethodArg,

    #[arg(long)]
    join_token: Option<String>,
    #[arg(long)]
    join_token_file: Option<PathBuf>,
    #[arg(long)]
    operator_cert_file: Option<PathBuf>,
    #[arg(long)]
    operator_key_file: Option<PathBuf>,

    #[arg(long, default_value = DEFAULT_CP_ENDPOINT)]
    cp_endpoint: String,
    #[arg(long, default_value = DEFAULT_CP_SERVER_NAME)]
    cp_server_name: String,
    /// Operator-pinned CP bootstrap trust anchor (PEM path) — no TOFU.
    #[arg(long)]
    bootstrap_ca_file: PathBuf,
    #[arg(long, default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    #[arg(long, default_value_t = 10)]
    connect_timeout_secs: u64,
    #[arg(long, default_value_t = 30)]
    rpc_timeout_secs: u64,

    #[arg(long, value_name = "WSS_URL")]
    gateway_endpoint: Vec<String>,
    #[arg(long, value_name = "LABEL")]
    gateway_failure_domain: Vec<String>,
    #[arg(long, value_name = "NAME")]
    gateway_server_name: Vec<String>,
    #[arg(long, default_value_t = DEFAULT_MIN_CONTROL_CHANNELS)]
    min_control_channels: usize,
    #[arg(long, default_value = DEFAULT_SPLICE_ADDR, value_parser = parse_splice_addr)]
    splice_addr: SocketAddr,
    #[arg(long, default_value_t = DEFAULT_MAX_CONCURRENT_SPLICES)]
    max_concurrent_splices: usize,
    #[arg(long, default_value_t = 30)]
    drain_deadline_secs: u64,

    #[arg(long)]
    once: bool,

    #[arg(long)]
    require_full_landlock: bool,

    #[arg(long, requires_all = ["self_blob_bundle", "self_provenance", "self_trusted_root"])]
    verify_self: bool,
    #[arg(long)]
    self_blob_bundle: Option<PathBuf>,
    #[arg(long)]
    self_provenance: Option<PathBuf>,
    #[arg(long)]
    self_trusted_root: Option<PathBuf>,
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

fn check_zip(flag: &str, endpoints: usize, given: usize) -> anyhow::Result<()> {
    if given > 1 && given != endpoints {
        anyhow::bail!(
            "{endpoints} --gateway-endpoint but {given} {flag}: provide one per endpoint, \
             exactly one (applied to all), or none"
        );
    }
    Ok(())
}

fn zipped(values: &[String], i: usize) -> Option<&String> {
    match values.len() {
        0 => None,
        1 => Some(&values[0]),
        _ => values.get(i),
    }
}

fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    if cli.version_json {
        let json = serde_json::to_string_pretty(&version::version_info())
            .context("serialising version descriptor")?;
        println!("{json}");
        return Ok(ExitCode::SUCCESS);
    }

    let _telemetry = telemetry::init(cli.log.as_deref());

    init_process().context("process initialisation")?;

    match cli.command {
        Some(Command::Run(args)) => {
            privilege::require_non_root()?;
            if args.verify_self {
                verify_self(&args)?;
            }
            let once = args.once;
            let require_full_landlock = args.require_full_landlock;
            let gateway = args.gateway_config()?;
            let config = args.into_config()?;

            let otlp_port = telemetry::otlp_endpoint()
                .as_deref()
                .and_then(hardening::otlp_port);
            let report = hardening::apply(&config, &gateway, otlp_port)
                .context("applying Tier-0 runtime hardening")?;
            if require_full_landlock && report.landlock != hardening::Landlock::FullyEnforced {
                anyhow::bail!(
                    "--require-full-landlock is set but Landlock is {:?}, not FullyEnforced — \
                     refusing to run with degraded filesystem/network-egress confinement (the \
                     network ABI needs Linux ≥6.7). Deploy on a Landlock-capable kernel, or drop \
                     the flag to accept the documented degrade.",
                    report.landlock
                );
            }

            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("building the tokio runtime")?;
            runtime.block_on(run(config, gateway, once))
        }
        Some(Command::Verify(args)) => run_verify(args),
        Some(Command::Update(args)) => run_update(args),
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

const EXIT_VERIFY_REFUSED: u8 = 2;

fn load_trust(path: &std::path::Path) -> anyhow::Result<TrustRoot> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading pinned trusted root {}", path.display()))?;
    Ok(TrustRoot::from_trusted_root_json(&bytes)?)
}

fn verify_self(args: &RunArgs) -> anyhow::Result<()> {
    let blob = args.self_blob_bundle.as_ref().expect("clap requires it");
    let prov = args.self_provenance.as_ref().expect("clap requires it");
    let root = args.self_trusted_root.as_ref().expect("clap requires it");
    let exe = std::env::current_exe().context("resolving current executable for --verify-self")?;
    let trust = load_trust(root)?;
    let policy = VerificationPolicy::sessionlayer_agent();
    match supply_chain::verify_files(&exe, blob, prov, &trust, &policy) {
        Ok(v) => {
            tracing::info!(
                digest = %v.digest_hex,
                version = v.version.as_deref().unwrap_or("?"),
                "self-verification passed — running a verified binary"
            );
            Ok(())
        }
        Err(e) => anyhow::bail!(
            "self-verification failed — refusing to run (NFR-7 verify-before-run): {e}"
        ),
    }
}

fn run_verify(args: VerifyArgs) -> anyhow::Result<ExitCode> {
    let policy = args.policy();
    let outcome = load_trust(&args.trusted_root).and_then(|trust| {
        supply_chain::verify_files(
            &args.binary,
            &args.blob_bundle,
            &args.provenance,
            &trust,
            &policy,
        )
        .map_err(anyhow::Error::from)
    });
    match outcome {
        Ok(v) => {
            tracing::info!(digest = %v.digest_hex, identity = %v.san, "release verified");
            println!("VERIFIED sha256:{} identity={}", v.digest_hex, v.san);
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            tracing::error!(error = %e, "verification failed — refusing (fail closed)");
            eprintln!("REFUSED: {e}");
            Ok(ExitCode::from(EXIT_VERIFY_REFUSED))
        }
    }
}

fn run_update(args: UpdateArgs) -> anyhow::Result<ExitCode> {
    let outcome = (|| -> anyhow::Result<supply_chain::VerifiedRelease> {
        let floor = args
            .current_version
            .as_deref()
            .unwrap_or(env!("CARGO_PKG_VERSION"));
        let updater = SelfUpdater::from_trust_root_file(&args.trusted_root)?
            .with_rollback_floor(floor, args.allow_downgrade)?;
        let blob = Bundle::parse(&std::fs::read(&args.blob_bundle)?)?;
        let prov = Bundle::parse(&std::fs::read(&args.provenance)?)?;
        Ok(updater.install(&args.candidate, &blob, &prov, &args.install_to)?)
    })();
    match outcome {
        Ok(v) => {
            println!(
                "INSTALLED sha256:{} -> {}",
                v.digest_hex,
                args.install_to.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            tracing::error!(error = %e, "update refused — not installing (fail closed)");
            eprintln!("REFUSED update: {e}");
            Ok(ExitCode::from(EXIT_VERIFY_REFUSED))
        }
    }
}

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
            match maybe_startup_renew(&store, &params, &config, existing).await {
                Ok(cred) => cred,
                Err(e) => return terminal_identity_result(e, "startup renewal"),
            }
        }
        None => {
            let join = config.join.build().context("building join method")?;
            tracing::info!(
                node_name = %config.node_name,
                join_method = join.method_name(),
                "no persisted identity — joining the platform"
            );
            let anchors = config.bootstrap_anchors_der().context("bootstrap CA")?;
            match identity::enroll(&store, &params, &anchors, join.as_ref(), &config.node_name)
                .await
            {
                Ok(cred) => cred,
                Err(e) => return terminal_identity_result(e, "agent enrollment"),
            }
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

async fn maybe_startup_renew(
    store: &IdentityStore,
    params: &ChannelParams,
    config: &AgentConfig,
    existing: identity::Credential,
) -> Result<identity::Credential, identity::IdentityError> {
    let remaining =
        identity::remaining_fraction(SystemTime::now(), existing.not_before, existing.not_after);
    if remaining > config.renew.startup_renew_below_fraction {
        return Ok(existing);
    }
    tracing::info!(remaining, "identity near expiry at startup — renewing now");
    match identity::renew(store, params, &existing).await {
        Ok(renewed) => Ok(renewed),
        Err(e) if identity::classify_renew_error(&e) == identity::RenewalDisposition::Transient => {
            tracing::warn!(error = %e, "startup renew failed transiently — keeping current, loop will retry");
            Ok(existing)
        }
        Err(e) => Err(e),
    }
}

/// A fresh enrollment and a startup renewal can both hit the same terminal CP
/// refusal the renew-ahead loop already classifies via `classify_renew_error`
/// (locked identity, stale generation, possible clone). Route both through it
/// too, so the refusal exits 3/4 here exactly like it does mid-loop, instead of
/// collapsing into the generic "transient" exit 1 — that erasure is what let a
/// locked/cloned node crash-loop invisibly, indistinguishable from an ordinary
/// blip (H4).
fn terminal_identity_result(
    error: identity::IdentityError,
    phase: &str,
) -> anyhow::Result<ExitCode> {
    let outcome = match &error {
        identity::IdentityError::GenerationMismatch { expected, got } => {
            Some(identity::RenewOutcome::GenerationMismatch {
                expected: *expected,
                got: *got,
            })
        }
        _ if identity::classify_renew_error(&error)
            == identity::RenewalDisposition::RepairNeeded =>
        {
            Some(identity::RenewOutcome::RepairNeeded)
        }
        _ => None,
    };
    match outcome {
        Some(outcome) => {
            tracing::error!(
                error = %error,
                phase,
                exit_code = exit_status(&outcome),
                "identity refused by the Control Plane — not transient, do not auto-restart into a loop"
            );
            Ok(exit_code(outcome))
        }
        None => Err(anyhow::anyhow!("{phase} failed: {error}")),
    }
}

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

    // H4: a locked/cloned identity refused during enrollment or a startup renew
    // used to collapse into the generic `anyhow` error (exit 1) — indistinguishable
    // from an ordinary transient CP blip, and silently crash-looped. It must
    // instead resolve like the main renew-ahead loop does: Ok(distinct exit code).
    #[test]
    fn terminal_identity_result_does_not_collapse_a_repair_needed_refusal_into_the_generic_error() {
        let error = identity::IdentityError::Rpc(tonic::Status::permission_denied("locked"));
        let result = terminal_identity_result(error, "agent enrollment");
        assert!(
            result.is_ok(),
            "a CP refusal must exit distinctly (4), not the generic anyhow path"
        );
    }

    #[test]
    fn terminal_identity_result_does_not_collapse_a_generation_mismatch_into_the_generic_error() {
        let error = identity::IdentityError::GenerationMismatch {
            expected: 3,
            got: 7,
        };
        let result = terminal_identity_result(error, "agent enrollment");
        assert!(
            result.is_ok(),
            "a possible-clone mismatch must exit distinctly (3), not the generic anyhow path"
        );
    }

    #[test]
    fn terminal_identity_result_keeps_a_transient_refusal_on_the_generic_error_path() {
        let error = identity::IdentityError::Rpc(tonic::Status::unavailable("cp down"));
        let result = terminal_identity_result(error, "agent enrollment");
        assert!(
            result.is_err(),
            "a transient blip must stay the generic (retryable) exit-1 path"
        );
    }
}
