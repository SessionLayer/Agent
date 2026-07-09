//! SessionLayer Agent binary (scaffold).
//!
//! Session One wires up the runtime, the version surface, the non-root probe,
//! and the single TLS crypto provider. There is no product behaviour yet: the
//! process initialises, reports readiness, and exits. The dial-out control
//! channels, join/credential lifecycle, and wire transport arrive in later
//! sessions.

use anyhow::Context;
use clap::Parser;

use sessionlayer_agent::{init_process, privilege, telemetry, version, LONG_VERSION};

/// SessionLayer Agent — per-node outbound connector for the Zero-Trust SSH
/// platform.
#[derive(Debug, Parser)]
#[command(
    name = "sessionlayer-agent",
    version = env!("CARGO_PKG_VERSION"),
    long_version = LONG_VERSION,
    about = "SessionLayer Agent — per-node outbound connector (Session One scaffold).",
    disable_help_subcommand = true
)]
struct Cli {
    /// Print the version descriptor as JSON and exit.
    #[arg(long)]
    version_json: bool,

    /// Tracing filter (e.g. `debug`, `sessionlayer_agent=trace`). Overrides
    /// `RUST_LOG`.
    #[arg(long, value_name = "FILTER")]
    log: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // `--version-json` is a pure query: no logging side effects, no init.
    if cli.version_json {
        let json = serde_json::to_string_pretty(&version::version_info())
            .context("serialising version descriptor")?;
        println!("{json}");
        return Ok(());
    }

    telemetry::init(cli.log.as_deref());

    // Fail closed if the single explicit TLS backend cannot be installed:
    // proceeding toward an unauthenticated transport is never acceptable.
    init_process().context("process initialisation")?;

    // Secondary detector for the non-root precondition (FR-CONN-6).
    privilege::warn_if_root();

    let info = version::component_info();
    tracing::info!(
        component = %info.name,
        semver = %info.semver,
        wire_protocol = %format!(
            "{}-{}",
            version::display_version(&version::PROTOCOL_MIN),
            version::display_version(&version::PROTOCOL_MAX)
        ),
        "SessionLayer Agent scaffold ready — no product behaviour in Session One"
    );

    Ok(())
}
