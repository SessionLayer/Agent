//! Structured logging via `tracing`.
//!
//! Session One provides a single console subscriber. Richer sinks (JSON export,
//! the node-local second audit trail described in Design §12.2) arrive with the
//! transport in a later session.

use tracing_subscriber::{fmt, EnvFilter};

/// Initialise the global `tracing` subscriber.
///
/// Filter precedence: the explicit `filter` argument (e.g. from `--log`), then
/// `RUST_LOG`, then a default of `info`. Uses `try_init` so a second call (as
/// happens across integration tests sharing a process) is a harmless no-op
/// rather than a panic.
pub fn init(filter: Option<&str>) {
    let env_filter = match filter {
        Some(f) => EnvFilter::new(f),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };

    let _ = fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .try_init();
}
