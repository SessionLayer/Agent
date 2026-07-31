//! SessionLayer Agent — durable identity + outbound connector (Design §8–9, FR-JOIN-*).
//! Non-root, fail-closed, TLS 1.3-only, key never leaves.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(rust_2018_idioms)]

pub mod config;
pub mod gateway;
pub mod hardening;
pub mod identity;
pub mod join;
pub mod mtls;
pub mod privilege;
mod secret;
pub mod supervisor;
pub mod supply_chain;
pub mod telemetry;
pub mod tls;
pub mod update;
pub mod version;

/// Types + gRPC stubs generated from the vendored contract.
/// These are the canonical cross-repo shapes — the Agent never hand-writes
/// a divergent copy (Design §13).
pub mod proto {
    // Generated code is not held to this crate's lint bar.
    #![allow(clippy::all, missing_docs, rustdoc::all)]
    include!(concat!(env!("OUT_DIR"), "/sessionlayer.controlplane.v1.rs"));

    /// The Agent<->Gateway wire payloads, generated from the vendored contract.
    /// These are the payloads of the framed WebSocket transport, not gRPC.
    pub mod wire {
        #![allow(clippy::all, missing_docs, rustdoc::all)]
        include!(concat!(env!("OUT_DIR"), "/sessionlayer.agent.v1.rs"));
    }
}

/// Long-form version string surfaced by `--version`: build SemVer plus the
/// supported wire-protocol range and the gRPC contract.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncomponent:      SessionLayer Agent",
    "\nwire-protocol:  1.0 - 1.0  (N-1 window; contracts/wire/agent-gateway-v1.md)",
    "\ngrpc-contract:  sessionlayer.controlplane.v1  (vendored common.proto + agent.proto)"
);

/// Agent startup errors (fail closed).
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("failed to install the process rustls crypto provider")]
    CryptoProviderInstall,
}

/// Install rustls crypto provider (fail-closed); idempotent.
pub fn init_process() -> Result<(), AgentError> {
    tls::install_ring_provider();
    if tls::crypto_provider_installed() {
        Ok(())
    } else {
        Err(AgentError::CryptoProviderInstall)
    }
}
