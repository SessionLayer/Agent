//! SessionLayer Agent — library surface.
//!
//! The Agent is the per-node **outbound** connector of the SessionLayer
//! Zero-Trust SSH platform (Design §9.2). It dials out to failure-domain-diverse
//! Gateways, and — on demand — dial-backs and splices a connection to the local
//! `sshd`, so a node needs **no inbound holes** and the Gateway never trusts the
//! node on TOFU.
//!
//! # Session Twelve scope — durable identity
//! This crate now gives the Agent a **durable identity** (Design §8, FR-JOIN-*):
//! it JOINS the platform via one of three [`join::JoinMethod`]s
//! ([`join::TokenJoin`] / [`join::OidcJoin`] / [`join::MtlsJoin`]), receives a
//! **renewable internal mTLS X.509 identity carrying a generation counter**
//! ([`identity`]), and keeps it fresh with a renew-ahead loop
//! ([`identity::RenewAhead`]) using persist-before-adopt + a single-writer
//! data-dir lock. The ongoing credential is always mTLS X.509 + generation
//! counter regardless of join method (D25/D28). The dial-back **data path**
//! (wire transport, splice to `127.0.0.1:22`) is Session Thirteen and is
//! deliberately absent here.
//!
//! # Security posture
//! * **Non-root, fail-closed** (FR-CONN-6, Design §9.3): a root Agent could read
//!   the node host key and impersonate the node. Enforced structurally by the
//!   container `USER` directive AND a runtime refusal ([`privilege::require_non_root`]).
//! * **Single, explicit TLS backend**: the process installs one rustls crypto
//!   provider ([`tls`]) before any TLS handshake (no OpenSSL — see `deny.toml`),
//!   TLS 1.3-only, mutually authenticated to the CP ([`mtls`]).
//! * **Key custody (D2/§15)**: the Agent generates its keypair + CSR locally and
//!   sends only the CSR; its mTLS private key never leaves the Agent and is
//!   zeroized in memory + `0600` on disk.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(rust_2018_idioms)]

pub mod config;
pub mod identity;
pub mod join;
pub mod mtls;
pub mod privilege;
mod secret;
pub mod telemetry;
pub mod tls;
pub mod version;

/// Types + gRPC stubs generated from the vendored contract
/// (`sessionlayer.controlplane.v1`: `common.proto` messages + the `agent.proto`
/// `AgentIdentity` service). These are the canonical cross-repo shapes — the
/// Agent never hand-writes a divergent copy (Design §13).
pub mod proto {
    // Generated code is not held to this crate's lint bar.
    #![allow(clippy::all, missing_docs, rustdoc::all)]
    include!(concat!(env!("OUT_DIR"), "/sessionlayer.controlplane.v1.rs"));
}

/// Long-form version string surfaced by `--version`: build SemVer plus the
/// supported protocol range and the gRPC contract the generated types come from.
/// The `1.0` literals are guarded against drift from [`version::PROTOCOL_MIN`]/
/// [`version::PROTOCOL_MAX`] by a unit test.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncomponent:      SessionLayer Agent",
    "\nwire-protocol:  1.0 - 1.0  (N-1 window; contracts/wire/agent-gateway-v1.md)",
    "\ngrpc-contract:  sessionlayer.controlplane.v1  (vendored common.proto + agent.proto)"
);

/// Errors raised while bringing the Agent process up.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The process-wide rustls crypto provider could not be installed. A missing
    /// crypto backend must never fail *open*.
    #[error("failed to install the process rustls crypto provider")]
    CryptoProviderInstall,
}

/// Perform one-time, process-wide initialisation that must happen before any TLS
/// is used: install the single explicit rustls crypto provider.
///
/// Fails closed: if no provider can be installed the caller should abort rather
/// than proceed toward an unauthenticated transport. Idempotent — safe if a
/// provider is already installed (e.g. by a test harness).
pub fn init_process() -> Result<(), AgentError> {
    tls::install_ring_provider();
    if tls::crypto_provider_installed() {
        Ok(())
    } else {
        Err(AgentError::CryptoProviderInstall)
    }
}
