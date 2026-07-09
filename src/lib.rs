//! SessionLayer Agent — library surface.
//!
//! The Agent is the per-node **outbound** connector of the SessionLayer
//! Zero-Trust SSH platform (Design §9.2). It dials out to failure-domain-diverse
//! Gateways, and — on demand — dial-backs and splices a connection to the local
//! `sshd`, so a node needs **no inbound holes** and the Gateway never trusts the
//! node on TOFU.
//!
//! # Session One scope
//! This crate is **scaffolding only**. It establishes the package, the
//! contract-generated types, the `--version` surface, the non-root posture, and
//! the quality/CI gate. It deliberately contains **no product behaviour**: no
//! `JoinMethod`, no mTLS identity, no dial-back, no generation counter, no wire
//! transport, no version-negotiation algorithm. Those arrive in later sessions
//! (S12/S13) behind the contracts frozen in `ControlPlane-API/contracts/`.
//!
//! # Security posture carried from day one
//! * **Non-root by construction** (FR-CONN-6, Design §9.3): a root Agent could
//!   read the node host key and impersonate the node. Enforced by the container
//!   `USER` directive; a runtime probe ([`privilege`]) shouts if it is ever
//!   violated.
//! * **Single, explicit TLS backend**: the process installs one rustls crypto
//!   provider at startup so every future TLS handshake uses an audited,
//!   memory-safe backend (no OpenSSL — see `deny.toml`).

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(rust_2018_idioms)]

pub mod privilege;
pub mod telemetry;
pub mod version;

/// Types generated from the vendored `common.proto`
/// (`sessionlayer.controlplane.v1`). These are the canonical cross-repo message
/// shapes — the Agent never hand-writes a divergent copy (Design §13).
pub mod proto {
    // Generated code is not held to this crate's lint bar.
    #![allow(clippy::all, missing_docs, rustdoc::all)]
    include!(concat!(env!("OUT_DIR"), "/sessionlayer.controlplane.v1.rs"));
}

/// The pinned Rust gRPC runtime, re-exported so the dependency edge is tracked
/// by `cargo audit`/`cargo deny`.
///
/// The Agent's live plane to the Gateway is the framed wire protocol
/// (`contracts/wire/agent-gateway-v1.md`), **not** gRPC, so `tonic` has no
/// runtime consumer this session — it is carried per the Session One
/// baseline-deps directive for toolchain symmetry with the Gateway/Control
/// Plane. The re-export makes the edge visible to the supply-chain gate; it does
/// not remove the transitive surface (see `audit/F-supply-2` and CLAUDE.md
/// "Dependencies").
pub mod grpc {
    pub use tonic;
}

/// Long-form version string surfaced by `--version` (deliverable §6.3.5): build
/// SemVer plus the supported **wire-protocol** range and the gRPC contract the
/// generated types come from. The `1.0` literals are guarded against drift from
/// [`version::PROTOCOL_MIN`]/[`version::PROTOCOL_MAX`] by a unit test.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncomponent:      SessionLayer Agent",
    "\nwire-protocol:  1.0 - 1.0  (N-1 window; contracts/wire/agent-gateway-v1.md)",
    "\ngrpc-contract:  sessionlayer.controlplane.v1  (vendored common.proto)"
);

/// Errors raised while bringing the Agent process up.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The process-wide rustls crypto provider could not be installed. At
    /// startup this is unexpected (nothing else has installed one yet) and is
    /// treated as fatal — a missing crypto backend must never fail *open*.
    #[error("failed to install the process rustls crypto provider (one was already set)")]
    CryptoProviderInstall,
}

/// Perform one-time, process-wide initialisation that must happen before any
/// TLS is used: install the single explicit rustls crypto provider.
///
/// Fails closed: if the provider cannot be installed the caller should abort
/// rather than proceed toward an unauthenticated transport.
pub fn init_process() -> Result<(), AgentError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_already_installed| AgentError::CryptoProviderInstall)
}
