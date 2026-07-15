//! The Agent's outbound connectivity role (Session Fourteen, Design §9.2).
//!
//! The Agent dials **out** to a Gateway over a mutually-authenticated WebSocket
//! control channel ([`client`]), is signalled to dial back for a session, opens a
//! second connection presenting a single-use token, and **splices** that byte
//! stream to the node's own `sshd` on loopback ([`splice`]). A node therefore needs
//! **zero inbound reachability**.
//!
//! What the Agent deliberately does **not** do (Design §9.3, contract §8):
//! * it never sees SSH plaintext — it splices ciphertext it structurally cannot
//!   read (the SSH session is end-to-end between the Gateway and the node's sshd);
//! * it holds no session credential, and is not a party to the inner-leg
//!   certificate or to host-identity verification;
//! * it never takes its splice target from the wire — see
//!   [`crate::config::parse_splice_addr`].
//!
//! The normative protocol is `contracts/wire/agent-gateway-v1.md`.

pub mod client;
pub mod splice;
pub mod transport;
pub mod wire;

pub use client::GatewayClient;

use std::time::Duration;

/// A failure on the Gateway plane. Every variant is a refusal: there is no path
/// that falls back to plaintext, to an unverified peer, or to an unnegotiated
/// protocol version.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("invalid Gateway endpoint {endpoint:?}: {reason}")]
    Endpoint { endpoint: String, reason: String },

    #[error("the credential's CA chain is unusable as a trust anchor: {0}")]
    TrustAnchor(String),

    #[error("the credential is unusable as a TLS client identity: {0}")]
    ClientIdentity(String),

    #[error("failed to connect to {endpoint}: {reason}")]
    Connect { endpoint: String, reason: String },

    #[error("TLS handshake with {endpoint} failed: {reason}")]
    Tls { endpoint: String, reason: String },

    #[error("WebSocket upgrade to {endpoint} failed: {reason}")]
    WebSocket { endpoint: String, reason: String },

    #[error("timed out connecting to {endpoint} after {after:?}")]
    Timeout { endpoint: String, after: Duration },

    /// The peer violated the frozen wire contract. Always fatal for the connection.
    #[error("wire protocol error: {0}")]
    Protocol(#[from] wire::CodecError),

    /// No common protocol version (`VERSION_REJECT`, §3). Fails closed: the Agent
    /// never downgrades or guesses a version (FR-HA-9).
    #[error(
        "Gateway rejected our protocol version (supports {gateway_min}-{gateway_max}); \
             failing closed — the Agent will not downgrade or guess"
    )]
    VersionRejected {
        gateway_min: String,
        gateway_max: String,
    },

    /// The preface did not complete, or `HELLO_ACK` proposed parameters outside the
    /// bounds this Agent will accept.
    #[error("connection preface failed: {0}")]
    Preface(String),

    #[error("the connection closed")]
    Closed,

    #[error("i/o error on the {what}: {reason}")]
    Io { what: &'static str, reason: String },
}

/// The parameters fixed by the connection preface (§3), for the life of one
/// connection. Re-negotiated on every reconnect — there is no resumption and no
/// cached authorization.
#[derive(Debug, Clone, Copy)]
pub struct Negotiated {
    /// The selected protocol major; the `VER` byte of every subsequent frame.
    pub version: u8,
    /// The Gateway's PING cadence. Two missed intervals ⇒ the channel is dead.
    pub heartbeat_interval: Duration,
    /// The payload bound both peers must enforce.
    pub max_frame_bytes: u32,
}
