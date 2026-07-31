pub mod client;
pub mod splice;
pub mod transport;
pub mod wire;

pub use client::GatewayClient;

use std::time::Duration;

pub fn default_failure_domain(endpoint: &str) -> Option<String> {
    transport::host_of(endpoint)
}

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

    #[error("wire protocol error: {0}")]
    Protocol(#[from] wire::CodecError),

    #[error(
        "Gateway rejected our protocol version (supports {gateway_min}-{gateway_max}); \
             failing closed — the Agent will not downgrade or guess"
    )]
    VersionRejected {
        gateway_min: String,
        gateway_max: String,
    },

    #[error("connection preface failed: {0}")]
    Preface(String),

    #[error("the connection closed")]
    Closed,

    #[error("i/o error on the {what}: {reason}")]
    Io { what: &'static str, reason: String },
}

#[derive(Debug, Clone, Copy)]
pub struct Negotiated {
    pub version: u8,
    pub heartbeat_interval: Duration,
    pub max_frame_bytes: u32,
}
