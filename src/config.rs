//! Agent runtime configuration (Session Twelve).
//!
//! Everything the identity lifecycle needs: the credential data-dir + its
//! single-writer lock (§8.2), the CP mTLS endpoint + the operator-pinned
//! bootstrap trust anchor, the node identity, the selected [`JoinMethod`], and
//! the renew-ahead knobs (§8.1). Values are set on the command line / environment
//! by the binary; this module holds the typed shape + sensible dev defaults and
//! knows how to construct the concrete [`JoinMethod`].

use crate::join::{JoinMethod, MtlsJoin, OidcJoin, TokenJoin};
use crate::mtls::ChannelParams;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

/// Default credential data-dir (holds the mTLS identity + generation + the
/// single-writer lock). Owned by the non-root agent user.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/sessionlayer-agent";
/// Default CP mTLS gRPC endpoint (dev; overridden in every real deploy).
pub const DEFAULT_CP_ENDPOINT: &str = "https://127.0.0.1:9443";
/// Default server name the CP server certificate must carry (SNI + SAN).
pub const DEFAULT_CP_SERVER_NAME: &str = "controlplane";

/// A configuration error (missing/invalid material). Fails startup closed.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required configuration: {0}")]
    Missing(String),
    #[error("invalid configuration for {field}: {reason}")]
    Invalid { field: String, reason: String },
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// How the Agent bootstraps (which [`JoinMethod`] + its backing material).
#[derive(Debug, Clone)]
pub enum JoinConfig {
    /// TokenJoin — an inline token or a file holding it.
    Token {
        token: Option<Zeroizing<String>>,
        token_file: Option<PathBuf>,
    },
    /// OidcJoin — a workload-token file (projected SA token) or an inline token.
    Oidc {
        token: Option<Zeroizing<String>>,
        token_file: Option<PathBuf>,
    },
    /// MtlsJoin — an operator cert PEM + its ECDSA P-256 key PEM.
    Mtls {
        certificate_file: PathBuf,
        key_file: PathBuf,
    },
}

impl JoinConfig {
    /// The `join_method` label.
    pub fn method_name(&self) -> &'static str {
        match self {
            JoinConfig::Token { .. } => "token",
            JoinConfig::Oidc { .. } => "oidc",
            JoinConfig::Mtls { .. } => "mtls",
        }
    }

    /// Construct the concrete [`JoinMethod`], reading any backing files.
    pub fn build(&self) -> Result<Box<dyn JoinMethod>, ConfigError> {
        match self {
            JoinConfig::Token { token, token_file } => {
                let raw = read_secret("token", token, token_file)?;
                Ok(Box::new(TokenJoin::new(raw.to_string())))
            }
            JoinConfig::Oidc { token, token_file } => {
                // A file source is preferred (projected/rotated token, re-read at
                // each attest). An inline value is a convenience for tests.
                if let Some(path) = token_file {
                    Ok(Box::new(OidcJoin::from_file(path.clone())))
                } else if let Some(t) = token {
                    Ok(Box::new(OidcJoin::from_literal(t.to_string())))
                } else {
                    Err(ConfigError::Missing("oidc workload token".to_string()))
                }
            }
            JoinConfig::Mtls {
                certificate_file,
                key_file,
            } => {
                let cert = std::fs::read(certificate_file).map_err(|source| ConfigError::Io {
                    path: certificate_file.clone(),
                    source,
                })?;
                let key = std::fs::read_to_string(key_file).map_err(|source| ConfigError::Io {
                    path: key_file.clone(),
                    source,
                })?;
                let jm = MtlsJoin::from_pem(&cert, &key).map_err(|e| ConfigError::Invalid {
                    field: "mtls join material".to_string(),
                    reason: e.to_string(),
                })?;
                Ok(Box::new(jm))
            }
        }
    }
}

fn read_secret(
    field: &str,
    inline: &Option<Zeroizing<String>>,
    file: &Option<PathBuf>,
) -> Result<Zeroizing<String>, ConfigError> {
    if let Some(v) = inline {
        return Ok(v.clone());
    }
    if let Some(path) = file {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
        return Ok(Zeroizing::new(raw.trim().to_string()));
    }
    Err(ConfigError::Missing(field.to_string()))
}

/// Renew-ahead configuration (§8.1). Defaults renew at 2/3 of the cert TTL
/// elapsed (≈1/3 remaining) with ±10% jitter to de-sync a fleet, aligned with the
/// Session-Four Gateway defaults.
#[derive(Debug, Clone)]
pub struct RenewConfig {
    pub renew_ahead_fraction: f64,
    pub renew_jitter_fraction: f64,
    /// On startup, renew immediately if the remaining TTL fraction is at or below
    /// this (a credential loaded near expiry, e.g. the agent was off for a while).
    pub startup_renew_below_fraction: f64,
    pub retry_backoff: Duration,
}

impl Default for RenewConfig {
    fn default() -> Self {
        Self {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            startup_renew_below_fraction: 0.5,
            retry_backoff: Duration::from_secs(30),
        }
    }
}

/// The full Agent identity configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Credential data-dir (+ single-writer lock).
    pub data_dir: PathBuf,
    /// CP mTLS endpoint, `https://host:port`.
    pub cp_endpoint: String,
    /// The server name the CP certificate must carry (SNI + SAN).
    pub cp_server_name: String,
    /// Bound on TCP connect + TLS handshake.
    pub connect_timeout: Duration,
    /// Per-RPC deadline.
    pub rpc_timeout: Duration,
    /// The operator-pinned CP bootstrap trust anchor (PEM path). Verifies the CP
    /// server certificate pre-enrollment (no TOFU).
    pub bootstrap_ca_file: PathBuf,
    /// The stable node identity this Agent joins as (the enrollment key).
    pub node_name: String,
    /// How to bootstrap.
    pub join: JoinConfig,
    /// Renew-ahead knobs.
    pub renew: RenewConfig,
}

impl AgentConfig {
    /// The channel parameters derived from this config.
    pub fn channel_params(&self) -> ChannelParams {
        ChannelParams {
            endpoint: self.cp_endpoint.clone(),
            server_name: self.cp_server_name.clone(),
            connect_timeout: self.connect_timeout,
            rpc_timeout: self.rpc_timeout,
        }
    }

    /// Load the bootstrap trust anchor DERs from the configured PEM file.
    pub fn bootstrap_anchors_der(&self) -> Result<Vec<Vec<u8>>, ConfigError> {
        let pem = std::fs::read(&self.bootstrap_ca_file).map_err(|source| ConfigError::Io {
            path: self.bootstrap_ca_file.clone(),
            source,
        })?;
        crate::mtls::pem_certs_to_der(&pem).map_err(|e| ConfigError::Invalid {
            field: "bootstrap CA".to_string(),
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_join_builds_from_inline_and_file() {
        let inline = JoinConfig::Token {
            token: Some(Zeroizing::new("tok".to_string())),
            token_file: None,
        };
        assert_eq!(inline.method_name(), "token");
        assert!(inline.build().is_ok());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t");
        std::fs::write(&path, "filetok\n").unwrap();
        let from_file = JoinConfig::Token {
            token: None,
            token_file: Some(path),
        };
        assert!(from_file.build().is_ok());
    }

    #[test]
    fn token_join_missing_material_fails_closed() {
        let none = JoinConfig::Token {
            token: None,
            token_file: None,
        };
        assert!(matches!(none.build(), Err(ConfigError::Missing(_))));
    }

    #[test]
    fn renew_defaults_align_with_gateway() {
        let r = RenewConfig::default();
        assert!((r.renew_ahead_fraction - 2.0 / 3.0).abs() < 1e-9);
        assert!((r.renew_jitter_fraction - 0.1).abs() < 1e-9);
    }
}
