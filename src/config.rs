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
use std::net::SocketAddr;
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

/// Default splice target: the node's own `sshd`, on loopback (Design §9.2).
pub const DEFAULT_SPLICE_ADDR: &str = "127.0.0.1:22";
/// Default cap on simultaneous spliced sessions this Agent will serve.
pub const DEFAULT_MAX_CONCURRENT_SPLICES: usize = 32;
/// Default number of control channels an Agent must hold — **2**, to
/// failure-domain-diverse Gateways (FR-HA-6). Set to 1 for single-instance mode.
pub const DEFAULT_MIN_CONTROL_CHANNELS: usize = 2;

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
                // The operator PKI private key is a long-lived, high-value secret:
                // hold it in a scrub-on-drop buffer like every other secret here,
                // so it is not left in a freed-but-unscrubbed heap allocation.
                let key = Zeroizing::new(std::fs::read_to_string(key_file).map_err(|source| {
                    ConfigError::Io {
                        path: key_file.clone(),
                        source,
                    }
                })?);
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

/// One Gateway control-channel target: where to dial, and which **failure domain**
/// it lives in. The Agent holds a channel to each and requires ≥2 distinct domains
/// (FR-HA-6) so losing one domain never strands the node.
#[derive(Debug, Clone)]
pub struct GatewayEndpoint {
    /// The `wss://host:port` address to dial out to.
    pub url: String,
    /// An operator-assigned failure-domain label (rack / AZ / region). Two channels
    /// in the same domain are not diverse; the default is the endpoint's **host**,
    /// so two Gateways on one host are correctly treated as one domain (fail-closed).
    pub failure_domain: String,
}

/// The Agent's outbound-connectivity configuration (S14; HA channels S15): the
/// Gateway control channels, and the local splice target the dial-back is joined to.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Gateway endpoints to dial **out** to (FR-HA-6). The Agent holds one control
    /// channel per endpoint concurrently — it does **not** mesh.
    pub endpoints: Vec<GatewayEndpoint>,
    /// The Gateway's enrolled name — the dNSName SAN its **serverAuth** leaf must
    /// carry. Dial an address, verify a name: the address never authorises anything
    /// (no TOFU on this path either).
    pub server_name: String,
    /// The node-local address the dial-back is spliced to. **Loopback-validated at
    /// startup** ([`parse_splice_addr`]); nothing on the wire can change it.
    pub splice_addr: SocketAddr,
    /// Cap on simultaneous spliced sessions (a dial-back beyond it is REFUSED),
    /// shared across all control channels.
    pub max_concurrent_splices: usize,
    /// Minimum control channels this Agent must be configured with, to that many
    /// failure-domain-diverse Gateways (FR-HA-6). Default 2; set 1 for
    /// single-instance mode.
    pub min_control_channels: usize,
    /// Bound on TCP connect + TLS handshake + the connection preface.
    pub connect_timeout: Duration,
    /// First reconnect backoff step; doubles up to [`Self::backoff_max`], ±50%
    /// jitter, indefinitely (§7).
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// How long live splices may keep running after the Agent has stopped taking
    /// new work (a terminal identity outcome, or shutdown) before they are cut.
    pub drain_deadline: Duration,
}

impl GatewayConfig {
    /// Reject a configuration that could not be served safely. Fails startup closed
    /// rather than coming up in a degraded posture.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.endpoints.is_empty() {
            return Err(ConfigError::Missing("--gateway-endpoint".to_string()));
        }
        if self.max_concurrent_splices == 0 {
            return Err(ConfigError::Invalid {
                field: "--max-concurrent-splices".to_string(),
                reason: "must be at least 1".to_string(),
            });
        }
        if self.min_control_channels == 0 {
            return Err(ConfigError::Invalid {
                field: "--min-control-channels".to_string(),
                reason: "must be at least 1".to_string(),
            });
        }
        if self.server_name.is_empty() {
            return Err(ConfigError::Missing("--gateway-server-name".to_string()));
        }

        // Two Gateways at the same authority are not two channels; a duplicate is a
        // config error, not silent single-homing dressed up as HA.
        let mut authorities: Vec<String> = Vec::with_capacity(self.endpoints.len());
        for ep in &self.endpoints {
            let auth = crate::gateway::transport::authority_of(&ep.url).map_err(|e| {
                ConfigError::Invalid {
                    field: "--gateway-endpoint".to_string(),
                    reason: e.to_string(),
                }
            })?;
            if authorities.contains(&auth) {
                return Err(ConfigError::Invalid {
                    field: "--gateway-endpoint".to_string(),
                    reason: format!("{} is listed more than once", ep.url),
                });
            }
            authorities.push(auth);
        }

        if self.endpoints.len() < self.min_control_channels {
            return Err(ConfigError::Invalid {
                field: "--gateway-endpoint".to_string(),
                reason: format!(
                    "{} endpoint(s) configured but --min-control-channels is {}; \
                     the Agent needs at least that many diverse Gateways (FR-HA-6). \
                     Use --min-control-channels 1 for single-instance mode",
                    self.endpoints.len(),
                    self.min_control_channels
                ),
            });
        }

        // HA (≥2 channels) is only real availability if the channels span ≥2 failure
        // domains — otherwise one rack/AZ outage takes them all. Single-instance
        // (min == 1) is exempt (there is nothing to diversify).
        if self.min_control_channels >= 2 {
            let distinct = self.distinct_failure_domains();
            if distinct < 2 {
                return Err(ConfigError::Invalid {
                    field: "--gateway-failure-domain".to_string(),
                    reason: format!(
                        "the {} control channels span only {distinct} failure domain(s); \
                         ≥2 diverse domains are required (FR-HA-6) so losing one domain \
                         does not strand the node. Label endpoints on distinct hosts, or \
                         pass --gateway-failure-domain",
                        self.endpoints.len()
                    ),
                });
            }
        }

        // Defence in depth: the splice address is loopback-validated where it is
        // parsed, but re-assert it here so no construction path can bypass it.
        require_loopback(self.splice_addr)
    }

    /// The number of distinct failure domains across the configured endpoints.
    pub fn distinct_failure_domains(&self) -> usize {
        let mut seen: Vec<&str> = Vec::new();
        for ep in &self.endpoints {
            if !seen.contains(&ep.failure_domain.as_str()) {
                seen.push(&ep.failure_domain);
            }
        }
        seen.len()
    }
}

/// Parse and **validate** the splice target: it MUST be a literal loopback socket
/// address (`127.0.0.0/8` or `::1`).
///
/// This is the confused-deputy / SSRF defence (contract §5), and it is structural
/// rather than a check on hostile input: `DIAL_BACK_REQUEST` deliberately carries
/// no target, so the Agent's splice destination comes only from its own local
/// configuration. A Gateway — however compromised — cannot redirect the splice or
/// use the Agent as a network pivot into the node's subnet.
///
/// A hostname is refused too: it would be resolved at dial time, which hands the
/// destination to whatever answers DNS, and a name that resolves to loopback today
/// can resolve elsewhere tomorrow.
pub fn parse_splice_addr(raw: &str) -> Result<SocketAddr, ConfigError> {
    let addr: SocketAddr = raw.parse().map_err(|_| ConfigError::Invalid {
        field: "--splice-addr".to_string(),
        reason: format!(
            "{raw:?} is not a literal IP socket address (a hostname is refused: \
             it must be a loopback IP:port such as 127.0.0.1:22)"
        ),
    })?;
    require_loopback(addr)?;
    Ok(addr)
}

fn require_loopback(addr: SocketAddr) -> Result<(), ConfigError> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    Err(ConfigError::Invalid {
        field: "--splice-addr".to_string(),
        reason: format!(
            "{addr} is not a loopback address; the Agent splices only to its own \
             node's sshd (127.0.0.0/8 or ::1) and refuses to start otherwise"
        ),
    })
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

    fn endpoint(url: &str, domain: &str) -> GatewayEndpoint {
        GatewayEndpoint {
            url: url.to_string(),
            failure_domain: domain.to_string(),
        }
    }

    /// A valid HA config: two channels in two distinct failure domains.
    fn gateway_config(splice_addr: SocketAddr) -> GatewayConfig {
        GatewayConfig {
            endpoints: vec![
                endpoint("wss://gw-a.test:8443", "az-a"),
                endpoint("wss://gw-b.test:8443", "az-b"),
            ],
            server_name: "gateway.test".to_string(),
            splice_addr,
            max_concurrent_splices: DEFAULT_MAX_CONCURRENT_SPLICES,
            min_control_channels: DEFAULT_MIN_CONTROL_CHANNELS,
            connect_timeout: Duration::from_secs(10),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            drain_deadline: Duration::from_secs(30),
        }
    }

    #[test]
    fn splice_target_accepts_only_loopback() {
        for ok in ["127.0.0.1:22", "127.0.0.53:2222", "[::1]:22"] {
            let addr = parse_splice_addr(ok).unwrap_or_else(|e| panic!("{ok} must parse: {e}"));
            assert!(addr.ip().is_loopback());
            gateway_config(addr).validate().unwrap();
        }
    }

    #[test]
    fn ha_requires_at_least_two_diverse_failure_domains() {
        let addr = parse_splice_addr(DEFAULT_SPLICE_ADDR).unwrap();

        // Two channels but ONE failure domain: not diverse — one AZ outage takes
        // both, so it is not HA. Fail closed.
        let mut same_domain = gateway_config(addr);
        same_domain.endpoints = vec![
            endpoint("wss://gw-a.test:8443", "az-a"),
            endpoint("wss://gw-b.test:8443", "az-a"),
        ];
        assert!(matches!(
            same_domain.validate(),
            Err(ConfigError::Invalid { .. })
        ));

        // Fewer endpoints than min_control_channels.
        let mut too_few = gateway_config(addr);
        too_few.endpoints = vec![endpoint("wss://gw-a.test:8443", "az-a")];
        assert!(matches!(
            too_few.validate(),
            Err(ConfigError::Invalid { .. })
        ));

        // A duplicate authority is not a second channel.
        let mut dup = gateway_config(addr);
        dup.endpoints = vec![
            endpoint("wss://gw-a.test:8443", "az-a"),
            endpoint("wss://gw-a.test:8443", "az-b"),
        ];
        assert!(matches!(dup.validate(), Err(ConfigError::Invalid { .. })));
    }

    #[test]
    fn single_instance_mode_allows_one_channel() {
        // min_control_channels == 1 opts out of the diversity requirement (there is
        // nothing to diversify) — S14's single-Gateway posture stays valid.
        let addr = parse_splice_addr(DEFAULT_SPLICE_ADDR).unwrap();
        let mut single = gateway_config(addr);
        single.endpoints = vec![endpoint("wss://gw-a.test:8443", "az-a")];
        single.min_control_channels = 1;
        single.validate().unwrap();
    }

    #[test]
    fn splice_target_refuses_non_loopback_hostname_and_wildcard() {
        // The SSRF / confused-deputy defence (contract §5). A routable address
        // would make the Agent a network pivot; the wildcard is not a destination;
        // a hostname hands the destination to DNS.
        for bad in [
            "10.0.0.5:22",
            "0.0.0.0:22",
            "192.168.1.10:22",
            "8.8.8.8:22",
            "[::]:22",
            "localhost:22",
            "sshd.internal:22",
            "not-an-address",
        ] {
            let err = parse_splice_addr(bad)
                .expect_err("a non-loopback splice target must fail startup closed");
            assert!(matches!(err, ConfigError::Invalid { .. }), "{bad}: {err}");
        }
    }

    #[test]
    fn gateway_config_validation_fails_closed_on_empty_and_zero_values() {
        let addr = parse_splice_addr(DEFAULT_SPLICE_ADDR).unwrap();

        let mut no_endpoint = gateway_config(addr);
        no_endpoint.endpoints.clear();
        assert!(matches!(
            no_endpoint.validate(),
            Err(ConfigError::Missing(_))
        ));

        let mut no_name = gateway_config(addr);
        no_name.server_name.clear();
        assert!(matches!(no_name.validate(), Err(ConfigError::Missing(_))));

        let mut no_splices = gateway_config(addr);
        no_splices.max_concurrent_splices = 0;
        assert!(matches!(
            no_splices.validate(),
            Err(ConfigError::Invalid { .. })
        ));

        let mut no_channels = gateway_config(addr);
        no_channels.min_control_channels = 0;
        assert!(matches!(
            no_channels.validate(),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn gateway_config_validate_rejects_a_non_loopback_splice_addr_built_directly() {
        // No construction path may bypass the loopback rule, not even one that
        // skips `parse_splice_addr`.
        let routable: SocketAddr = "10.0.0.5:22".parse().unwrap();
        assert!(matches!(
            gateway_config(routable).validate(),
            Err(ConfigError::Invalid { .. })
        ));
    }
}
