//! Agent runtime configuration.

use crate::join::{JoinMethod, MtlsJoin, OidcJoin, TokenJoin};
use crate::mtls::ChannelParams;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

pub const DEFAULT_DATA_DIR: &str = "/var/lib/sessionlayer-agent";
pub const DEFAULT_CP_ENDPOINT: &str = "https://127.0.0.1:9443";
pub const DEFAULT_CP_SERVER_NAME: &str = "controlplane";

pub const DEFAULT_SPLICE_ADDR: &str = "127.0.0.1:22";
pub const DEFAULT_MAX_CONCURRENT_SPLICES: usize = 32;
pub const DEFAULT_MIN_CONTROL_CHANNELS: usize = 1;

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

#[derive(Debug, Clone)]
pub enum JoinConfig {
    Token {
        token: Option<Zeroizing<String>>,
        token_file: Option<PathBuf>,
    },
    Oidc {
        token: Option<Zeroizing<String>>,
        token_file: Option<PathBuf>,
    },
    Mtls {
        certificate_file: PathBuf,
        key_file: PathBuf,
    },
}

impl JoinConfig {
    pub fn method_name(&self) -> &'static str {
        match self {
            JoinConfig::Token { .. } => "token",
            JoinConfig::Oidc { .. } => "oidc",
            JoinConfig::Mtls { .. } => "mtls",
        }
    }

    pub fn build(&self) -> Result<Box<dyn JoinMethod>, ConfigError> {
        match self {
            JoinConfig::Token { token, token_file } => {
                let raw = read_secret("token", token, token_file)?;
                Ok(Box::new(TokenJoin::new(raw.to_string())))
            }
            JoinConfig::Oidc { token, token_file } => {
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

#[derive(Debug, Clone)]
pub struct RenewConfig {
    pub renew_ahead_fraction: f64,
    pub renew_jitter_fraction: f64,
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

#[derive(Debug, Clone)]
pub struct GatewayEndpoint {
    pub url: String,
    pub failure_domain: String,
    pub server_name: String,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub endpoints: Vec<GatewayEndpoint>,
    pub splice_addr: SocketAddr,
    pub max_concurrent_splices: usize,
    pub min_control_channels: usize,
    pub connect_timeout: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    pub drain_deadline: Duration,
}

impl GatewayConfig {
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
        let mut authorities: Vec<String> = Vec::with_capacity(self.endpoints.len());
        for ep in &self.endpoints {
            if ep.server_name.is_empty() {
                return Err(ConfigError::Missing(format!(
                    "--gateway-server-name for {}",
                    ep.url
                )));
            }
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

        if self.endpoints.len() >= 2 {
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

        require_loopback(self.splice_addr)
    }

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

/// Validate splice target: literal loopback only (SSRF defence).
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

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub data_dir: PathBuf,
    pub cp_endpoint: String,
    pub cp_server_name: String,
    pub connect_timeout: Duration,
    pub rpc_timeout: Duration,
    pub bootstrap_ca_file: PathBuf,
    pub node_name: String,
    pub join: JoinConfig,
    pub renew: RenewConfig,
}

impl AgentConfig {
    pub fn channel_params(&self) -> ChannelParams {
        ChannelParams {
            endpoint: self.cp_endpoint.clone(),
            server_name: self.cp_server_name.clone(),
            connect_timeout: self.connect_timeout,
            rpc_timeout: self.rpc_timeout,
        }
    }

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
            server_name: "gateway.test".to_string(),
        }
    }

    fn gateway_config(splice_addr: SocketAddr) -> GatewayConfig {
        GatewayConfig {
            endpoints: vec![
                endpoint("wss://gw-a.test:8443", "az-a"),
                endpoint("wss://gw-b.test:8443", "az-b"),
            ],
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
    fn two_or_more_endpoints_require_at_least_two_diverse_failure_domains() {
        let addr = parse_splice_addr(DEFAULT_SPLICE_ADDR).unwrap();

        let mut same_domain = gateway_config(addr);
        same_domain.endpoints = vec![
            endpoint("wss://gw-a.test:8443", "az-a"),
            endpoint("wss://gw-b.test:8443", "az-a"),
        ];
        assert!(matches!(
            same_domain.validate(),
            Err(ConfigError::Invalid { .. })
        ));

        let mut dup = gateway_config(addr);
        dup.endpoints = vec![
            endpoint("wss://gw-a.test:8443", "az-a"),
            endpoint("wss://gw-a.test:8443", "az-b"),
        ];
        assert!(matches!(dup.validate(), Err(ConfigError::Invalid { .. })));
    }

    #[test]
    fn fewer_endpoints_than_the_min_channel_threshold_is_refused() {
        let addr = parse_splice_addr(DEFAULT_SPLICE_ADDR).unwrap();
        let mut too_few = gateway_config(addr);
        too_few.endpoints = vec![endpoint("wss://gw-a.test:8443", "az-a")];
        too_few.min_control_channels = 2;
        assert!(matches!(
            too_few.validate(),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn single_instance_is_the_default_and_allows_one_channel() {
        let addr = parse_splice_addr(DEFAULT_SPLICE_ADDR).unwrap();
        let mut single = gateway_config(addr);
        single.endpoints = vec![endpoint("wss://gw-a.test:8443", "az-a")];
        assert_eq!(single.min_control_channels, DEFAULT_MIN_CONTROL_CHANNELS);
        assert_eq!(DEFAULT_MIN_CONTROL_CHANNELS, 1);
        single.validate().unwrap();
    }

    #[test]
    fn each_endpoint_carries_its_own_verified_server_name() {
        let addr = parse_splice_addr(DEFAULT_SPLICE_ADDR).unwrap();
        let mut cfg = gateway_config(addr);
        cfg.endpoints[0].server_name = "gw-a-ha".to_string();
        cfg.endpoints[1].server_name = "gw-b-ha".to_string();
        cfg.validate().unwrap();
        assert_ne!(cfg.endpoints[0].server_name, cfg.endpoints[1].server_name);

        cfg.endpoints[1].server_name.clear();
        assert!(matches!(cfg.validate(), Err(ConfigError::Missing(_))));
    }

    #[test]
    fn splice_target_refuses_non_loopback_hostname_and_wildcard() {
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
        no_name.endpoints[0].server_name.clear();
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
        let routable: SocketAddr = "10.0.0.5:22".parse().unwrap();
        assert!(matches!(
            gateway_config(routable).validate(),
            Err(ConfigError::Invalid { .. })
        ));
    }
}
