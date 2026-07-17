//! Tier-0 runtime hardening (Part A / NFR-5 / Design §15), **fail-closed**.
//!
//! The Agent already runs non-root ([`crate::privilege`]); this narrows what the
//! process can still do to the minimum the data path needs, so a compromise of the
//! Agent process is contained:
//!
//! - **coredump/ptrace hygiene** — `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`, so the
//!   mTLS private key and the join token can never land in a coredump and the
//!   process cannot be `ptrace`d for its memory.
//! - **Landlock filesystem** — writes are confined to the credential data-dir; the
//!   bootstrap CA + join files are read-only; everything else is read-only (or
//!   unreachable). A compromised Agent cannot tamper with binaries/config or drop
//!   persistence.
//! - **Landlock network egress** — TCP `connect` is allowed only to the exact set
//!   of destination **ports** the Agent legitimately reaches: the CP identity
//!   plane, each configured Gateway, the **loopback splice** to the node's sshd,
//!   and (only when configured) the OTLP collector. No other egress — the Agent
//!   cannot be used as a network pivot even if a Gateway is hostile.
//! - **seccomp** — a syscall allow-list scoped to the runtime + TLS + WebSocket +
//!   dial-back + loopback-splice path. Anything outside it **kills the process**
//!   (`SECCOMP_RET_KILL_PROCESS`) — clean fail-closed, and it sidesteps the
//!   `panic=abort`/`SIGSYS` interaction a trap-based action would have.
//!
//! **Whole-process coverage.** Landlock restricts the calling thread and every
//! thread spawned *after* it (there is no TSYNC for Landlock); seccomp is applied
//! with TSYNC. The binary therefore applies hardening **before it builds the tokio
//! runtime** (`main`), so every worker inherits both the Landlock domain and the
//! seccomp filter. Seccomp is installed **last** so the Landlock syscalls run
//! before the filter is active and never need to be on the allow-list.
//!
//! **Fail-closed policy.** A step that *can* apply but fails to → the process
//! aborts (never runs unhardened). A **kernel that lacks Landlock** (or the network
//! ABI) is the one documented exception: a loud, explicit Accepted-Risk *degrade*,
//! never a silent one (seccomp + the loopback-only splice validation still hold).

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::config::{AgentConfig, GatewayConfig, JoinConfig};

/// OTLP/gRPC default port (used when `OTEL_EXPORTER_OTLP_ENDPOINT` names no port).
const OTLP_DEFAULT_PORT: u16 = 4317;
/// Default TLS port for `https://`/`wss://` endpoints that name no port.
const TLS_DEFAULT_PORT: u16 = 443;

/// The concrete, config-derived hardening surface: what the process may write, what
/// it may read, and which TCP destination ports it may `connect` to. Computed from
/// configuration (platform-independent, unit-testable) and consumed by [`apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardeningPlan {
    /// Writable + readable (the credential data-dir and everything beneath it).
    pub read_write_paths: Vec<PathBuf>,
    /// Read-only (bootstrap CA + any join-material files).
    pub read_only_paths: Vec<PathBuf>,
    /// The egress allow-list: the only TCP ports `connect` may target.
    pub allowed_connect_ports: Vec<u16>,
}

impl HardeningPlan {
    /// Derive the plan from configuration. `otlp_port` is `Some` only when the OTLP
    /// exporter is enabled (its collector is the Agent's only non-CP/Gateway/loopback
    /// egress and must be permitted, or export would break under the ruleset).
    pub fn derive(
        config: &AgentConfig,
        gateway: &Option<GatewayConfig>,
        otlp_port: Option<u16>,
    ) -> Self {
        let mut ports: Vec<u16> = Vec::new();
        let push = |p: Option<u16>, ports: &mut Vec<u16>| {
            if let Some(p) = p {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
        };
        // CP identity plane (enroll + renew).
        push(url_port(&config.cp_endpoint, TLS_DEFAULT_PORT), &mut ports);
        if let Some(gw) = gateway {
            // Every configured Gateway control channel + the same-Gateway dial-back.
            for ep in &gw.endpoints {
                push(url_port(&ep.url, TLS_DEFAULT_PORT), &mut ports);
            }
            // The loopback splice to the node's own sshd — the platform's whole point.
            push(Some(gw.splice_addr.port()), &mut ports);
        }
        push(otlp_port, &mut ports);
        ports.sort_unstable();

        let mut read_only_paths = vec![config.bootstrap_ca_file.clone()];
        read_only_paths.extend(join_material_paths(&config.join));

        Self {
            read_write_paths: vec![config.data_dir.clone()],
            read_only_paths,
            allowed_connect_ports: ports,
        }
    }
}

/// The files a join method reads at bootstrap (so Landlock can permit exactly them).
fn join_material_paths(join: &JoinConfig) -> Vec<PathBuf> {
    match join {
        JoinConfig::Token { token_file, .. } | JoinConfig::Oidc { token_file, .. } => {
            token_file.iter().cloned().collect()
        }
        JoinConfig::Mtls {
            certificate_file,
            key_file,
        } => vec![certificate_file.clone(), key_file.clone()],
    }
}

/// The OTLP collector's TCP port from `OTEL_EXPORTER_OTLP_ENDPOINT` (default 4317,
/// OTLP/gRPC), so the egress allow-list can permit exactly it. `None` if the
/// endpoint names no derivable port.
pub fn otlp_port(endpoint: &str) -> Option<u16> {
    url_port(endpoint, OTLP_DEFAULT_PORT)
}

/// Extract the destination port from an endpoint string: an `https://`/`wss://`
/// URI, a bare `host:port`, or a literal socket address. Falls back to `default`
/// for a scheme with no explicit port. `None` if no port can be determined.
fn url_port(s: &str, default: u16) -> Option<u16> {
    use tokio_tungstenite::tungstenite::http::Uri;
    if let Ok(uri) = s.parse::<Uri>() {
        if let Some(p) = uri.port_u16() {
            return Some(p);
        }
        if uri.host().is_some() {
            return Some(default);
        }
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr.port());
    }
    s.rsplit_once(':').and_then(|(_, port)| port.parse().ok())
}

/// What [`apply`] actually enforced, for the startup log + the E2E-under-hardening
/// assertion.
#[derive(Debug)]
pub struct Report {
    pub coredumps_disabled: bool,
    pub landlock: Landlock,
    pub seccomp_syscalls: usize,
    pub allowed_ports: Vec<u16>,
}

/// The Landlock enforcement outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum Landlock {
    /// The full ruleset (fs + net egress) is enforced.
    FullyEnforced,
    /// Enforced best-effort — some access types are unsupported on this kernel
    /// (e.g. network egress needs ABI v4 / Linux 6.7). A documented degrade.
    PartiallyEnforced,
    /// The kernel has no Landlock support at all — the Accepted-Risk degrade.
    Unavailable,
}

/// Apply Tier-0 hardening for the run described by `config`/`gateway`. Fails closed
/// (returns `Err`, so the caller aborts) if a step that should apply cannot; a
/// kernel that lacks Landlock is a loud degrade, not an error.
///
/// MUST be called while the process is still single-threaded (before the tokio
/// runtime is built) so Landlock covers every worker (see the module docs).
pub fn apply(
    config: &AgentConfig,
    gateway: &Option<GatewayConfig>,
    otlp_port: Option<u16>,
) -> anyhow::Result<Report> {
    let plan = HardeningPlan::derive(config, gateway, otlp_port);
    tracing::info!(
        write = ?plan.read_write_paths,
        read = ?plan.read_only_paths,
        egress_ports = ?plan.allowed_connect_ports,
        "applying Tier-0 runtime hardening (coredump + Landlock + seccomp)"
    );
    apply_impl(&plan)
}

#[cfg(target_os = "linux")]
mod imp;

/// Test-only seam so a forked child can install the exact production seccomp
/// allow-list — compiled in the parent (allocates) and applied in the child (no
/// allocation → fork-safe) — to prove a disallowed syscall is KILLED
/// (`SECCOMP_RET_KILL_PROCESS`). Not for production use; real hardening goes
/// through [`apply`].
#[doc(hidden)]
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod testing {
    /// Compile the production seccomp program (parent side).
    pub fn compile_seccomp() -> anyhow::Result<seccompiler::BpfProgram> {
        super::imp::compile_seccomp().map(|(program, _count)| program)
    }
    /// Install a compiled program on the caller's thread group (child side).
    pub fn apply_seccomp(program: &seccompiler::BpfProgram) -> anyhow::Result<()> {
        super::imp::apply_seccomp(program)
    }
}

#[cfg(target_os = "linux")]
fn apply_impl(plan: &HardeningPlan) -> anyhow::Result<Report> {
    imp::apply(plan)
}

#[cfg(not(target_os = "linux"))]
fn apply_impl(plan: &HardeningPlan) -> anyhow::Result<Report> {
    // The Agent ships only on Linux (distroless); a non-Linux build is dev-only and
    // has no LSM to apply. Degrade loudly rather than pretend to be hardened.
    tracing::warn!(
        "Tier-0 hardening is a no-op on this non-Linux target (dev only); the shipped \
         Agent runs on Linux where seccomp + Landlock are enforced"
    );
    Ok(Report {
        coredumps_disabled: false,
        landlock: Landlock::Unavailable,
        seccomp_syscalls: 0,
        allowed_ports: plan.allowed_connect_ports.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{JoinConfig, RenewConfig};
    use std::time::Duration;

    fn base_config(data_dir: &str, cp: &str, join: JoinConfig) -> AgentConfig {
        AgentConfig {
            data_dir: data_dir.into(),
            cp_endpoint: cp.into(),
            cp_server_name: "controlplane".into(),
            connect_timeout: Duration::from_secs(10),
            rpc_timeout: Duration::from_secs(30),
            bootstrap_ca_file: "/etc/sl/ca.pem".into(),
            node_name: "n1".into(),
            join,
            renew: RenewConfig::default(),
        }
    }

    fn gw(splice: &str, endpoints: &[&str]) -> Option<GatewayConfig> {
        Some(GatewayConfig {
            endpoints: endpoints
                .iter()
                .map(|u| crate::config::GatewayEndpoint {
                    url: u.to_string(),
                    failure_domain: u.to_string(),
                    server_name: "gateway".into(),
                })
                .collect(),
            splice_addr: splice.parse().unwrap(),
            max_concurrent_splices: 32,
            min_control_channels: 1,
            connect_timeout: Duration::from_secs(10),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            drain_deadline: Duration::from_secs(30),
        })
    }

    #[test]
    fn url_port_parses_uris_addrs_and_defaults() {
        assert_eq!(url_port("https://cp.example:9443", 443), Some(9443));
        assert_eq!(url_port("https://cp.example", 443), Some(443));
        assert_eq!(url_port("wss://gw.example:8443/x", 443), Some(8443));
        assert_eq!(url_port("127.0.0.1:22", 443), Some(22));
        assert_eq!(url_port("http://collector:4317", 4317), Some(4317));
        assert_eq!(url_port("collector:4317", 4317), Some(4317));
    }

    #[test]
    fn plan_covers_cp_every_gateway_the_splice_and_otlp() {
        let join = JoinConfig::Token {
            token: Some(zeroize::Zeroizing::new("t".into())),
            token_file: None,
        };
        let config = base_config("/var/lib/agent", "https://cp:9443", join);
        let gateway = gw("127.0.0.1:2222", &["wss://gw-a:8443", "wss://gw-b:9443"]);
        let plan = HardeningPlan::derive(&config, &gateway, Some(4317));

        // The egress allow-list MUST contain every real destination and nothing else.
        assert_eq!(plan.allowed_connect_ports, vec![2222, 4317, 8443, 9443]);
        assert_eq!(plan.read_write_paths, vec![PathBuf::from("/var/lib/agent")]);
        assert_eq!(plan.read_only_paths, vec![PathBuf::from("/etc/sl/ca.pem")]);
    }

    #[test]
    fn plan_includes_the_loopback_splice_port_so_the_splice_is_never_broken() {
        // The single most load-bearing entry: without the splice port in the egress
        // allow-list, the dial-back → node-sshd splice (the platform's point) breaks.
        let join = JoinConfig::Token {
            token: None,
            token_file: Some("/run/secrets/join".into()),
        };
        let config = base_config("/data", "https://cp:443", join);
        let gateway = gw("127.0.0.1:22", &["wss://gw:443"]);
        let plan = HardeningPlan::derive(&config, &gateway, None);
        assert!(
            plan.allowed_connect_ports.contains(&22),
            "splice port must be allowed"
        );
        // The join-token file is read-only material Landlock must permit.
        assert!(plan
            .read_only_paths
            .contains(&PathBuf::from("/run/secrets/join")));
    }

    #[test]
    fn identity_only_plan_has_no_gateway_or_splice_egress() {
        let join = JoinConfig::Mtls {
            certificate_file: "/etc/sl/op.crt".into(),
            key_file: "/etc/sl/op.key".into(),
        };
        let config = base_config("/data", "https://cp:9443", join);
        let plan = HardeningPlan::derive(&config, &None, None);
        assert_eq!(plan.allowed_connect_ports, vec![9443]);
        assert!(plan
            .read_only_paths
            .contains(&PathBuf::from("/etc/sl/op.crt")));
        assert!(plan
            .read_only_paths
            .contains(&PathBuf::from("/etc/sl/op.key")));
    }
}
