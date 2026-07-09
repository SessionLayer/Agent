# F-privilege-3: root detector warns rather than fails closed
- Severity: info
- Status: Accepted-Risk
- Area: privilege

The task explicitly asked for a verdict on warn-vs-hard-exit; both auditors
reviewed it and concurred.

## Assessment
Warn-not-exit is the correct calibration for Session One. FR-CONN-6's concrete
harm — a root Agent reading the node host key to impersonate the node — requires
product behaviour that does not exist yet (no host-key access, no TLS handshake,
no credential material). The process installs a crypto provider, logs readiness,
and exits, so running as root grants an attacker nothing to gate. The actual
guarantee is structural (immutable image `USER 65532:65532`, the CI non-root
regression guard, and Kubernetes `runAsNonRoot`); a scaffold refusing to boot on
`euid==0` would break trivial dev/`--version` runs for no security gain.

## Decision: Accepted-Risk (this session), with a load-bearing follow-up
`warn_if_root()` MUST be promoted to fail-closed (hard exit) the moment S12
introduces the mTLS identity / host-key access / credential storage — from that
point a root process can actually read the host key. Tracked here and in the
`src/privilege.rs` module docs so the warn-only posture cannot silently outlive
the scaffold.
