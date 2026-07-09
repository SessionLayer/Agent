# SessionLayer Agent — repo guide (CLAUDE.md)

The **Agent** is the per-node **outbound** connector of the SessionLayer
Zero-Trust SSH platform. It dials out to failure-domain-diverse Gateways and, on
demand, dial-backs and splices a connection to the local `sshd` — so a node
needs **no inbound holes** and the Gateway never trusts the node on TOFU
(Design §9.2). This repo is one of four (CP, Gateway, **Agent**, Dashboard);
the canonical cross-repo contracts live in `ControlPlane-API/contracts/`.

---

## Scope is per session — Session One is scaffolding ONLY

This repo currently contains **no product behaviour**. Session One delivered the
package, contract codegen, the `--version` surface, the non-root posture, and
the quality/CI gate — nothing more. The following are **deliberately absent** and
arrive in later sessions behind the frozen contracts:

- `JoinMethod` (token / OIDC / mTLS bootstrap), the durable mTLS X.509 identity,
  the generation counter, renew-ahead (FR-JOIN-*) — **S12**.
- The wire transport (WebSocket/TLS), framing, HELLO/version negotiation,
  dial-back, stream splice (`contracts/wire/agent-gateway-v1.md`) — **S13**.
- `NodeConnector`, node status/heartbeat, ≥2 control channels (FR-HA-6) — S12/S13.

**If you find yourself implementing an `FR-*` behaviour, you are out of scope for
a scaffolding change.** Add the behaviour in its designated session.

---

## Non-root is a HARD requirement (FR-CONN-6 / Design §9.3, D24)

The Agent MUST run as a **dedicated non-root user**. This is a security control,
not a nicety: node host keys are root-only, so a root Agent that is compromised
could read the host key and **impersonate the node**, collapsing host-identity
verification from "node-root-compromise" back to "agent-process-compromise".

How it is enforced, in layers:
1. **Structural (the guarantee):** `Dockerfile` builds in a throwaway builder
   stage and runs in a distroless runtime under `USER 65532:65532`. There is no
   `USER root` in the final stage.
2. **CI regression guard:** `scripts/check-dockerfile-nonroot.sh` (in the `gate`
   job) fails the build if the final runtime `USER` is ever root/empty.
   `scripts/verify-nonroot-image.sh` does the full build-and-`docker inspect`
   check (needs Docker + network).
3. **Runtime detector:** `privilege::warn_if_root()` logs a loud warning if the
   process ever finds `euid == 0`. It warns rather than hard-exits — the
   enforcement point is the immutable image/deployment, and later sessions may
   promote this to fail-closed once the deployment contract is fully specified.

---

## Runtime: plain multi-threaded tokio — NO io_uring

The Agent uses a plain multi-threaded `tokio` runtime. It is a **control-plane
participant** (dial-out, negotiation, heartbeat, dial-back signalling), **not a
hot byte-copy datapath** — the SSH ciphertext splice is a modest per-session
stream, and the platform's high-throughput path lives in the Gateway. So
`tokio-uring` is deliberately **not** used: io_uring's benefit is saturating
many concurrent syscalls on a byte-copy fast path, which the Agent does not have,
and it would add a Linux-version-specific, harder-to-audit dependency for no
throughput the Agent needs. Revisit only if profiling the S13 splice proves a
syscall bottleneck.

---

## TLS backend: one explicit rustls provider, no OpenSSL

`init_process()` installs a single `rustls` crypto provider (**ring**) at
startup, before any TLS is used, so the whole fleet uses one audited,
memory-safe backend. rustls is **TLS 1.3-only** (the `tls12` feature is not
enabled — both ends of the Agent's plane are first-party, so there is no TLS 1.2
negotiation/downgrade surface). `deny.toml` **bans the `openssl`/`openssl-sys`
crates** so the C OpenSSL stack can never enter the tree. Installing the provider
**fails closed**: if it cannot be installed the process aborts rather than drift
toward an unauthenticated transport.

---

## Contract vendoring + sync + N-1 policy

The Agent is **contract-first** (Design §13, FR-API-1). It does not hand-write
the shared message types; it generates them from a **byte-identical vendored
copy** of the canonical proto:

- Source of truth: `ControlPlane-API/contracts/proto/sessionlayer/controlplane/v1/common.proto`.
- Vendored copy (committed): `proto/sessionlayer/controlplane/v1/common.proto`.
- `build.rs` runs `tonic-build`/`prost-build` over the vendored copy. `common.proto`
  declares **no service**, so only the message types (`ProtocolVersion`,
  `ComponentInfo`) are generated — no gRPC stub. The Agent's live plane to the
  Gateway is the **framed wire protocol** (`contracts/wire/agent-gateway-v1.md`),
  not gRPC.

Why vendor rather than reference across repos: the parent `SessionLayer/` folder
is intentionally **not** a git repo, and CI checks out this repo alone.

Keep the copy in sync with `scripts/sync-contracts.sh`:
- `scripts/sync-contracts.sh` — re-copy from the sibling contracts repo when
  present (local dev); a documented no-op in CI (source absent).
- `scripts/sync-contracts.sh --check` — fail if the vendored copy has drifted.

**N-1 compatibility (contracts/VERSIONING.md, D33/FR-HA-9):** protocol versions
are `major.minor`; a component supports peers **one minor back** (`protocol_min`
stays at N-1 from the first minor bump). The Session One baseline is `1.0`
(`min == max == 1.0`; no prior minor exists yet). The negotiation *algorithm*
itself is out of scope this session (it ships with the transport in S13).

---

## Layout & version single-sourcing

Single Cargo package that is **both a library and a thin binary**:
`sessionlayer_agent` (lib, `src/lib.rs`) + `sessionlayer-agent` (bin,
`src/main.rs`). The library split keeps the version logic unit-testable without
the build cost of a multi-crate workspace on a shared 2-core builder. A
workspace (`agent` + `agent-core`) is deferred until there is enough logic to
justify it (S12/S13).

- Build (artifact) version = `CARGO_PKG_VERSION` (`0.1.0`) — single-sourced.
- Wire-protocol version constants live in `src/version.rs`; a unit test guards
  the human `--version` banner against drifting from them.
- `--version` prints SemVer + the supported wire-protocol range; `--version-json`
  emits the machine-readable descriptor.

## Dependencies (why each is here; NFR-7 keeps this list honest)

`tokio` (runtime), `prost` (generated types), `tracing`(+`-subscriber`)
(logging), `serde`/`serde_json` (`--version-json`), `thiserror`/`anyhow`
(errors), `clap` (CLI), `rustls`+`ring` (pinned TLS backend, installed at
startup), `libc` (euid probe; already transitive via tokio). `tonic` is the
pinned Rust gRPC runtime, **re-exported from `grpc`** so it is a tracked
dependency rather than dead weight; it is carried for toolchain symmetry with
the Gateway/CP and for the CP-adjacent codegen wired in a later session (the
Agent's own plane is the wire protocol, not gRPC). `tonic-build` is a build-only
codegen tool. Adding a runtime dependency is a supply-chain decision — justify it
here and keep the set minimal.

---

## Gate & audit

Run the full gate locally exactly as CI does:

```bash
./scripts/gate.sh
# = cargo fmt --check
#   cargo clippy --all-targets --all-features -- -D warnings
#   cargo nextest run --all-features
#   cargo audit -D warnings
#   cargo deny check
#   + audit/ zero-open-medium+-findings check
```

- **CI** (`.github/workflows/ci.yml`): one job id `gate` (the required check);
  all actions pinned by full commit SHA.
- **Toolchain** pinned in `rust-toolchain.toml` (`1.95.0`) for reproducible
  builds (NFR-7).

**Findings workflow (`audit/`):** `audit/STATE` is `ROUND_DISCOVERY` while
building, `ROUND_FINAL` only when clean and the gate passes. Findings are
`audit/F-<area>-<n>.md` with this exact front-matter (tooling greps it):

```
# F-<area>-<n>: <title>
- Severity: critical|high|medium|low|info
- Status: Open|Verified-Fixed|Accepted-Risk
- Area: <area>
```

Resolved **medium+** findings are **moved to `audit/closed/`** (the ROUND_FINAL
idle hook counts any medium+ severity file left under `audit/` regardless of
status). Do not idle in `ROUND_FINAL` with a failing gate.

Session One's red-team pass (`redteam-auditor` + `security-reviewer`) found **no
medium+ issues**; the nine low/info findings (`audit/F-*.md`) are all
Verified-Fixed or Accepted-Risk. The two load-bearing follow-ups for later
sessions: promote `warn_if_root()` to fail-closed once host-key access lands
(F-privilege-3), and pin base-image digests in the release pipeline (F-docker-2).

## Supply-chain intent (NFR-7)

Agent releases target SLSA provenance + Sigstore signature + SBOM + reproducible
builds, with nodes verifying the signature before run/update. Session One lays
the groundwork: pinned toolchain, pinned CI action SHAs, a committed `Cargo.lock`,
`--locked` builds, a minimal reviewed dependency set, an exact-match license
allow-list, an OpenSSL ban, and a deterministic release profile. The signing /
provenance / SBOM pipeline itself is a later session.
