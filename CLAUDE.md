# SessionLayer Agent — repo guide (CLAUDE.md)

The **Agent** is the per-node **outbound** connector of the SessionLayer
Zero-Trust SSH platform. It dials out to failure-domain-diverse Gateways and, on
demand, dial-backs and splices a connection to the local `sshd` — so a node
needs **no inbound holes** and the Gateway never trusts the node on TOFU
(Design §9.2). This repo is one of four (CP, Gateway, **Agent**, Dashboard);
the canonical cross-repo contracts live in the public `SessionLayer/Contracts`
repo, pinned here via `contracts.lock`.

---

## Scope is per session

Session One was scaffolding only. **Session Twelve added the Agent's durable
identity** (Design §8, FR-JOIN-*): the `JoinMethod` trait + three methods
([`join`]), the renewable mTLS X.509 identity + generation counter + renew-ahead
([`identity`]), a fail-closed non-root check, and the CP-facing mTLS channel
([`mtls`]). The identity machinery is a deliberate port of the Session-Four
Gateway machinery — do NOT reinvent it; reuse `Gateway/gateway-core/src/{identity,mtls,tls,secret}.rs`.

Still **deliberately absent** (later sessions, behind the frozen contracts):

- The wire transport (WebSocket/TLS), framing, HELLO/version negotiation,
  dial-back, stream splice (`contracts/wire/agent-gateway-v1.md`) — **S13**.
- `NodeConnector`, node status/heartbeat, ≥2 control channels (FR-HA-6) — S13/S14.

**If you find yourself implementing an out-of-session `FR-*` behaviour, stop.**
Add it in its designated session.

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
3. **Runtime, fail-closed (S12):** `privilege::require_non_root()` **refuses to
   start** if `euid == 0`, called BEFORE any credential is loaded/issued. From
   S12 the Agent holds a renewable credential and is one hop from host-key
   access, so a root process is a live hazard — the earlier warn-only probe was
   promoted to a hard refusal (closing the S1 carry-forward F-privilege-3).

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

- Source of truth: the public `SessionLayer/Contracts` repo
  (https://github.com/SessionLayer/Contracts), `contracts/proto/...` — pinned by
  `contracts.lock` (tag + resolved commit SHA) at the repo root.
- Vendored copies (committed): `proto/sessionlayer/controlplane/v1/{common,agent}.proto`,
  `proto/sessionlayer/agent/v1/wire.proto`, plus the wire-conformance golden
  frames at `tests/conformance/frames.json`.
- `build.rs` runs `tonic-prost-build` over the vendored copies. `common.proto`
  has the shared messages; `agent.proto` (S12) declares the **`AgentIdentity`**
  service (`EnrollAgent`, `RenewAgentIdentity`) — build.rs emits the **client**
  (the Agent's enroll/renew calls, [`identity`]) and the **server** (used only by
  the in-process mock CP in tests). The CP↔Agent **identity** plane is gRPC/mTLS;
  the future dial-back **data** plane is the framed wire protocol
  (`contracts/wire/agent-gateway-v1.md`, S13).

Why vendor rather than reference across repos: each repo builds standalone, and
committed vendored copies keep builds reproducible and reviewable.

Keep the copy in sync with `scripts/vendor-contracts.sh`:
- `scripts/vendor-contracts.sh` — git-clone the tag pinned in `contracts.lock`,
  verify the resolved commit SHA against the lock (a moved/re-pushed tag fails
  hard), then re-copy the vendored files.
- `scripts/vendor-contracts.sh --check` — same clone + SHA verify, then fail if
  any vendored copy has drifted. CI runs this right after checkout, so drift is
  a **real** failure there (the old sibling-path sync was a silent no-op in CI).

To adopt a new contracts version: update `contracts.lock` (tag + SHA) in a
reviewed PR, run `scripts/vendor-contracts.sh`, regenerate with `cargo build`,
and commit the diff.

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

`tokio` (runtime), `tonic`+`tonic-prost`+`prost` (the CP↔Agent gRPC/mTLS
identity plane — a real runtime consumer since S12), `rustls`+`ring` (pinned TLS
backend, installed at startup; TLS 1.3-only), `rcgen` (local keypair + PKCS#10
CSR generation — key custody, D2/§15), `p256` (MtlsJoin proof-of-possession
ECDSA signing), `rand_core` (renew-ahead jitter), `pem` (DER↔PEM anchors),
`fd-lock` (single-writer data-dir lock, §8.2), `zeroize` (scrub key/token),
`serde`/`serde_json` (persisted manifest + `--version-json`),
`thiserror`/`anyhow` (errors), `clap` (CLI), `libc` (euid probe + the
prctl/setrlimit constants Tier-0 hardening uses). Build-only: `tonic-prost-build`.
Dev-only: `rcgen` gains `x509-parser` via feature-unification (the mock CP signs
CSRs) so production stays lean. Adding a runtime dependency is a supply-chain
decision — justify it here and keep the set minimal (NFR-7).

**Session 21 additions.** Tier-0 hardening (Linux-only, `cfg(target_os="linux")`):
`seccompiler` (pure-Rust seccomp-BPF — one fewer non-Rust input than libseccomp)
builds+installs the syscall allow-list; `landlock` applies the filesystem + network
egress rulesets. OpenTelemetry (Part C, off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is
set): `opentelemetry` + `opentelemetry_sdk` (the SDK), `opentelemetry-otlp`
(`grpc-tonic` + **`tls-ring`**, never native-TLS — the OpenSSL ban holds; it reuses
the same tonic 0.14 already in the tree, no duplicate), `tracing-opentelemetry`
(the `tracing`→OTel bridge). All new crates' licenses (MIT / Apache-2.0 /
BSD-3-Clause) are already in the `deny.toml` allow-list.

---

## Comment discipline (S5-onward baseline)

Comment **sparingly — WHY, not WHAT.** No section-divider banners, no comments
that restate code or a name, no obvious narration. Prefer self-documenting names
and small functions. Keep terse doc-comments only on genuinely public API /
contract surfaces and a brief note for a security/crypto/spec-tied invariant
(e.g. "fail closed", a WHY tied to an FR/Design §). Match the leaner post-S5
baseline shared across the repos; do not restore a denser style.

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
