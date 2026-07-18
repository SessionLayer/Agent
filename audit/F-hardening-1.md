# F-hardening-1: Tier-0 hardening residual risks (Landlock degrade + OTLP export threads)
- Severity: low
- Status: Accepted-Risk
- Area: hardening

## Context
Part A adds in-process Tier-0 hardening (`src/hardening.rs`): coredump/ptrace
hygiene (`RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`), a Landlock filesystem ruleset
(writes confined to the data-dir), a Landlock network egress allow-list (TCP
`connect` only to the CP, each Gateway, the loopback splice, and the OTLP collector
when set), and a seccomp syscall allow-list (`SECCOMP_RET_KILL_PROCESS` on any
syscall off the list). Applied **before** the tokio runtime is built so every
worker inherits both the Landlock domain and the seccomp filter.

**Egress control is layered — Landlock net is a coarse backstop, not the primary
gate.** Landlock's `AccessNet::ConnectTcp` restricts by destination **port**, not
host/address, so on an allowed port (e.g. the Gateway's) a compromised process
could in principle `connect` to a *different* host on that same port. The Agent's
*fine-grained* egress control is at the application layer and predates this
session: the splice target is loopback-validated and never taken from the wire
(`config::parse_splice_addr`), a dial-back endpoint must be exactly the arriving
control channel's configured Gateway (`gateway::client` affinity check +
`configured_endpoint`, F-connect-1), and every leg is pinned-CA TLS 1.3 (a wrong
host fails the handshake). Landlock net narrows the *port* surface as
defence-in-depth on top of those; it is not relied on as the sole egress control.

Two residuals are accepted with justification; both fail **safe**, not open. Two
deliberate design decisions are recorded below them.

## Design decision — seccomp default action: KillProcess (Agent) vs EPERM (Gateway)
The Agent's seccomp mismatch (default) action is **`SECCOMP_RET_KILL_PROCESS`**: a
syscall off the allow-list terminates the process. This diverges — deliberately —
from the Gateway, which uses **EPERM-default + a KILL-denylist** for the
exploitation set. The rationale is per-threat-model, not an inconsistency:
- The **Agent** has a small, predictable syscall surface (dial-out WS + dial-back +
  loopback splice + enroll/renew — no russh/recorder/WORM/HA), so a *complete*
  allow-list is achievable; it is node-resident and more exposed, so the tighter
  containment of a hard kill is worth more.
- The **Gateway** is a long-lived Tier-0 daemon holding many concurrent live
  plaintext SSH sessions; a single un-harvested syscall (a tokio/ring/glibc bump)
  under KILL-default would SIGSYS-drop *every* live session — an availability
  incident and fail-open pressure — so EPERM-default is the safer choice there.

Because KILL-default is fail-deadly on a missed syscall, allow-list **completeness**
is load-bearing and is proven, not assumed:
- `tests/seccomp_kill.rs` — a forked child under the real filter is KILLED with
  SIGSYS on a disallowed syscall (`ptrace`) and runs an allowed one (`getpid`)
  cleanly: enforcement is real, not silently permissive.
- Docker `tests/splice_e2e.rs` — the widest agent-path exercise (enroll + control
  channel + dial-back + splice of a full cert-authenticated SSH session, with the
  OTLP exporter enabled) completes under the hardened binary, so the tonic/mTLS,
  WebSocket, rustls/ring, tokio, file-I/O and networking syscalls are all covered.
  The Agent splices opaque ciphertext, so shell/exec/sftp share one code path and
  one syscall surface.
The allow-list is in `src/hardening/imp.rs` (`allowed_syscalls`); the
kernel-ebpf-specialist review independently validates completeness + the choice.

## Design decision — Landlock whole-process coverage (no TSYNC)
`landlock_restrict_self` has no TSYNC: it confines only the calling thread and
threads spawned *after* it. The Agent therefore applies hardening while still
single-threaded (before the tokio runtime is built — `main` drops `#[tokio::main]`),
so **every** worker (including those running the loopback splice) inherits the
Landlock domain. This is verified by the splice_e2e above: the workers carrying the
real SSH session are confined and the session still completes. seccomp is applied
with TSYNC (`apply_filter_all_threads`) as belt-and-braces across any pre-existing
thread.

## Residual 1 — Landlock unavailable / partial on old kernels (documented degrade)
Landlock needs Linux ≥5.13 (filesystem) / ≥6.7 (network egress, ABI v4). On a
kernel without it, the `landlock` crate's best-effort mode reports `NotEnforced`
and hardening logs a loud `Landlock is UNAVAILABLE ... ACCEPTED-RISK` (or a
`PARTIALLY enforced` notice when only the network ABI is missing) and continues —
seccomp and the loopback-only splice validation still hold. This is the SESSION's
sanctioned exception (a kernel-capability gap is a documented degrade, never a
silent one), not a fail-open: the process still refuses to run non-hardened at the
**seccomp** layer (a seccomp install failure aborts). Deploy on a Landlock-capable
kernel + the container `securityContext` (`deploy/`) for full confinement.

**Opt-in fail-closed for regulated deploys.** `--require-full-landlock` aborts
startup unless `report.landlock == FullyEnforced`, so a deploy that must not run
with degraded filesystem/egress confinement can turn the default Accepted-Risk
degrade into a hard failure. The default stays BestEffort (the sanctioned
kernel-gap degrade) so single-instance / older-kernel deploys keep working.

## Residual 2 — OTLP exporter threads predate the Landlock domain
When (and only when) `OTEL_EXPORTER_OTLP_ENDPOINT` is set, the OTLP exporter runs
on a small dedicated tokio runtime built in `telemetry::init`, which runs **before**
`hardening::apply` (so startup logs — including the root refusal and the hardening
report — are captured by the subscriber). Those export threads are therefore
covered by **seccomp** (installed with TSYNC across all existing threads) but **not**
by the Landlock domain (Landlock has no TSYNC and only covers the calling thread +
threads spawned after `restrict_self`). Impact is minimal: the exporter is
first-party code whose only egress is the operator-configured collector (whose port
is in the seccomp-permitted networking set), and it performs no filesystem writes.
The alternative — initialising OTLP after hardening — would lose the startup logs
(and the exporter is off by default, so the common path has no such threads at all).
Accepted.

## Residual 3 — Landlock network egress is TCP-only + port-scoped (not host/IP)
The in-process Landlock egress ruleset is a **coarse** control by construction:
- it filters **TCP `connect` by destination port only** — it does NOT scope by
  host/IP, so on an allow-listed port a compromised process could `connect` to a
  different host on that port;
- it has **no UDP support** — outbound UDP is not confined by Landlock at all;
- it needs **Linux ≥6.7 (ABI v4)**; on the common <6.7 LTS kernels (5.15 / 6.1 /
  6.6, typical EKS/GKE) the network handling silently downgrades to
  `PartiallyEnforced` (filesystem still enforced) — a soft degrade of the *egress*
  control specifically.

These are inherent to Landlock, not a bug. They are mitigated in depth, not relied
on alone:
- **Application layer (primary, kernel-version-independent):** the splice target is
  loopback-validated and never taken from the wire (`config::parse_splice_addr`); a
  dial-back must be exactly the arriving control channel's configured Gateway
  (`gateway::client` affinity, F-connect-1); every leg is pinned-CA TLS 1.3 (a wrong
  host fails the handshake). This is what actually stops "the Agent as a pivot".
- **NetworkPolicy (`deploy/kubernetes/agent-networkpolicy.yaml`) — LOAD-BEARING,
  not just defence-in-depth:** it is the control that actually enforces host/IP + UDP
  scoping at the CNI, which Landlock cannot do at all (Landlock is TCP-connect,
  port-only). Agent → CP + Gateways + DNS only; ingress denied. A deploy relying on
  network-level egress confinement MUST ship it — it is not optional colour on the
  DaemonSet.
- **`--require-full-landlock`:** turns the <6.7 egress degrade into a hard abort for
  deploys that require it.
Landlock net remains valuable as an in-process port backstop even against a
Landlock-unaware compromise; the prose (`hardening.rs`, README, deploy docs) states
the confinement accurately (TCP-connect-port on ≥6.7), not as absolute pivot-proofing.

## Note — aarch64 build proven at CI (S24); runtime allow-list still x86_64-run
The seccomp allow-list is shared across x86_64 + aarch64 (the `ioctl`/FIONREAD fix
lives in the common list). **S24 adds a build-level arm64 proof to CI**
(`cargo check --target aarch64-unknown-linux-gnu`, ci.yml — cross linker +
`libc6-dev-arm64-cross`), closing the "does it even compile on arm64" gap (carry-
forward B4). Locally reproduced green on this x86_64 box via the same cross target.
The remaining, deliberately-scoped caveat: glibc's *syscall* footprint differs by
arch (e.g. `arch_prctl` is x86_64-only; aarch64 lacks the legacy non-`*at` forms), so
the seccomp KILL-default's runtime *completeness* on arm64 is still exercised only on
x86_64. When aarch64 images ship, the hardened Docker E2E + `seccomp_kill` / DNS
guards MUST run on an aarch64 runner before relying on KILL-default there.

## Verification
- `tests/seccomp_kill.rs` — a disallowed syscall is SIGSYS-killed; an allowed one
  runs; **`ioctl(FIONREAD)` is allowed but other ioctls are killed** (arg-restriction
  real); and **glibc hostname resolution survives the filter** (F1/F3 regression
  guards — they FAIL before the ioctl fix, PASS after).
- `tests/hardening_e2e.rs` — hardening is applied+logged, the Agent **survives the
  filter to the join path** (asserts NOT signal-killed + a post-filter marker, so an
  incomplete allow-list on the startup path is caught — F2), and it fails closed on a
  missing data-dir.
- Docker `tests/splice_e2e.rs` — a full cert-authenticated SSH session **+ an SFTP
  transfer**, with the OTLP exporter enabled, complete under the hardened binary (the
  data path is not regressed).
- `src/hardening.rs` unit tests — the egress allow-list covers CP + every Gateway +
  the loopback splice + OTLP (+ TCP:53 only when an endpoint is a hostname), and
  nothing else.
