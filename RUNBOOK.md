# SessionLayer Agent — Runbook (S12: join + renewable mTLS identity)

The Agent is the per-node **outbound** connector. In S12 its only job is to join
the platform and maintain a renewable mTLS X.509 identity (Design §8, FR-JOIN-*).
It has **no inbound listener, no metrics, and no health endpoint yet** (those land
with the S13 data plane). The only orchestration signals today are the **process
exit status** and the **structured logs** — alert on both.

## Exit codes
| Code | Meaning | Response |
|------|---------|----------|
| 0 | Clean shutdown (SIGTERM / SIGINT), or `--once` completed | none |
| 1 | Startup failure (config / enroll / persist / startup-renew terminal) | check logs; usually transient CP or disk — the orchestrator may restart |
| 3 | **Generation mismatch** — possible clone; CP auto-locked (FR-JOIN-5) | SECURITY incident (below). Do NOT auto-restart into a loop; re-provision |
| 4 | **Repair-needed** — identity locked / unknown-rotated cert / stale generation | re-provision via the join-token API |

Set the orchestrator so codes 3 and 4 **page** and do not silently restart
(e.g. k8s `restartPolicy: OnFailure` will loop — prefer alerting on the exit code;
systemd: `Restart=on-failure` with `RestartPreventExitStatus=3 4`).

## Alert: log `SECURITY: generation mismatch on renewal ... auto-locked` (exit 3)
Cause: two live copies of the credential forked the generation counter (a clone),
OR a crash landed in the residual persist window (see "Self-lock window" below).
Both auto-lock at the CP with **no auto-clear** (FR-JOIN-5).
Action:
1. Determine clone vs. crash: is there a second Agent process / a copy of the
   data-dir (`/var/lib/sessionlayer-agent/identity.json`) anywhere?
2. Never auto-clear the lock. Treat a genuine clone as an incident.
3. Re-provision the node: `POST /v1/join-tokens` (FR-JOIN-2, automatable), deploy
   the token, wipe the node data-dir, restart the Agent to re-enroll (generation 0).

## Alert: log `REPAIR-NEEDED: renewal rejected ...` (exit 4)
Cause: an incident lock on the node/identity, an unknown/rotated client cert, or
the CP advanced past this credential's generation.
Action: resolve the incident lock (CP side) if intentional; otherwise re-provision
as above. Renewal will **not** self-heal — the old credential is kept until it
expires but cannot be renewed.

## Self-lock window (accepted residual)
Persist-before-adopt makes the Agent-local crash between persist and adopt safe,
but it cannot close the gap between the CP *committing* generation N+1 and the
Agent *persisting* it. A crash in that gap leaves the Agent at N while the CP is
at N+1; the next renewal declares N, the CP sees a mismatch and auto-locks
(exit 4/3). This is **fail-closed, never silent corruption**. Recovery is
re-provision (above). The window is only the RPC-response/persist gap.

## Symptom: repeated transient renewal warnings, never succeeding (process stays up)
Likely a **CA-rotation lockout** or the CP is unreachable.
- The Agent pins exactly the CA chain returned by its last successful renewal and
  verifies the CP server cert against it. If the CP rotates its internal mTLS CA
  and switches its server cert to the new CA **before** this Agent has renewed
  onto it (or the Agent was offline past the overlap), `connect_mtls` fails and the
  Agent retries (transient) until the cert expires, then needs re-provision.
- Operational requirement: CP CA rotation MUST return an overlapping chain and
  keep the old issuer valid for server certs until the whole fleet has renewed.
- Check: does the CP server cert chain to the anchors this Agent last stored?

## Symptom: the CP sees a renewal storm from one node
A short cert TTL combined with a large clock-skew backdate (FR-BOOT-4), or a CP
clock ahead of the node, can make every issued cert born past its renew trigger.
The post-renewal floor (`RENEW_MIN_INTERVAL`, ~60s) bounds this to ≈1 renewal/min,
but fix the root cause: correct the TTL/backdate ratio and/or NTP sync.

## Deployment preconditions
- **Non-root** (FR-CONN-6): the container runs `USER 65532`; `require_non_root()`
  also refuses to start at euid 0. A root Agent could read the node host key and
  impersonate the node.
- **Data-dir must be node-local.** The single-writer lock is `flock`, which is a
  no-op / unreliable on some network filesystems — never put
  `/var/lib/sessionlayer-agent` on NFS. Owned by the agent user; the manifest is
  written `0600`.
- **Shutdown grace.** A SIGTERM that lands during an in-flight renewal waits for it
  to finish (bounded by `connect_timeout + rpc_timeout`, default ~40s) so the
  persist completes — set `terminationGracePeriodSeconds` (k8s) / `TimeoutStopSec`
  (systemd) to at least that plus a buffer. A mid-renew SIGKILL is crash-safe (the
  persist is an atomic temp+rename) but not graceful.
- **NTP-synced clocks** are assumed (FR-BOOT-4); certs are backdated for skew and
  the Agent expires credentials conservatively.

## Observability — logs, exit codes, OpenTelemetry (S21)
The Agent is outbound-only, so it exposes **no inbound metrics/health endpoint** by
design (a scrape port would contradict "no inbound reachability"). Its signals are:
- the **exit codes** above and the `SECURITY` / `REPAIR-NEEDED` log lines (alert on
  both);
- **OpenTelemetry spans** (S21): `agent.enroll`, `agent.renew`, `agent.dial_back`,
  `agent.splice`, each stamped with `sessionlayer.session_id` so a trace pivots to
  the CP audit chain + recording by the same id. Export is **off** unless
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set (OTLP/gRPC, ring TLS); `OTEL_SERVICE_NAME`
  defaults to `sessionlayer-agent`. Spans carry IDs/enums/durations only — never
  tokens/keys/plaintext. When export is on, the collector's port is auto-added to
  the Landlock egress allow-list.

## Tier-0 runtime hardening (S21, Part A) — troubleshooting
The Agent applies seccomp + Landlock + coredump hygiene at startup, **fail-closed**,
and logs `Tier-0 runtime hardening applied` once done (with the Landlock status,
seccomp syscall count, and the egress port allow-list). See `deploy/README.md`.
- **Agent killed with signal `SIGSYS` (or the container reports a seccomp kill):** a
  syscall outside the allow-list was attempted — either a genuine anomaly, or (after
  a toolchain/dep bump) a newly-needed syscall. The allow-list is in
  `src/hardening/imp.rs` (`allowed_syscalls`); the Docker `splice_e2e` validates the
  full data path against it.
- **Log `Landlock is UNAVAILABLE ... ACCEPTED-RISK` / `PARTIALLY enforced`:** the
  kernel lacks Landlock (needs Linux ≥5.13; network egress needs ≥6.7). Documented
  degrade — seccomp + the loopback-only splice validation still hold; deploy on a
  newer kernel + the container `securityContext` for full confinement.
- **Startup aborts with a hardening error (e.g. `data-dir ... must exist`):** a path
  hardening must confine is missing/unwritable, or seccomp could not install. This is
  fail-closed — the Agent will not run unhardened. Fix the data-dir / permissions.

---

# S14: outbound connectivity (control channel + dial-back splice)

The Agent now dials **out** to a Gateway over a mutually-authenticated WebSocket
control channel, receives dial-back requests, and splices each session's byte
stream to the node's own `sshd` on loopback. A node still needs **zero inbound
reachability**. The normative protocol is `contracts/wire/agent-gateway-v1.md`.

Enable the role by passing `--gateway-endpoint wss://GW:PORT`. With no
`--gateway-endpoint` the Agent runs **identity-only** (the S12 posture), which
stays supported.

## Configuration (clap flags; no config file)
| flag | default | notes |
|------|---------|-------|
| `--gateway-endpoint` (repeatable) | none | `wss://` only; `ws://` is refused. Omit ⇒ identity-only. **Pass it ≥2 times** for HA (S15): the Agent holds one control channel per endpoint concurrently and does **not** mesh. |
| `--gateway-failure-domain` (repeatable) | endpoint host | failure-domain label (rack / AZ) for the corresponding `--gateway-endpoint`, **zipped positionally**. Provide one per endpoint, or none (each then defaults to its host). Whenever ≥2 endpoints are configured they must span ≥2 domains. |
| `--min-control-channels` | 1 | degrade-warn threshold: the Agent warns when live channels drop below this. **Default 1 = single-instance** (only the all-lost signal). An HA operator sets `2+`; then 2→1 warns and 1→0 is the hard "node unreachable". |
| `--gateway-server-name` (repeatable) | `gateway` | the enrolled name whose serverAuth SAN the Agent verifies for the corresponding `--gateway-endpoint`, **zipped positionally**. Distinct real Gateways carry **distinct** SANs, so give one per endpoint; or exactly one to apply to all; or none to default each to `gateway`. Verified against the internal CA — dial an address, verify a name. |
| `--splice-addr` | `127.0.0.1:22` | the node's local sshd. **Loopback-validated at startup; the Agent refuses to boot otherwise** (see below). |
| `--max-concurrent-splices` | 32 | a dial-back beyond the cap is `REFUSED`, never queued. Shared across all control channels. |
| `--drain-deadline-secs` | 30 | how long live splices may finish after the Agent stops taking new work. |

Reconnect backoff is 1s→30s exponential with ±50% jitter, **per channel**, indefinitely.

## S15: ≥2 failure-domain-diverse control channels (FR-HA-6)
The Agent dials **out** to two or more Gateways in **distinct failure domains** and
holds a control channel to each simultaneously. It does **not** mesh — the channels
are independent dial-outs. This is what makes a node reachable when one Gateway (or a
whole rack/AZ) dies.

- **Startup validation, fail-closed.** Whenever ≥2 `--gateway-endpoint`s are given,
  the Agent refuses to boot unless they span ≥2 distinct failure domains (a duplicate
  endpoint, or two channels in one domain, is refused — it is not real HA). Two
  Gateways on the *same host* are one domain by default; label them or use different
  hosts. This diversity check is independent of `--min-control-channels`.
- **Single-instance mode (default).** One `--gateway-endpoint` and the default
  `--min-control-channels 1`: the Agent runs against one Gateway with no diversity
  requirement (the S14 posture). An HA operator passes ≥2 endpoints and sets
  `--min-control-channels 2` so a drop to one channel warns.
- **Per-channel dial-back affinity.** A `DIAL_BACK_REQUEST` arriving on the channel
  to gw-A may **only** dial back to gw-A. In the HA routing model the node's *owning*
  Gateway signals over its own channel, so the dial-back endpoint always equals the
  arriving channel. A Gateway that named a *different* Gateway's endpoint is refused
  before anything is dialled — a compromised gw-A cannot task the Agent to open a
  connection to gw-B.

## Alert: log `ALL Gateway control channels are down — this node is UNREACHABLE`
The node has lost **every** Gateway control channel (all diverse domains down at
once — a broad outage, or a misconfiguration hitting all of them). This is the
documented **degrade** (FR-HA-6): the platform does **not** build a bespoke fallback,
because the whole point of ≥2 diverse channels is that all-lost is rare. While in
this state new sessions get the generic §7.1 "node offline / unreachable" outcome;
**recover the node with out-of-band tooling** (console / cloud-provider serial / a
break-glass path that does not depend on SessionLayer). The Agent keeps reconnecting
to every endpoint with backoff+jitter and logs `node is reachable` when the first
channel comes back — no restart is needed once a Gateway is reachable again.

## The confused-deputy / SSRF defence (why `--splice-addr` is loopback-only)
`DIAL_BACK_REQUEST` deliberately carries **no splice target**. The Agent splices
only to its own locally-configured `--splice-addr`, which is validated to be a
loopback address (`127.0.0.0/8` or `::1`) at startup — a routable address, the
wildcard `0.0.0.0`, or a **hostname** (which would hand the destination to DNS) all
**refuse to start**. So no Gateway — however compromised — can redirect the splice
or use the Agent as a network pivot into the node's subnet. This is structural, not
a runtime check on hostile input.

## Non-root holds over the splice (FR-CONN-6 / Design §9.3)
The Agent runs non-root (`USER 65532`; `require_non_root()` refuses euid 0) and
therefore **cannot read the node's host key** (`/etc/ssh/ssh_host_*`, root-only).
Spoofing the node's host identity thus requires **node-root compromise**, not
merely a compromised Agent — the agent model *raises* that bar. The Gateway's
no-TOFU host verification is what would catch a splice to an impostor; the Agent is
not a party to it and cannot weaken it. The Docker E2E asserts the Agent account
cannot read the host key.

## Node-local sshd second trail (FR-AUD-4) — and why the Agent does NOT forward it
In the agent model the node's **own** `sshd` log is a **tamper-independent** second
record of every session. The Gateway's inner-leg certificate carries
`key_id = session_id + identity`; a node running `LogLevel VERBOSE` (set in the
canonical `testing/docker/sshd/sshd_config`, and required on real nodes) logs that
key-id on every accepted certificate. The platform audit trail and this node-local
trail cross-correlate on `session_id`.

**Log forwarding by the Agent is deliberately OFF.** The entire value of this
second trail is that it does **not** depend on the Agent: the Agent neither writes
it nor can suppress it, so it remains trustworthy even if the Agent is compromised.
Routing it *through* the Agent would collapse that independence. Ship the node's
sshd log to your SIEM by the **node's** normal log pipeline (journald/syslog →
collector), never via the Agent. Correlate platform ↔ node on `session_id`.

## Availability: a terminal identity outcome does NOT kill live sessions
The renew-ahead loop runs **concurrently** with the control channel (spawned, not
awaited). A terminal identity outcome — clone (exit 3) or repair-needed (exit 4) —
stops the Agent taking **new** dial-backs and closes the control channel, but a
**live spliced session is a real user mid-work**: it is drained up to
`--drain-deadline-secs`, not torn down. The S12 exit codes are unchanged. If you see
`terminal identity outcome — refusing new sessions and draining live ones`, the
process will exit with code 3/4 once live sessions end or the drain deadline passes;
handle it exactly as the S12 clone/repair incident above.

## Symptom: the control channel reconnects in a loop (node flaps offline)
Each reconnect re-runs the **full** TLS + mTLS + preface — there is no resumption.
Common causes: (a) the Gateway's serverAuth cert does not chain to the CA the Agent
holds, or its SAN ≠ that endpoint's `--gateway-server-name` (TLS fails closed — verify
properly or not at all; with ≥2 Gateways make sure each endpoint's server name is the
one that Gateway is enrolled under); (b) a `VERSION_REJECT` (no common protocol
version — the Agent will
**never** downgrade, FR-HA-9); (c) a `HELLO_ACK` proposing a heartbeat outside
1–300s or `max_frame_bytes` outside 4 KiB–1 MiB (refused, fail closed). The log
line names which. A node whose Agent is not connected is simply **offline** (§7.1),
reported post-authorization exactly like an unreachable agentless node.

## Symptom: dial-backs fast-fail with `LOCAL_DIAL_FAILED`
The node's own `sshd` is down / not listening on `--splice-addr`. The Agent reports
this immediately (it does not wait out the Gateway's dial-back deadline); the user
sees the generic §7.1 "target node is offline / unreachable". Check the node sshd.
