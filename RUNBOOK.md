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

## Observability (S12 limits)
No metrics/health surface yet (S13). Until then: alert on the exit codes above and
on the `SECURITY` / `REPAIR-NEEDED` log lines. Time-to-cert-expiry, renewal
attempt/failure counters, and the current generation become metrics with the S13
transport (tracked as Accepted-Risk finding F-observability-1).
