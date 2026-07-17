# SessionLayer Agent — deployment & Tier-0 posture

The Agent is the per-node **outbound** connector: it dials out to failure-domain
diverse Gateways and, on demand, dial-backs and splices a connection to the node's
own `sshd` on loopback. A node therefore needs **no inbound reachability**.

## Tier-0 runtime hardening (Part A / NFR-5 / Design §15)

Hardening is applied in **two layers** — the process enforces it itself
(fail-closed), and the container/orchestrator config makes it structural:

| Control | In-process (fail-closed) | Container / k8s |
|---|---|---|
| **Non-root** | `privilege::require_non_root()` refuses `euid==0` before any credential work | `runAsNonRoot`, `runAsUser: 65532`, distroless `USER 65532` |
| **Coredump/ptrace** | `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0` (mTLS key + join token never hit a coredump) | — |
| **Filesystem** | Landlock: writes confined to the data-dir; CA + join files read-only | `readOnlyRootFilesystem: true` + a writable `emptyDir` at the data-dir |
| **Egress** | Landlock network: TCP `connect` allowed only to the CP, each Gateway, the loopback splice, and (if set) the OTLP collector | a NetworkPolicy / CNI egress rule to the same set |
| **Syscalls** | seccomp allow-list scoped to the runtime + TLS + WSS + dial-back + splice; anything else **kills the process** | `seccompProfile: RuntimeDefault` (a floor under the app's allow-list) |
| **No new privileges** | set by the Landlock + seccomp install | `allowPrivilegeEscalation: false`, `capabilities: drop [ALL]` |

**Fail-closed.** A hardening step that *can* apply but fails aborts the process
(it never runs unhardened). The **one** documented exception is a kernel that
lacks Landlock (or its network ABI, Linux ≥6.7): a loud, explicit **Accepted-Risk
degrade** — seccomp and the loopback-only splice validation still hold. The degrade
is logged (`Landlock is UNAVAILABLE ... ACCEPTED-RISK`); it is never silent.

Because Landlock covers the calling thread and threads spawned *after* it (there is
no TSYNC for Landlock), the binary applies hardening **before it builds the tokio
runtime**, so every worker inherits the Landlock domain and the seccomp filter.

## Read-only rootfs

The container runs with `readOnlyRootFilesystem: true`. The only writable path is
the credential **data-dir** (`--data-dir`, default `/var/lib/sessionlayer-agent`),
mounted as a writable volume — which matches the in-process Landlock RW rule. The
Agent writes nowhere else (it logs to stdout/stderr, holds the single-writer lock
and `identity.json` in the data-dir, and reads the bootstrap CA + join material
read-only).

See [`kubernetes/agent-daemonset.yaml`](kubernetes/agent-daemonset.yaml) for a
reference DaemonSet, and, for a plain Docker host, run with `--read-only` plus a
writable volume at the data-dir:

```
docker run --read-only \
  --user 65532:65532 \
  --security-opt no-new-privileges \
  -v sl-agent-data:/var/lib/sessionlayer-agent \
  ghcr.io/sessionlayer/agent:latest run ...
```

## OpenTelemetry (Part C / §14, OTEL-CONTRACT §2.2)

The Agent mints its own spans — `agent.enroll`, `agent.renew`, `agent.dial_back`,
`agent.splice` — and correlates them to the platform trace by stamping the
`sessionlayer.session_id` it already holds (attribute correlation only; it does
**not** touch the frozen wire or the SLDB1 token). The OTLP exporter is **off by
default** and enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; export rides
tonic on the ring TLS backend. Spans carry IDs/enums/durations only — never SSH
plaintext, keys, tokens, or recording bytes. When the exporter is enabled, its
collector port is automatically added to the Landlock egress allow-list.
