# sessionlayer-agent

Deploys the SessionLayer Agent as a DaemonSet, one per node, with a
ServiceAccount, NetworkPolicy and optional PodDisruptionBudget. The chart is a
translation of `deploy/kubernetes/agent-daemonset.yaml` and
`deploy/kubernetes/agent-networkpolicy.yaml`; those manifests remain the
reference for a deployment that does not use Helm. For a bare-metal or VM node,
`deploy/systemd/` is the deployment model, not this chart.

The Agent takes its configuration as command-line flags, so the chart builds an
argument list rather than a config file. It creates no Secret: the join
credential is either a Secret you name or a token the kubelet projects.

## Install

```bash
kubectl -n sessionlayer create configmap sessionlayer-bootstrap-ca --from-file=ca.pem=cp-ca.pem

helm install ag deploy/helm/sessionlayer-agent \
  --namespace sessionlayer \
  --set trustAnchor.existingConfigMap=sessionlayer-bootstrap-ca \
  --set hostNetwork=true \
  --set 'gateways[0].endpoint=wss://gw-a.example.com:9444' \
  --set 'gateways[0].serverName=gw-a' \
  --set image.digest=sha256:<the digest you verified>
```

Replace `gw-a.example.com` with your Gateway's agent-transport address, `gw-a`
with the name that Gateway enrolled under, and `<the digest you verified>` with
the digest `cosign verify` reported for `ghcr.io/sessionlayer/agent`.

`ci/production-values.yaml` is a complete values file, kept as what the chart is
linted and schema-checked against.

## hostNetwork and the splice

Each session arrives over the Agent's outbound channel and is spliced to the
node's own `sshd`. The Agent refuses any splice address that is not loopback,
so it cannot be pointed at the node by IP. A pod's loopback is not the node's,
which leaves one arrangement that works for a DaemonSet fronting node `sshd`:

```yaml
hostNetwork: true
```

`dnsPolicy` then defaults to `ClusterFirstWithHostNet`, without which a
host-network pod resolves through the node's resolver and never sees the
cluster's Service names. Weigh this against sharing the node's network
namespace. With `hostNetwork` off, the install notes say plainly that sessions
to this node reach nothing.

## Join methods

| `join.method` | What the Agent presents | What you set |
|---|---|---|
| `oidc` | A ServiceAccount token the kubelet projects, scoped to `join.audience` and rotated | `join.audience`, matching `sessionlayer.agent-join.oidc.audience` on the Control Plane |
| `token` | A single-use join token | `join.existingSecret`, `join.tokenKey` |
| `mtls` | An operator certificate and key | `join.existingSecret`, `join.certKey`, `join.keyKey` |

`oidc` is the default because it is the only one where no long-lived credential
is stored: the kubelet mints a short-lived, audience-scoped token, and the
Control Plane refuses one minted for anything else.

`serviceAccount.automountServiceAccountToken` stays `false` on every method,
including `oidc`. A projected `serviceAccountToken` volume does not depend on
it, and the Agent never calls the Kubernetes API, so mounting the default token
would add an API credential nothing uses.

## Rendering refuses these

| Condition | Why |
|---|---|
| No `trustAnchor.existingConfigMap` | The Agent pins the Control Plane's CA and performs no trust-on-first-use. |
| `join.method` of `token` or `mtls` with no `join.existingSecret` | The chart never creates a credential. |
| Empty `gateways` | An Agent with no Gateway endpoint joins, holds an identity and serves no session. It looks healthy and reaches nothing. |
| A `gateways` entry without `serverName` | The binary's fallback is a development name, so an unset value fails the TLS handshake with nothing that names the cause. |
| `failureDomain` on some entries but not all | The binary aligns the endpoint flags by position and refuses a partial list. |
| `minControlChannels` above the number of `gateways` | The Agent could never reach its own floor and would never become healthy. |
| `terminationGracePeriodSeconds` below `drainDeadlineSecs` | See below. |

## Termination

`terminationGracePeriodSeconds` defaults to 60, above Kubernetes' 30. The
overrun is not a slow drain: a SIGKILL landing in the credential-persist window
leaves a generation the Control Plane reads as a clone and auto-locks, so a
routine node drain becomes a security page and a manual re-provision. Sixty
seconds covers the drain deadline and the in-flight renewal underneath it.

## Values

### Image

| Key | Default | Notes |
|---|---|---|
| `image.repository` | `ghcr.io/sessionlayer/agent` | |
| `image.tag` | `""` | Empty resolves to the chart's `appVersion`. |
| `image.digest` | `""` | Wins over `tag`. Pin this in production. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |

### Identity

| Key | Default | Notes |
|---|---|---|
| `controlPlane.endpoint` | `""` | Empty derives `https://controlplane.<namespace>.svc:9443`. |
| `controlPlane.serverName` | `""` | The name the Control Plane's certificate carries. Empty derives `controlplane.<namespace>.svc`. |
| `trustAnchor.existingConfigMap` | `""` | ConfigMap holding the Control Plane's CA certificate. |
| `trustAnchor.key` | `ca.pem` | |
| `join.method` | `oidc` | |
| `join.audience` | `sessionlayer-controlplane` | |
| `join.expirationSeconds` | `3600` | |
| `join.existingSecret` | `""` | |

### Session path

| Key | Default | Notes |
|---|---|---|
| `gateways` | `[]` | Each entry takes `endpoint`, `serverName` and optionally `failureDomain`. |
| `minControlChannels` | `1` | The Agent tolerates a Gateway being unreachable only while this many channels remain up. Raising it above 1 is what makes a single Gateway outage a non-event. |
| `spliceAddr` | `127.0.0.1:22` | Loopback only. |
| `maxConcurrentSplices` | `32` | |
| `drainDeadlineSecs` | `30` | |
| `dataDir` | `/var/lib/sessionlayer-agent` | The only writable path, matching the in-process Landlock rule. |
| `hostNetwork` | `false` | See above. |
| `dnsPolicy` | `""` | Empty derives `ClusterFirstWithHostNet` when `hostNetwork` is on. |
| `extraArgs` | `[]` | |

### Runtime and posture

| Key | Default | Notes |
|---|---|---|
| `resources.requests` | `50m` / `64Mi` | Requests only. Without them the Agent lands in BestEffort and is the first thing the kubelet evicts under node memory pressure, which is when it is most needed: an evicted Agent makes its node unreachable through the platform. A memory limit would turn a burst into an OOMKill in the same window. |
| `requireFullLandlock` | `false` | On means the process refuses to start where the kernel cannot fully enforce Landlock, rather than degrading to the container's read-only root filesystem and dropped capabilities alone. |
| `podSecurityContext` | `runAsNonRoot`, uid/gid/fsGroup `65532`, `RuntimeDefault` | Host-key access on a node is root-only, and a root Agent could read the node's host key and impersonate it. |
| `containerSecurityContext` | `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` | |
| `terminationGracePeriodSeconds` | `60` | |
| `updateStrategy` | `RollingUpdate`, `maxUnavailable: 1` | |
| `podDisruptionBudget.enabled` | `false` | A node drain ignores DaemonSet pods, so a budget here constrains only callers that go through the eviction API, such as an autoscaler or a descheduler. |

The manifest's structural half and the binary's own half compose: the pod runs
non-root with a read-only root filesystem, no privilege escalation, all
capabilities dropped and `seccompProfile: RuntimeDefault` as the kernel floor,
while the binary installs its own tighter seccomp allow-list, Landlock rules
and coredump suppression, and fails closed.

### NetworkPolicy

| Key | Default | Notes |
|---|---|---|
| `networkPolicy.enabled` | `true` | Ingress denied entirely. A node running an Agent needs no inbound reachability. |
| `networkPolicy.controlPlanePodSelector` | `app.kubernetes.io/name: sessionlayer-controlplane` | |
| `networkPolicy.controlPlaneGrpcPort` | `9443` | Match the port inside `controlPlane.endpoint`. |
| `networkPolicy.gatewayPodSelector` | `app.kubernetes.io/name: sessionlayer-gateway` | |
| `networkPolicy.gatewayPort` | `9444` | The Gateway's agent transport. |
| `networkPolicy.gatewayCidrs` | `[]` | Gateways outside this cluster, which no pod selector can express. |

The network layer enforces host and UDP scoping, which the in-process Landlock
ruleset cannot: it filters TCP `connect` by port only, has no UDP support, and
needs a recent kernel. The two are defence in depth. The loopback splice is
in-pod traffic and is not subject to NetworkPolicy.

### Scheduling and extension

`podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`,
`priorityClassName`, `extraEnv`, `extraVolumes` and `extraVolumeMounts` pass
through unchanged.

## What this chart is not

It is validated statically: `helm lint`, `helm template`, `values.schema.json`,
`kubeconform -strict` against the Kubernetes schemas, and the rendered argument
list parsed by the Agent binary itself. It has not been installed into a live
cluster as part of this repository's testing.

## See also

- `deploy/kubernetes/` for the plain manifests this chart translates
- `deploy/systemd/` for the bare-metal and VM node deployment
- [Agent installation](https://github.com/SessionLayer/Documentation/blob/main/docs/installation/agent.md)
- [Agent configuration](https://github.com/SessionLayer/Documentation/blob/main/docs/reference/config-agent.md)
