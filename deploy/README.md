# Agent deployment assets

Container image, Kubernetes DaemonSet manifest, a hardened systemd unit for the
bare-metal and VM model, and Prometheus alert rules for the Agent's Tier-0
hardening and exit-code alerting. The systemd unit sets
`RestartPreventExitStatus=3 4`, which Kubernetes has no equivalent for — a
DaemonSet pod restarts on any exit code, so there the alert rules are what stop a
terminal identity outcome from becoming restart noise. See
`docs/installation/agent.md` in the
[Documentation](https://github.com/SessionLayer/Documentation) repo for the
hardening model, the read-only rootfs posture, and the exit-code contract these
assets implement.

## Container image

`Dockerfile` compiles the release binary with a digest-pinned Rust toolchain and
copies it into `gcr.io/distroless/cc-debian12:nonroot`, which carries glibc,
libgcc and the CA roots and nothing else. The aarch64 binary is cross-compiled
from the build platform, so neither architecture is built under emulation.

| Property | Value |
|---|---|
| Image | `ghcr.io/sessionlayer/agent:v0.0.2` |
| Platforms | `linux/amd64`, `linux/arm64` |
| User | `65532:65532`, numeric so `runAsNonRoot` needs no `/etc/passwd` lookup |
| Writable path | `/var/lib/sessionlayer-agent`, declared as a `VOLUME` and owned by 65532 |
| Shell | none in the final layer |
| Ports | none; the Agent dials out |

Node host keys are root-only, so a root Agent that is compromised can read the
host key and impersonate the node. The image therefore has no `USER root` in its
final stage and no shell to regain one, and the binary refuses to start at
euid 0 regardless of how it is launched.

Build from the repository root, not from `deploy/`:

```console
$ docker build -f deploy/Dockerfile -t sessionlayer/agent:dev .
$ docker run --rm sessionlayer/agent:dev --version
sessionlayer-agent 0.0.1
component:      SessionLayer Agent
wire-protocol:  1.0 - 1.0  (N-1 window; contracts/wire/agent-gateway-v1.md)
grpc-contract:  sessionlayer.controlplane.v1  (vendored common.proto + agent.proto)
```

Log output carries ANSI colour escapes whether or not stderr is a terminal, and
`docker compose logs --no-color` strips only Compose's own service prefix. An
escape sits between every field name and its `=`, so a grep for `node_name=` over
a raw `docker logs` matches nothing and reads as if the event never happened.
Strip the escapes first:

```bash
docker logs sessionlayer-agent 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep 'node_name='
```

The release workflow publishes both platforms on a `v*` tag, signs the index and
every platform manifest with keyless cosign, and attaches an SPDX SBOM and SLSA
provenance. Verify an image before you run it, substituting the tag you intend to
deploy:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/SessionLayer/Agent/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/sessionlayer/agent:v0.0.2
```
