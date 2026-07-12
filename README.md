# SessionLayer Agent

The per-node **outbound** connector for the [SessionLayer](https://github.com/SessionLayer)
Zero-Trust SSH platform. The Agent dials out to failure-domain-diverse Gateways
and, on demand, dial-backs and splices a connection to the local `sshd` — so a
node needs **no inbound holes** and the Gateway never trusts the node on TOFU
(Design §9.2).

> **Status: Session Twelve — durable identity.** The Agent now **joins** the
> platform (`TokenJoin` / `OidcJoin` / `MtlsJoin`), receives a **renewable
> internal mTLS X.509 identity carrying a generation counter**, and keeps it
> fresh with a renew-ahead loop (persist-before-adopt + single-writer data-dir
> lock + clone-detecting generation counter) — running **non-root, fail-closed**,
> one credential **per node** (Design §8, FR-JOIN-1..6, FR-CONN-6). The dial-back
> **data path** (wire transport, splice to `127.0.0.1:22`) is Session Thirteen.
> See `CLAUDE.md` for scope.

## Security posture

- **Non-root, fail-closed** (FR-CONN-6 / Design §9.3): a root Agent could read
  the node host key and impersonate the node. The container runs as a dedicated
  non-root user, and the Agent **refuses to start** as root (`euid == 0`) before
  loading any credential; CI fails if the image posture regresses.
- **Key custody (D2/§15)**: the Agent generates its keypair + PKCS#10 CSR
  locally and sends only the CSR — the mTLS private key never leaves the Agent
  (zeroized in memory, `0600` on disk).
- **One explicit TLS backend**: a single `rustls` (ring) crypto provider is
  installed at startup; the C OpenSSL stack is banned from the dependency tree.

## Build & test

Requires the pinned toolchain (`rust-toolchain.toml`, Rust 1.95.0) and `protoc`.

```bash
cargo build                 # build the library + binary
cargo nextest run           # run the tests
./scripts/gate.sh           # full local gate (fmt, clippy, tests, audit, deny, findings)
```

## Run

```bash
sessionlayer-agent --version        # SemVer + supported wire-protocol range
sessionlayer-agent --version-json   # machine-readable version descriptor

# Join the platform and maintain the renewable mTLS identity (non-root):
sessionlayer-agent run \
  --node-name web-01 --join-method token --join-token-file /run/join-token \
  --cp-endpoint https://controlplane:9443 --cp-server-name controlplane \
  --bootstrap-ca-file /etc/sessionlayer/cp-ca.pem --data-dir /var/lib/sessionlayer-agent
# --join-method oidc  --join-token-file /var/run/secrets/tokens/sa-token   (delegated, no secret)
# --join-method mtls  --operator-cert-file … --operator-key-file …          (operator PKI)
# --once  enrolls/renews once and exits (CI/E2E); omit to run the renew-ahead loop.
```

## Container (non-root)

```bash
docker build -t sessionlayer-agent .
scripts/verify-nonroot-image.sh     # build + assert the runtime USER is non-root
```

## Contracts

The Agent generates its types + gRPC stubs from byte-identical **vendored
copies** of the canonical protos (`common.proto` + `agent.proto`, the
`AgentIdentity` service) from `ControlPlane-API/contracts/proto/...`. Keep them
in sync with `scripts/sync-contracts.sh` (`--check` to verify). The Agent↔Gateway
dial-back wire protocol (S13) is specified in `contracts/wire/agent-gateway-v1.md`.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
