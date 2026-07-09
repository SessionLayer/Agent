# SessionLayer Agent

The per-node **outbound** connector for the [SessionLayer](https://github.com/SessionLayer)
Zero-Trust SSH platform. The Agent dials out to failure-domain-diverse Gateways
and, on demand, dial-backs and splices a connection to the local `sshd` — so a
node needs **no inbound holes** and the Gateway never trusts the node on TOFU
(Design §9.2).

> **Status: Session One scaffold.** This repo is currently **scaffolding only** —
> package, contract codegen, a `--version` surface, the non-root posture, and the
> quality/CI gate. There is **no product behaviour yet** (no join/credential
> lifecycle, no wire transport, no dial-back). See `CLAUDE.md` for scope and the
> roadmap.

## Security posture from day one

- **Non-root by construction** (FR-CONN-6 / Design §9.3): a root Agent could read
  the node host key and impersonate the node. The container runs as a dedicated
  non-root user; CI fails if that ever regresses.
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
sessionlayer-agent                  # initialise, report readiness, exit (no behaviour yet)
```

## Container (non-root)

```bash
docker build -t sessionlayer-agent .
scripts/verify-nonroot-image.sh     # build + assert the runtime USER is non-root
```

## Contracts

The Agent generates its shared message types from a byte-identical **vendored
copy** of the canonical `common.proto`
(`ControlPlane-API/contracts/proto/...`). Keep it in sync with
`scripts/sync-contracts.sh` (`--check` to verify). The Agent↔Gateway wire
protocol is specified in `contracts/wire/agent-gateway-v1.md`.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
