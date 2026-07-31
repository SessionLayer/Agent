# SessionLayer Agent

The per-node outbound connector for [SessionLayer](https://github.com/SessionLayer): it
dials out to a set of Gateways and, on demand, splices a signed dial-back
connection to the node's own `sshd` on loopback, so the node needs no inbound
reachability.

It joins the platform once, with a join token, an OIDC workload identity, or a
certificate from your own PKI, and from then on holds a renewable mTLS
identity with a clone-detecting generation counter. It refuses to start as
root. Releases carry a Sigstore signature and SLSA provenance that the Agent
itself verifies, fully offline, before a binary runs or updates.

## Build and test

Requires the pinned toolchain (`rust-toolchain.toml`, Rust 1.95.0) and `protoc`.

```bash
cargo build                 # library + binary
cargo nextest run --all-features
cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings
cargo audit -D warnings && cargo deny check
```

## Documentation

Installation, join methods, hardening, and the Agent runbook live in the
[Documentation repository](https://github.com/SessionLayer/Documentation).

## License

GPL-3.0-only. See [LICENSE](LICENSE).
