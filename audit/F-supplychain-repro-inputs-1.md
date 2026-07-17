# F-supplychain-repro-inputs-1: unpinned build inputs in the signing job
- Severity: info
- Status: Accepted-Risk
- Area: supplychain

## Summary
The Rust release jobs `apt-get install protobuf-compiler` (unpinned) and
`cargo install --locked --version 0.5.9 cargo-cyclonedx` (version- + lockfile-
pinned, not hash-pinned). protoc affects codegen determinism (a binary input);
cargo-cyclonedx affects only the (normalized) SBOM.

## Justification (Accepted-Risk)
The in-CI double-build is same-runner so it passes; an INDEPENDENT rebuilder must
match the pinned toolchain, the std sysroot, and the **protoc version** — these are
documented reproducibility preconditions (RESULT §5), the same class as the CP
Temurin pin. cargo install has no upstream hash-pin mechanism; `--locked` bounds
its transitive deps. (T3 redteam NEW #5.)
