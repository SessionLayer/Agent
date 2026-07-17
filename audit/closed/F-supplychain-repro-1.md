# F-supplychain-repro-1: reproducibility gate proved same-runner, not independent
- Severity: medium
- Status: Verified-Fixed
- Area: supplychain

## Summary
The Rust double-build ran in one job on one runner with `$HOME`/`$CARGO_HOME`
held constant, and RUSTFLAGS only remapped the workspace — so cargo-registry
paths leaked into panic-location `.rodata` (strip=symbols doesn't remove rodata;
Gateway isn't stripped). An independent off-GitHub rebuilder would get a different
digest, defeating NFR-7 third-party verifiability.

## Fix
RUSTFLAGS now remaps BOTH `$PWD` and `${CARGO_HOME}/registry`. (`[profile] trim-paths`
is not stabilized in the pinned Cargo 1.95.0, so the remap is done in the workflow.)
Residual: the std sysroot path — bounded by pinning the exact toolchain (documented).
Local proof already used both remaps → identical digest. (T3 reliability F2 / security LOW-3.)
