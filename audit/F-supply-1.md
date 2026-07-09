# F-supply-1: CI supply-chain enforcers were installed unpinned
- Severity: low
- Status: Verified-Fixed
- Area: supply-chain

Flagged by `redteam-auditor` in the Session One red-team pass.

## Issue
`.github/workflows/ci.yml` installed `cargo-nextest,cargo-deny,cargo-audit` via a
SHA-pinned `taiki-e/install-action`, but without tool versions — so the very
crates that enforce the supply-chain gate floated to "latest" on every run. A
regressed/backdoored upstream release or a default-behaviour change (e.g. a
cargo-deny schema shift turning a check into a no-op) could silently alter the
gate's guarantees run-to-run, defeating NFR-7 reproducibility.

## Fix
The tools are now pinned to exact versions matching the local toolchain:
`cargo-nextest@0.9.135,cargo-deny@0.19.6,cargo-audit@0.22.1`. Bumps go through
reviewed PRs, matching the toolchain/action-SHA pinning discipline used
elsewhere.
