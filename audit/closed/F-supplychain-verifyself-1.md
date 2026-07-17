# F-supplychain-verifyself-1: verify-before-RUN not wired to the run path
- Severity: medium
- Status: Verified-Fixed
- Area: supplychain

## Summary
Only `verify`/`update` verified; the daemon `run` path did not self-verify, though
the contract promised a startup `--verify-self` and NFR-7 says a node refuses to
*run* an unverified binary.

## Fix
`run --verify-self` (with `--self-blob-bundle/--self-provenance/--self-trusted-root`)
verifies `/proc/self/exe` against the pinned root+identity BEFORE any credential
work and aborts on failure (fail closed). (T3 divergence F-DIV-2 / reliability F3.)
