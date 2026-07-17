# F-supplychain-toctou-1: install re-read the candidate after verifying (TOCTOU)
- Severity: high
- Status: Verified-Fixed
- Area: supplychain

## Summary
`SelfUpdater::install` read the candidate, verified those bytes, then
`atomic_replace` did a SECOND `fs::copy` from the candidate path — a verify-then-
swap window: an attacker with write access to the candidate dir could pass a
signed binary through verification then swap it before the copy, installing an
unverified binary (defeating the whole control). Also removed the TOCTOU-prone,
tests-only `SelfUpdater::run`/`Launcher` (verify-then-exec-the-path) primitive.

## Fix
`install` now writes the exact **verified bytes buffer** to a fresh O_EXCL temp
then renames (`atomic_write`), never re-reading the path. The secure run/update
flow is `install` (verified bytes) → restart → `--verify-self`. (T3 reliability F1.)
