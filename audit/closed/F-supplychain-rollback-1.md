# F-supplychain-rollback-1: no anti-rollback — a signed OLDER release could be forced
- Severity: high
- Status: Verified-Fixed
- Area: supplychain

## Summary
The update path verified signature+provenance+identity+digest but never compared
versions, so a genuine, correctly-signed **older** release (e.g. a pre-patch build
with a fixed RCE) passed every check — a signed downgrade attack, and an
indefinite-freeze vector.

## Fix
The release version is extracted from the identity-pinned, Fulcio-signed SAN tag
ref (`…@refs/tags/v<VERSION>`) into `VerifiedRelease.version`;
`SelfUpdater::with_rollback_floor` + `check_rollback` refuse a candidate whose
SemVer is not >= the running version (default floor = `CARGO_PKG_VERSION`) unless
`--allow-downgrade`. Test: `refuses_signed_downgrade`. (T3 divergence F-DIV-1.)
