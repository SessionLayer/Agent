# F-supplychain-bundle-shape-1: verifier refused any bundle without exactly one tlog entry
- Severity: medium
- Status: Verified-Fixed
- Area: supplychain

## Summary
`tlog_entry()` required EXACTLY one Rekor entry; a future multi-entry bundle
(Rekor v1→v2 dual-log window) would be refused fail-closed → the updater could
never accept a genuine new release (availability foot-gun). `trusted_root.json`
also failed the whole load if any single tlog key wasn't P-256.

## Fix
Accept the FIRST of >=1 entries (its SET must still verify AND its body must bind
the artifact digest, so extra entries can't weaken it); trust.rs now SKIPS
unusable tlog keys and errors only if none are usable. (T3 security MED-2/LOW-4.)
