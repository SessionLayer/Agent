# F-supplychain-trust-brittle-1: trusted_root.json load hardened + rotation runbook
- Severity: low
- Status: Verified-Fixed
- Area: supplychain

## Summary
`from_trusted_root_json` had no operator guidance for rotation/staleness: a stale
pinned root after a Sigstore Fulcio-intermediate rotation fails closed fleet-wide
with a confusing chain error and no runbook.

## Fix
Added a RUNBOOK "Trust-root rotation & staleness" section (refresh cadence, the
fleet-wide-chain-error → refresh response, digest-pin as the control). Load also
now tolerates non-P256 tlog keys (see F-supplychain-bundle-shape-1). (T3 reliability F4/F10.)
