# F-supplychain-sct-1: Fulcio SCT / CT-log not verified
- Severity: low
- Status: Accepted-Risk
- Area: supplychain

## Summary
`cosign`/sigstore-go verify the embedded SCT against the CT-log key; our offline
verifier does not parse `ctlogs` or check the SCT.

## Justification (Accepted-Risk)
SCT value is detectability of Fulcio mis-issuance via CT monitors, not verify-time
prevention. Given a pinned Fulcio root + a mandatory Rekor SET + a pinned identity,
the offline verifier's guarantees hold without the SCT. (T3 divergence F-DIV-4.)
