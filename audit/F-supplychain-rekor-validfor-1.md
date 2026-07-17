# F-supplychain-rekor-validfor-1: Rekor/Fulcio key validFor windows not enforced
- Severity: low
- Status: Accepted-Risk
- Area: supplychain

## Summary
The verifier trusts every CA/tlog key in the pinned trusted_root.json without
checking each key's `validFor` window against the entry's integratedTime, so a
retired-then-compromised Rekor key would stay trusted until the operator re-pins.

## Justification (Accepted-Risk)
Narrow: exploitation needs Sigstore to retire a key AND that key compromised AND a
Fulcio cert matching our exact pinned identity. The Fulcio CA validity IS checked
against log time; the digest-pinned, operator-controlled trusted_root.json is the
control (rotate on Sigstore key retirement — RUNBOOK). Track for a future session.
