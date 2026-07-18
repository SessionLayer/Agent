# F-supplychain-rekor-validfor-1: Rekor/Fulcio key validFor windows not enforced
- Severity: low
- Status: Accepted-Risk
- Area: supplychain

## SUPERSEDED
Superseded by `audit/closed/F-supplychain-validfor-1.md` (S23), which upgraded this
to MEDIUM and **fixed** it: the verifier now parses each trusted-root `validFor`
window and rejects a Rekor SET / Fulcio CA whose window does not contain the log
`integratedTime`. The original S22 Accepted-Risk text is kept below for history.

## Summary
The verifier trusts every CA/tlog key in the pinned trusted_root.json without
checking each key's `validFor` window against the entry's integratedTime, so a
retired-then-compromised Rekor key would stay trusted until the operator re-pins.

## Justification (Accepted-Risk)
Narrow: exploitation needs Sigstore to retire a key AND that key compromised AND a
Fulcio cert matching our exact pinned identity. The Fulcio CA validity IS checked
against log time; the digest-pinned, operator-controlled trusted_root.json is the
control (rotate on Sigstore key retirement — RUNBOOK). Track for a future session.
