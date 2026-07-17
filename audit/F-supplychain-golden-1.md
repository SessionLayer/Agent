# F-supplychain-golden-1: no golden test against a real captured Sigstore bundle
- Severity: info
- Status: Accepted-Risk
- Area: supplychain

## Summary
The tamper matrix builds bundles with a test Fulcio-shaped chain and shares the
canonical-SET-payload helper with the verifier, so byte-exactness vs REAL Rekor is
asserted by construction + analysis, not against a captured production bundle.

## Justification (Accepted-Risk)
Signing needs the CI's ambient GitHub OIDC + live Fulcio/Rekor — not reproducible
on this box. The canonical SET payload + PAE + DER handling are correct by analysis
(confirmed by two reviewers). The first real tagged release validates end-to-end
(gh attestation verify + sessionlayer-agent verify). (T3 security MED-2.)
