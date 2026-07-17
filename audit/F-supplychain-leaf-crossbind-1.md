# F-supplychain-leaf-crossbind-1: Rekor entry body not cross-bound to the bundle leaf
- Severity: low
- Status: Accepted-Risk
- Area: supplychain

## Summary
The verifier checks the Rekor SET + a digest cross-bind, but does not check that
the leaf cert in the bundle equals the cert embedded in the logged entry body
(cosign/sigstore-go do this for conformance).

## Justification (Accepted-Risk)
Not exploitable: the same bundle leaf must sign BOTH the candidate (blob sig) and
the DSSE (verified under it), the Fulcio key is ephemeral, and a cross-release
pairing also fails the `integratedTime ∈ leaf-validity` check. Conformance-only;
track for a future session. (T3 redteam NEW #2.)
