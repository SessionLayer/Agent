# F-supplychain-set-only-1: transparency via Rekor SET only (no Merkle inclusion proof)
- Severity: low
- Status: Accepted-Risk
- Area: supplychain

## Summary
Transparency is verified via the Rekor SignedEntryTimestamp (inclusion *promise*)
under the pinned Rekor key + a body-to-digest cross-bind + (S24) a leaf-to-body
cross-bind; the Merkle inclusion *proof* against a signed log checkpoint is not
verified, and the SET is required.

## Justification (Accepted-Risk) — re-affirmed S24, the one inherent verifier residual
This is the single verifier residual the S24 zero-compromise pass deliberately
leaves as re-justified Accepted-Risk. It is spec-deferred, not fixable-and-skipped:
- **Sound offline model.** SET-only offline verification is the standard cosign
  `--offline` approach. The SET is signed by the pinned Rekor key and authenticates
  both loggedness and the trusted `integratedTime` (the only clock the verifier
  trusts). The Merkle inclusion proof's checkpoint is *also* signed by the same Rekor
  key, so in the single-pinned-key model it adds little verify-time prevention beyond
  the SET; its real value (gossip/monitor detection of a split-view log) is a
  transparency-ecosystem property, not an offline verify-time gate — the same
  boundary as the D34 externally-anchored audit Merkle root (ratified-deferred, S23
  B1), and out of scope for this session's verifier hardening.
- **Fails closed forward.** attest-build-provenance v3 / cosign `--new-bundle-format`
  emit the SET today. If a future bundle ever drops the SET for inclusionProof-only,
  verification fails CLOSED (a missing SET is refused) until inclusionProof support is
  added — never fails open. Tracked as the clean next increment.
- **Now stronger than at S23.** The other three reference-standard checks that were
  Accepted-Risk (SCT, leaf-cross-bind, golden) are Verified-Fixed this session, so
  the SET-only Merkle-proof gap is the sole remaining, genuinely-inherent residual.
