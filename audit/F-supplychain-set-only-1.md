# F-supplychain-set-only-1: transparency via Rekor SET only (no Merkle inclusion proof)
- Severity: low
- Status: Accepted-Risk
- Area: supplychain

## Summary
Transparency is verified via the Rekor SignedEntryTimestamp (inclusion *promise*)
under the pinned Rekor key + a body-to-digest cross-bind; the Merkle inclusion
*proof* against a signed checkpoint is not verified, and the SET is required.

## Justification (Accepted-Risk)
The SET-only, offline model is the standard cosign `--offline` approach and is
sound given a pinned Rekor key (it authenticates loggedness + the trusted
timestamp). Current attest-build-provenance v3 / cosign --new-bundle-format emit
the SET. Forward-compat: if a future bundle drops the SET for inclusionProof-only,
verification fails CLOSED (safe) until we add inclusionProof support — tracked.
