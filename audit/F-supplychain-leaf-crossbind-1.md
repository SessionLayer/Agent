# F-supplychain-leaf-crossbind-1: Rekor entry body not cross-bound to the bundle leaf
- Severity: low
- Status: Verified-Fixed
- Area: supplychain

## Summary
The S23 verifier checked the Rekor SET + a body-to-digest cross-bind, but did not
check that the leaf cert in the bundle equals the cert embedded in the logged entry
body (cosign/sigstore-go do this for conformance) — so the transparency entry was
bound to the digest, not to *this* leaf.

## Fix (S24)
`rekor::require_body_binds_leaf` (called from `verify_identity` for both bundles)
now extracts the certificate embedded in the Rekor entry body — `hashedrekord`
(`spec.signature.publicKey.content`), `dsse`/`intoto` (`spec.signatures[].verifier`
or `spec.publicKey`) — decodes it (base64 → PEM or DER) and requires it to equal the
verified signing leaf DER. Fail-closed: a body that embeds a different cert, or no
cert, is refused (`VerifyError::Transparency`). This binds the tlog entry to the
verified leaf, not merely to "a Rekor entry exists for this digest".

## Regression tests (`src/supply_chain/tests.rs`)
- `refuses_body_cert_not_the_signing_leaf` — the Rekor body embeds a different
  (valid) certificate than the signing leaf → refused.
- The accept path (`accepts_valid_release`, `golden_bundle_verifies_and_rejects_tampering`)
  now embeds the real leaf PEM in both bodies and passes end-to-end.
