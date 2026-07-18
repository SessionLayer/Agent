# F-supplychain-golden-1: no golden test against a captured Sigstore bundle
- Severity: info
- Status: Verified-Fixed
- Area: supplychain

## Summary
The S23 tamper matrix built bundles on the fly with a test Fulcio-shaped chain, so
byte-exactness of the full chain was asserted by construction + analysis, not
against a committed, frozen bundle exercised through the real file-based path.

## Fix (S24)
A committed golden fixture under `src/supply_chain/testdata/golden/` (a real-schema
Sigstore v0.3 bundle: cosign blob-signature bundle + SLSA provenance DSSE bundle +
a full `trusted_root.json` with Fulcio CAs, the Rekor tlog key AND a CT-log key,
plus the released binary). The leaf carries a valid embedded precert SCT, so the
golden drives SCT + chain + SET + leaf-cross-bind + DSSE end-to-end.

`golden_bundle_verifies_and_rejects_tampering` (`src/supply_chain/tests.rs`):
- ACCEPTS the untampered golden through `verify_files` under the PRODUCTION identity
  policy (`VerificationPolicy::sessionlayer_agent()`) + `from_trusted_root_json`.
- REFUSES a single-field tamper battery: flip a byte in the leaf cert, the Rekor SET
  (inclusion promise), the artifact digest, the DSSE payload, or the binary — each
  fails closed.

The fixture is regenerable via `SL_REGEN_GOLDEN=1 cargo test regenerate_golden_fixture`.

## On "real captured production bundle" (unchanged constraint)
Signing a genuine production bundle needs the CI's ambient GitHub OIDC + live
Fulcio/Rekor — not reproducible offline on this box, and a real bundle would carry a
foreign identity that our pinned policy rejects. The golden is therefore
self-generated (public certs/signatures/SET/SCT only; the ephemeral signing keys are
discarded, never committed) but is a real-schema, frozen, byte-exact bundle driven
through the real verifier. The first real tagged release remains the production
end-to-end validation (`gh attestation verify` + `sessionlayer-agent verify`).
