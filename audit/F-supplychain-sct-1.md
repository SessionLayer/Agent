# F-supplychain-sct-1: Fulcio SCT / CT-log not verified
- Severity: low
- Status: Verified-Fixed
- Area: supplychain

## Summary
`cosign`/sigstore-go verify the embedded SCT against the CT-log key; the S23
offline verifier did not parse `ctlogs` or check the SCT, so a *compromised Fulcio*
issuing an off-log signing cert was not caught at verify time.

## Fix (S24)
The verifier now performs RFC 6962 embedded-**precert** SCT verification
(`src/supply_chain/sct.rs`), the form real Fulcio emits:
- `TrustRoot::from_trusted_root_json` parses `ctlogs[].publicKey` into pinned P-256
  CT-log keys with their `validFor` window and RFC 6962 LogID (`SHA-256(SPKI)`) —
  same skip-the-unparseable policy as the Rekor keys.
- `cert::parse_and_chain` reconstructs the precert TBS (the leaf's TBSCertificate
  with the SCT-list extension stripped — `src/supply_chain/der.rs`), prefixes the
  `SHA-256` of the issuer SPKI, and verifies each embedded SCT's ECDSA signature
  against a pinned CT-log key **whose `validFor` window contains the trusted Rekor
  `integratedTime`** (a retired CT key cannot vouch — same rule as Fulcio/Rekor).
- **Fail-closed & gated:** a pinned CT log makes an SCT mandatory; a leaf with no
  SCT, or none verifying under a pinned in-window key, is refused. No pinned CT log
  ⇒ CT not enforced (matches sigstore-go); the production `trusted_root.json` pins
  one, so releases must be logged.

## Regression tests (`src/supply_chain/tests.rs`)
- `accepts_valid_embedded_sct` — a valid precert SCT verifies. The fixture signs the
  SCT over an INDEPENDENTLY-built precert (not the verifier's reconstruction), so a
  pass also proves the reconstruction is byte-exact.
- `refuses_missing_sct_when_ct_pinned` / `refuses_sct_signed_by_unpinned_ct_key` —
  the two negative cases, both refused (`VerifyError::Sct`).
- `no_ct_pinned_does_not_require_sct` — the "operator hasn't configured CT" posture.
- `precert_reconstruction_strips_only_the_sct_extension` — ground truth for the DER
  surgery, independent of the signature check.
- `golden_bundle_verifies_and_rejects_tampering` drives the SCT path (CT log pinned)
  on the frozen golden bundle end-to-end.
