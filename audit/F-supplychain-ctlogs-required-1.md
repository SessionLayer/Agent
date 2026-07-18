# F-supplychain-ctlogs-required-1: a ctlog-less trust root silently disabled SCT
- Severity: low
- Status: Verified-Fixed
- Area: supplychain

## Summary
S24 added Fulcio SCT verification gated on a CT log being pinned in the trust root
(`ctlog_keys.is_empty() ⇒ SCT not enforced`, matching sigstore-go). Correct in the
generic case, but there was **no guard that the operator-supplied
`trusted_root.json` for the pinned SessionLayer/Agent identity actually contains
`ctlogs`** — so an anchor with empty/absent `ctlogs` silently disabled the entire
SCT hardening (the rogue-Fulcio-off-log-cert risk it closes) with zero operator
signal. The golden *test* asserts `ctlogs` present; production did not.
(T3 redteam A1, LOW / defense-in-depth.)

## Root cause (the exact fail-open, Sec-F1)
`from_trusted_root_json` loaded `ctlogs` with a skip-the-unparseable loop but — unlike
`fulcio_cas` (fatal on a bad window) and `rekor_keys` (errors if none) — imposed **no
"at least one usable" floor**. So a `trusted_root.json` that DECLARES a ctlog whose key
this P-256-only parser can't decode (a future ed25519/P-384 CT key, bad base64, or an
unparseable `validFor`) left `ctlog_keys` empty ⇒ `sct::verify_embedded_scts` hit
`if ctlog_keys.is_empty() { return Ok(()) }` ⇒ SCT silently no-ops. Realistic
non-attacker trigger: **Sigstore rotates the CT log to a key type this parser can't
decode.**

## Fix (root cause — two layers)
- **Load floor (path-independent):** `trust.rs::from_trusted_root_json` now refuses
  (`VerifyError::TrustAnchor`) when `ctlogs` is **non-empty but no key is usable** —
  declared-but-unusable is a broken trust root, not "no CT", so it fails closed at load
  regardless of policy. An empty-DECLARED `ctlogs` stays "SCT optional" (sigstore-go
  compat) and emits a `warn!`.
- **Policy requirement (pinned identity):** `VerificationPolicy::require_certificate_transparency`
  is **true** for the pinned `sessionlayer_agent()` identity; `verify_binary` fails
  closed (`VerifyError::Sct`) when the policy requires CT but the trust root pins no
  CT-log key. `main.rs::VerifyArgs::policy()` relaxes it (`= false`) only for a custom
  `--expect-*` identity (a private Sigstore may run no CT log).

## Regression tests (`src/supply_chain/tests.rs`)
- `refuses_trust_root_that_declares_unusable_ctlogs` — a trust root declaring a ctlog
  with a valid **P-384** SPKI (a key type the parser can't decode) **FAILS TO LOAD**
  (`TrustAnchor`), not load-with-SCT-silently-disabled. This is the exact Sec-F1 case.
- `refuses_pinned_identity_when_trust_root_pins_no_ctlogs` — production policy + a trust
  root with no `ctlogs` → refused (`VerifyError::Sct`).
- `no_ct_pinned_does_not_require_sct` asserts the relaxed (`require = false`) posture is
  what permits the no-CT case.
