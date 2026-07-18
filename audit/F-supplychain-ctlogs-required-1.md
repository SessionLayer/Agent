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

## Fix (root cause)
- `VerificationPolicy::require_certificate_transparency` — **true** for the pinned
  `sessionlayer_agent()` production identity. `verify_binary` now **fails closed**
  (`VerifyError::Sct`) when the policy requires CT but the trust root pins no CT-log
  key, so SCT verification can never be silently inert on the production path.
- `main.rs::VerifyArgs::policy()` relaxes the requirement (`= false`) only when the
  operator overrides identity via `--expect-*` (a custom private Sigstore may run no
  CT log) — the generic "no ctlogs ⇒ not enforced" behavior is kept there.
- `trust.rs::from_trusted_root_json` emits a `warn!` whenever `ctlog_keys` is empty,
  so even a relaxed/custom deployment gets an operator signal.

## Regression test (`src/supply_chain/tests.rs`)
- `refuses_pinned_identity_when_trust_root_pins_no_ctlogs` — production policy
  (`require = true`) + a trust root with no `ctlogs` → refused (`VerifyError::Sct`).
- `no_ct_pinned_does_not_require_sct` updated to assert the relaxed (`require = false`)
  posture is what permits the no-CT case.
