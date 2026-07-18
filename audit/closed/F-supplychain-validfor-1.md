# F-supplychain-validfor-1: Sigstore Rekor/Fulcio `validFor` windows not enforced
- Severity: medium
- Status: Verified-Fixed
- Area: supplychain

(Supersedes the S22 `F-supplychain-rekor-validfor-1` Accepted-Risk/LOW; upgraded to
MEDIUM and fixed this session.)

## Context / root cause
`trust.rs::from_trusted_root_json` loaded every Rekor tlog key and every Fulcio CA
from the pinned `trusted_root.json` but **discarded each entry's `validFor` window**.
A Rekor log key is a bare P-256 public key — it has **no X.509 validity of its
own**, so its `validFor` window was the *only* time bound on it, and we dropped it.
Consequence: a **retired-then-compromised** Rekor key stayed fully trusted (able to
mint a valid `SignedEntryTimestamp` dating a fresh forged signing event) until an
operator manually re-pinned the root; likewise a **retired-but-not-yet-expired**
Fulcio intermediate could still anchor a chain. sigstore-go / cosign require the
Rekor SET's `integratedTime` to fall inside **both** the selected tlog key's
`validFor` **and** the anchoring Fulcio CA's `validFor`. This was the one
reference-standard check the offline verifier had dropped; it converts a
retired-key compromise into a working forgery against our exact pinned identity.

Sigstore schema (protobuf-specs `TimeRange`, proto-JSON camelCase): `start`
(RFC3339, required) and `end` (RFC3339, **optional** — absent = still valid, no
upper bound); bounds are **inclusive**. A window contains `t` iff
`start <= t && (end absent || t <= end)`.

## Fix
- `trust.rs`: `TrustRoot` now carries each Rekor key as `RekorKey { key, valid_for }`
  and each Fulcio cert as `FulcioCa { der, valid_for }` (`valid_for: TimeRange`,
  a CA's window applies to every cert in its chain). `validFor` is parsed from
  RFC3339 to **Unix seconds** with a small hand-rolled parser (`parse_rfc3339_secs`
  + Hinnant `days_from_civil`) — the Rekor `integratedTime` is already Unix seconds,
  so no `chrono`/`time` crate is added (NFR-7; a dep would need `cargo deny` sign-off
  and was avoided). A tlog key whose window is missing/unparseable is **skipped**
  (existing "don't brick on an odd key" behaviour, fails closed if none remain); a
  CA's window is a hard parse (as its cert bytes already were).
- `rekor.rs::verify_set`: a pinned Rekor key is accepted **only if its `valid_for`
  contains `integratedTime`** (distinct "retired key" transparency error otherwise).
- `cert.rs::verify_chain`: every pinned CA used in the chain (intermediate + the
  anchoring self-signed root) must have `integratedTime ∈ valid_for`, in addition to
  the existing cert `not_before`/`not_after`-at-log-time check.

## Regression tests (`src/supply_chain/tests.rs`, real Fulcio-shaped fixtures)
The three new tests re-emit the fixture's real chain + key as a `trusted_root.json`
and load it through `from_trusted_root_json`, so they exercise the actual RFC3339
parse + window enforcement end to end (LOG_TIME = `2027-01-15T08:00:00Z`):
- `refuses_retired_rekor_key_window` — SET key `validFor.end` one second before
  `integratedTime` → `Transparency` refusal.
- `refuses_expired_fulcio_ca_window` — Fulcio CA `validFor.end` before
  `integratedTime` → `CertValidity` refusal.
- `accepts_when_log_time_in_all_windows_open_ended` — positive control: both
  windows open-ended (`end` absent) → accepted (proves absent-end = still valid, no
  false refusal on a current root).
Plus unit tests in `trust.rs` for the RFC3339 parser (Z / fractional / `±hh:mm`
offset / malformed-reject) and `TimeRange::contains` (inclusive bounds, open end).
All pre-existing tamper-matrix tests continue to pass unchanged.

## Residual
The window is only as fresh as the operator's pinned `trusted_root.json` (rotate on
Sigstore key retirement — RUNBOOK); enforcement now makes a retired key fail
**closed** at verify time rather than trusting it until the next re-pin.
