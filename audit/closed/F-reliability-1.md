# F-reliability-1: renew-ahead loop operability gaps (exit-code masking, renew storm, classifier divergence)
- Severity: medium
- Status: Verified-Fixed
- Area: reliability

## Summary
An SRE/operability review of the S12 renewable-identity lifecycle
(`src/identity.rs`, `src/main.rs`) found a set of failure-mode gaps. The
lifecycle's safety spine (renew-ahead math, persist-before-adopt, single-writer
lock, clone detection) was already sound; these are operability hardening. Fixed
in this pass.

## Findings and remediation (applied)

**F1 (medium) — a terminal/security loop stop exited the process with status 0.**
`RenewAhead::run` returned `()` for shutdown, generation-mismatch (clone), and
repair-needed alike, and `main` discarded it → all three exited 0. Under an
always-restart policy a clone-locked Agent logged one error, exited 0, restarted,
loaded the still-valid cert, re-locked at 2/3 TTL, and exited 0 again — a silent
slow crash-loop with no non-zero exit and (no metrics in S12) no other operator
signal. FR-JOIN-5's "raise a security alert" was reduced to a log line the exit
status contradicted. Fix: `run` now returns `RenewOutcome`; `main` maps it to
distinct exit codes (0 shutdown, 3 generation-mismatch, 4 repair-needed) via
`exit_status`. Test: `terminal_and_security_stops_are_distinct_non_zero_exit_codes`.

**F2 (medium) — no floor between consecutive renewals → CP renew storm.**
`compute_renew_delay` returns 0 when the trigger is already past; the loop slept
that with no lower bound and re-renewed immediately. A cert born past its trigger
(short TTL + large clock-skew backdate, FR-BOOT-4, or a CP clock ahead) caused
renew-as-fast-as-RPCs-complete, ×fleet, burning generations. Fix:
`floor_after_renew` bounds the *post-renewal* wait to `RENEW_MIN_INTERVAL` (~60s),
capped at half the remaining TTL so it never delays past expiry; manual triggers
and shutdown are unaffected (separate select arms). Test:
`floor_after_renew_bounds_a_storm_but_never_delays_past_expiry`.

**F3 (medium) — startup vs loop error classification diverged.** `is_transient`
(main) and `is_repair_needed` (identity) disagreed: `Corrupt`/`Io` were terminal
→ exit at startup but transient → retry in the loop. Fix: one
`classify_renew_error` → `RenewalDisposition` used by both paths; `Corrupt`/`Io`
now keep the current valid credential and retry everywhere. Test:
`classify_renew_error_unifies_startup_and_loop_dispositions`.

**F5 (low) — retry backoff had no jitter.** A fleet that entered backoff together
(CP outage) retried in lockstep. Fix: `jittered_backoff` applies ±50% jitter.
Test: `jittered_backoff_stays_within_half_bounds`.

**F9 (low/nit) — `remaining_fraction` had no Agent unit test; the `flock` lock is
NFS-unsafe.** Fix: added `remaining_fraction_tracks_the_window`, and an NFS caveat
on `IdentityStore` + `RUNBOOK.md` (keep the data-dir node-local).

**F4 (doc) — residual self-lock window.** A crash after the CP commits gen N+1 but
before the Agent persists leaves the Agent at N; the next renewal mismatches and
the CP auto-locks (fail-closed to re-provision, never silent corruption).
Documented on `renew()` and in `RUNBOOK.md`.

## Not fixed here (accepted / deferred)
- F6 metrics/health surface → `audit/F-observability-1.md` (Accepted-Risk, S13).
- F7 (drain waits for an in-flight renew; deliberately not raced — racing would
  widen F4; the atomic persist makes even SIGKILL crash-safe) and F8 (CA-rotation
  overlap is a CP responsibility) → documented in `RUNBOOK.md`, no code change.

## Verification
`./scripts/gate.sh` green (fmt / clippy -D warnings / nextest / audit / deny /
findings). Cross-repo note: the Gateway baseline shares the F2 latent
busy-renew behavior; flagged to the Gateway owners separately.
