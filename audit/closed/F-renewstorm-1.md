# F-renewstorm-1: post-renewal floor collapses to zero when the cert has no remaining window
- Severity: high
- Status: Verified-Fixed
- Area: identity

## Summary
The renew-ahead loop applies a post-renewal minimum-interval floor (F2,
`RENEW_MIN_INTERVAL` = 60s) so a certificate born past its renew trigger cannot
make the loop renew back-to-back and hammer the CP / burn generations. The floor
was capped at half the remaining validity window so the next renewal still landed
before expiry:

```rust
base.max(RENEW_MIN_INTERVAL.min(remaining / 2))   // BUG
```

When the CP issues a certificate that is **already expired** — `remaining == 0`,
which happens with a TTL shorter than the clock-skew backdate (FR-BOOT-4) or a CP
clock ahead of the node — `remaining / 2 == 0`, so `RENEW_MIN_INTERVAL.min(0) == 0`
and the floor collapses to `base` (itself 0, since an expired cert is past its
trigger). The delay becomes zero and the loop renews as fast as the RPC completes:
the exact storm the floor exists to prevent, precisely in the degraded state where
it matters most. It was also silent — no distinct operator signal.

## Fix (`src/identity.rs`)
- `floor_after_renew`: when `remaining.is_zero()`, apply the **full**
  `RENEW_MIN_INTERVAL` floor instead of the collapsing cap. With no window left,
  there is nothing to race, so protecting the CP wins.
- The loop (`RenewAhead::run`) now detects the zero-remaining case and logs a
  distinct, loud **`error!`** — `RENEW-STORM GUARD` — naming the likely cause (clock
  skew / TTL < backdate, FR-BOOT-4) and that the generation counter is a
  clone-detection signal.

### Deliberate call: retry (not terminal), bounded, loud
Considered making an already-expired issued cert terminal (`RepairNeeded`, exit 4).
Chose **retry** instead, and wrote the reasoning down because it is not obvious:
1. **Often transient.** NTP recovery, a VM snapshot restore, or a settling container
   clock corrects itself; a terminal exit would turn a recoverable blip into a
   re-provision incident (availability hit for no security gain).
2. **The fault may be the CP's clock, not the node's.** The RPC keeps *succeeding*
   because the CP validates against the **CP's** clock. A CP clock that jumps ahead
   would make *every* agent see `remaining == 0` at once — a terminal exit would take
   down the whole fleet on a single central misconfiguration.
3. **The counter is a security signal.** S12 clone-detection fires on a generation
   mismatch, so a hot renew loop *corrupts the very counter* that distinguishes a
   clone from a healthy identity. The full floor bounds the burn to ≈1/min (from
   ~20+/s), keeping the signal usable, and the `error!` makes the fault page.

So: bounded retry + loud `error!`, not terminal. The S12 exit-code contract (0/3/4)
is unchanged.

## Tests
- `identity::tests::floor_after_renew_does_not_collapse_when_no_window_remains`
  (unit): `floor_after_renew(0, 0) == RENEW_MIN_INTERVAL`, and a base beyond the
  floor is still honoured.
- `identity::tests::floor_after_renew_bounds_a_storm_but_never_delays_past_expiry`
  (unit, retained): the genuine near-expiry window (`remaining = 20s → 10s`) still
  beats expiry — the fix does not regress the real-window path.
- `join_it::renew_loop_does_not_storm_when_the_cp_issues_expired_certs`
  (integration): the mock CP issues zero-TTL (already-expired) certs; the loop runs
  for 3s and the recorded generation stays in `1..=5` (a storm would rack up
  hundreds). Without the fix this test fails.

## Cross-repo note
This is the S12 carry-forward the memory `[[agent-renew-reliability]]` flagged as
shared with the Gateway ("the Gateway shares the F2 busy-renew latent bug,
cross-repo, unfixed there"). The Gateway's identical helper must land the same
semantics: full floor on zero remaining, loud-but-retry. gw-engineer notified.
