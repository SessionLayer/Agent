# F-splicehalfclose-1: splice teardown aborted the opposite direction instead of a clean half-close
- Severity: low
- Status: Verified-Fixed
- Area: splice

## Summary
The bidirectional splice (`gateway/splice.rs::splice`) ended with
`tokio::select! { … r = to_node => { to_gateway.abort(); … } … }`: the first
direction to reach EOF hard-`abort()`ed the other task. That skips the other
direction's clean shutdown — any bytes already in flight from the peer are dropped,
and its `shutdown()` / `STREAM_CLOSE` may not run. Benign for SSH in practice (both
directions EOF together at session teardown), but it diverges from the S8 inner-leg
byte bridge, which drains each direction to its own EOF with a proper half-close.

## Fix (`src/gateway/splice.rs`)
On the first direction's EOF — each task already half-closes its peer's write half
before completing (`node_wr.shutdown()` on the gateway→node task; `STREAM_CLOSE` +
`sink.close()` on the node→gateway task) — the surviving direction is now allowed to
**drain to its own EOF** instead of being aborted immediately. The drain is bounded
by `HALF_CLOSE_DRAIN` (10s), which only starts counting once the first direction has
ended (so it never truncates a live session), and a final `abort()` is the backstop
so a peer that half-closes without reciprocating cannot pin the splice — and its
concurrency permit — open.

## Tests
- Existing `gateway_it::agent_dials_back_and_splices_bytes_to_its_local_target` and
  `the_splice_target_is_never_taken_from_the_wire` exercise a full bidirectional
  splice and orderly close over the real transport.
- `splice_e2e::agent_splices_a_real_ssh_session_into_the_nodes_own_sshd` runs a real
  SSH session (version exchange + KEXINIT + cert auth + exec) through the splice and
  tears it down cleanly — proving the half-close path carries and ends a real session.

## Note
Low severity: no security impact and no data loss for SSH (symmetric EOF). The fix
aligns the Agent splice with the S8 bridge's drain-to-EOF discipline and removes the
mid-flight truncation, while keeping a bound so it cannot hang.
