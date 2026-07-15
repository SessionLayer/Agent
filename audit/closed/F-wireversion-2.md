# F-wireversion-2: the Agent↔Gateway wire version reused the gRPC/component version constant
- Severity: low
- Status: Verified-Fixed
- Area: wire

## Summary
The wire `HELLO` preface (`gateway/client.rs`) advertised its protocol range from
`version::PROTOCOL_MIN/MAX` and `version::component_info()` — the **same** constants
the CP↔Agent gRPC/identity plane uses. Both protocols happen to be at `1.0` today, so
the Agent is correct only by coincidence. If the gRPC/component version were ever
bumped (its own N-1 evolution), the wire `HELLO` would silently start advertising a
wire version this build does not implement — the mirror of the Gateway-side
F-wireversion-1 (the Gateway advertised wire 1.1 by reusing its gRPC `PROTOCOL_*`).

## Fix (`src/version.rs`, `src/gateway/client.rs`, `src/gateway/wire.rs`, `src/lib.rs`)
- Added a dedicated Agent↔Gateway **wire** version, fixed at `1.0` (`min == max`):
  `WIRE_PROTOCOL_MAJOR/MINOR`, `WIRE_PROTOCOL_MIN/MAX`, and `wire_component_info()`.
- The wire preface and `negotiated_from` now use `WIRE_PROTOCOL_*` /
  `wire_component_info()` exclusively; `PROTOCOL_*` / `component_info()` are now
  documented as the CP↔Agent gRPC/component descriptor (unchanged, still used by
  `identity.rs` enroll/renew and `--version`).
- The `--version` banner (which cites `agent-gateway-v1.md`) is the wire protocol,
  so its drift-guard test now tracks `WIRE_PROTOCOL_*`.

The two version lines are now independent: a future gRPC bump cannot make the wire
`HELLO` advertise a wire version the Agent does not speak.

## Tests
- `version::wire_protocol_range_is_exactly_1_0` (integration, `tests/version.rs`):
  `WIRE_PROTOCOL_MIN == WIRE_PROTOCOL_MAX == 1.0` and `wire_component_info()` carries
  exactly that range.
- Existing `gateway::client::tests::refuses_a_version_we_never_advertised` already
  proves the Agent rejects `1.7`, `2.0`, `0.9` — i.e. it fails closed against any
  selected version outside `[1.0, 1.0]`, including a Gateway that (per F-wireversion-1)
  advertises wire `1.1`.

## Cross-repo note
The Agent side was latent (correct-by-accident); the Gateway side (F-wireversion-1)
was an active HIGH that gw-engineer owns. My Agent correctly refuses a Gateway that
selects any non-`1.0` wire version, so the two fixes are independent.
