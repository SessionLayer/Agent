# F-ha-agent-servername-1: a single --gateway-server-name cannot verify ≥2 diverse gateways

- Severity: medium
- Status: Verified-Fixed
- Area: ha

## Summary
Surfaced by the S15 cross-repo two-real-binary HA E2E (Part H) — a bug the per-repo
doubles structurally could not catch, because the in-repo `TestGateway` gave every
instance the **same** serverAuth SAN (`gateway`).

FR-HA-6 requires the Agent to hold **≥2 failure-domain-diverse control channels**.
The real Control Plane stamps each gateway's serverAuth leaf with
`dNSName SAN = gateway_identity.name`, and gateway names are **unique** — so two real
gateways carry **distinct** SANs. But `GatewayConfig` held a **single**
`server_name`, applied to every endpoint: `ControlChannel::serve_once` (and
`splice::dial_back`) passed that one name to `transport::connect`, where
`Tls13OnlyPinnedVerifier` (wrapping `WebPkiServerVerifier`) pins the presented
cert's SAN to it. Consequently an Agent configured with two diverse gateways would
verify the FIRST gateway's SAN against both, so the **second gateway's serverAuth
cert fails the name check** → that channel never completes the preface → the Agent is
single-homed. The ≥2-diverse-channel requirement did not actually work in production.

Fails **closed** (the second channel refuses and reconnect-loops; no fail-open, no
security bypass) — it is an availability/correctness defect, not a disclosure.

## Fix
`server_name` moves from `GatewayConfig` into `GatewayEndpoint`, so each channel is
verified against **its own** gateway's enrolled name (no TOFU). The control channel
uses its endpoint's name; the dial-back looks up the matched configured endpoint
(`configured_endpoint`) and verifies against **that** gateway's name. CLI
`--gateway-server-name` becomes repeatable, zipped positionally with
`--gateway-endpoint` (one per endpoint / exactly one applied to all / none → default
`gateway`), so single-instance is unchanged. `validate()` requires each endpoint to
carry a non-empty name.

## Why the doubles missed it (test gap, also fixed)
The masking test `gateway_it::agent_holds_two_diverse_channels_and_survives_losing_one_gateway`
gave both `TestGateway`s the SAN `gateway`, so the single server-name matched both and
the bug hid — the same class as a node-id bug hiding behind UUID fixtures. `GwOptions`
now takes a per-instance `server_name`; the two Part F tests use **distinct** SANs
(`gw-a`/`gw-b`), so they exercise the real diverse-gateway case and would fail without
the per-endpoint fix.

## Tests
- `config::tests::each_endpoint_carries_its_own_verified_server_name` (unit): distinct
  per-endpoint names validate; an empty endpoint name is refused.
- `gateway_it::agent_holds_two_diverse_channels_and_survives_losing_one_gateway`
  (integration): two `TestGateway`s with distinct SANs `gw-a`/`gw-b`; the Agent
  registers on BOTH — impossible under a single server name — then survives losing one.
- `gateway_it::a_dial_back_is_refused_unless_its_endpoint_is_the_arriving_channels_gateway`
  (integration): now also runs against distinct-SAN gateways.
- `splice::tests::dial_back_endpoint_must_be_a_configured_gateway` updated for the
  endpoint lookup; F-connect-1 allowlist behaviour unchanged.

## Note for the reviewer
Additive: no new dependencies, no contract change. Single-instance and the S14
single-Gateway path are unchanged (one name applies to all endpoints, default
`gateway`). This is exactly the two-real-binary E2E doing what Part H is for —
catching a real bug the mock-gateway doubles could not.
