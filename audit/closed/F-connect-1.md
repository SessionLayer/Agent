# F-connect-1: dial-back endpoint was an unconstrained connect primitive for a hostile Gateway
- Severity: medium
- Status: Verified-Fixed
- Area: connect

## Summary
The confused-deputy / SSRF defence (wire contract §5/§8) locks the **splice
target** to a loopback address taken only from local config — solid. But the
dial-back has a *second* wire-carried destination: `DialBackRequest.dial_back_endpoint`,
the `wss://` address the Agent connects **back** to. It was used verbatim.

An authenticated-but-compromised Gateway (it must already hold a valid, unlocked
mTLS identity to open the control channel and send `DIAL_BACK_REQUEST`) could set
`dial_back_endpoint` to any `host:port` the node can reach. The Agent would perform
a TCP connect + TLS ClientHello there. The TLS handshake then fails closed against
the pinned internal CA (so no bytes/splice ever flow to a non-Gateway), but the
**TCP connect + ClientHello themselves** are a network-pivot / port-scan / recon
primitive from inside the node's network segment — precisely what §5/§8 say no
Gateway "however compromised" may obtain. A red-team teammate demonstrated the
connect against a canary listener during this session.

## Fix
`gateway::splice::dial_back` now refuses (before any connect) a `dial_back_endpoint`
whose authority is not among the Agent's configured `--gateway-endpoint` set
(`endpoint_is_configured`). This is consistent with the contract, which fixes the
endpoint to "the owning Gateway's address; in single-Gateway mode it is the same
Gateway" — never an arbitrary address. Refusal is `DIAL_BACK_ERROR_CODE_REFUSED`
with the reason in the operator log only; nothing is dialled.

Defence in depth, not a replacement: the TLS + mTLS verification against the pinned
CA with the configured server name still stands as the second layer.

## Tests
- `gateway::splice::tests::dial_back_endpoint_must_be_a_configured_gateway` (unit):
  a different host/port, a bare IP, loopback, `169.254.169.254`, `ws://`, and
  garbage are all rejected; a configured host:port (any path) is allowed.
- `gateway_it::a_hostile_dial_back_endpoint_cannot_be_used_as_a_pivot` (integration):
  an unconfigured endpoint yields `REFUSED` and the victim listener sees **zero**
  connections.

## Note for the reviewer
This hardens beyond the literal §5 text (which names only the splice target). It is
raised explicitly as a design decision: it matches the contract's stated intent for
the endpoint and closes a real primitive, at the cost that a real HA deployment
(S15) MUST list every Gateway a node may be dialled back to in that node's
`--gateway-endpoint` set — which it already must, to reach them.
