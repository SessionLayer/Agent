# F-enroll-cn-1: enrollment CSR set only the SAN, not the CN the CP validates

- Severity: medium
- Status: Verified-Fixed
- Area: identity

## Summary
Surfaced by the S15 cross-repo two-real-binary HA E2E (Part H): the **real** Agent
binary fails to enroll against the **real** CP jar —
`agent enrollment failed: Control Plane refused the identity RPC (gRPC status InvalidArgument)`.

Root cause: `generate_keypair_and_csr` built the enrollment CSR with `node_name`
only as a **dNSName SAN**, leaving the subject **Common Name empty**
(`CertificateParams::new(vec![node_name])` — that vector is the SAN list; the DN was
never set). But the CP validates the **CN**: `AgentEnrollmentService` rejects a CSR
whose `commonName() != node_name`. Empty CN ≠ the node name → `InvalidArgument`, so
the real Agent could not enroll at all.

This is a **port regression**: the Agent's identity machinery was ported from the
Gateway's, and the Gateway's `generate_keypair_and_csr` sets **both** the SAN and
`DnType::CommonName` (and has a `csr_carries_a_non_blank_cn` test). The Agent port
dropped the CN line. Fails closed (enrollment is refused; no bad identity issued).

## Why the double missed it
The in-repo `MockCp` validated the CSR's **SAN** (via `sign_csr`), not the CN, so the
SAN-only CSR was accepted and every Agent-repo test stayed green. Same class as the
per-endpoint-SAN and node-id fixtures that hid real behaviour.

## Fix
1. `generate_keypair_and_csr` now pushes `DnType::CommonName = node_name` in addition
   to the SAN — byte-for-byte the Gateway's approach, satisfying the CP's check. The
   ISSUED cert's identity is unchanged (the CP re-stamps the SAN from `node.name()`);
   the CN is only what the CP validates at enrollment.
2. `MockCp.enroll_agent` now **also validates `csr.commonName() == node_name`**
   (mirroring the real CP), so the double can no longer mask a SAN-only CSR — with
   the Agent fix in place all enroll/renew ITs pass; without it they would now fail.

## Tests
- `identity::tests::csr_carries_node_name_as_common_name` (unit): the CSR subject CN
  equals `node_name` (mirrors the Gateway's `csr_carries_a_non_blank_cn`).
- `join_it` (integration, 9 tests): every enrollment now goes through the MockCp's
  CN check and passes — proving the Agent CSR carries the CN the real CP requires.

## Note for the reviewer
Agent-side, no contract change, no new deps. The fix side is unambiguous: the CP's
CN validation is the existing convention the Gateway already conforms to, so the
Agent conforms too rather than the CP loosening to accept a SAN. Real-jar-E2E
finding #3 (after config-wiring and per-endpoint SAN `F-ha-agent-servername-1`).
