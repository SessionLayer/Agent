# F-observability-1: renew-ahead loop has no metrics / health surface (S12)
- Severity: low
- Status: Accepted-Risk
- Area: observability

## Summary
The S12 Agent runs a long-lived renew-ahead loop with **no metrics and no
liveness/readiness endpoint**, and the `tracing` subscriber emits human-format
(not JSON) events. For an on-call, the key signals — time-to-cert-expiry, renewal
attempt/failure counters, current generation, and loop-alive heartbeat — do not
exist as metrics; the only orchestration signal is the process exit status.

## Assessment / why Accepted-Risk (this session)
The Agent is an **outbound-only control-plane participant** in S12 with no data
plane, no inbound listener, and no consumers of a health surface yet. A metrics
stack and a health/readiness endpoint are scoped to land with the S13 transport /
`NodeConnector` (where readiness = "≥2 control channels established" becomes
meaningful, FR-HA-6). Adding a metrics runtime dependency now, ahead of any
consumer, would be premature (NFR-7 keeps the dependency set minimal).

## Compensating controls (in place this session)
- F1 (this pass) makes a terminal/security loop stop exit with a **distinct
  non-zero code** (3 = clone/mismatch, 4 = repair-needed), so the process exit
  status — S12's only orchestration signal — is actionable and alertable
  (`RUNBOOK.md`), rather than the previous silent exit 0.
- The `SECURITY: generation mismatch ...` and `REPAIR-NEEDED: ...` events are
  distinct, structured `tracing` error lines suitable for log-based alerting; CP
  wire text is never rendered (only the gRPC code — F-identity-1).

## Follow-up (S13)
Add RED metrics (renewal rate/errors/duration), saturation gauges (time-to-expiry,
generation), a liveness/readiness surface, W3C traceparent propagation on the
CP RPCs, and switch the subscriber to JSON. Tracked for the session that ships the
transport.
