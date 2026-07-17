# F-observability-1: renew-ahead loop has no metrics / health / tracing surface (S12)
- Severity: low
- Status: Verified-Fixed
- Area: observability

## Summary (S12)
The S12 Agent ran a long-lived renew-ahead loop with **no tracing, no metrics, and
no liveness/readiness endpoint**; the only orchestration signal was the process
exit status. Follow-up scoped to the transport session: add spans + W3C
propagation, and richer signals.

## Resolution (S21 — Part C, OTEL-CONTRACT §2.2)
Distributed tracing is now in place. The Agent mints its own spans —
**`agent.enroll`, `agent.renew`, `agent.dial_back`, `agent.splice`** — and
correlates them to the platform trace by stamping the `sessionlayer.session_id`
it already holds (attribute correlation only; the frozen wire / SLDB1 token are
**not** touched, per §2.2). An OTLP/gRPC exporter (tonic, ring TLS) ships them to a
collector when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; otherwise only the local
`tracing`/fmt subscriber runs, unchanged. Spans carry IDs/enums/durations only —
`tests/telemetry_no_content.rs` proves no token/key/plaintext reaches any span,
attribute, or log (§5).

## Why the remaining items are not gaps for the Agent
- **No inbound metrics/health endpoint by design.** The Agent is an outbound-only
  connector — a node has *no inbound reachability* (Design §9.2), so a scrape
  endpoint would contradict the platform's whole posture. Its health signals are
  push/pull-free: the **exit-code contract** (0 clean / 3 clone / 4 repair,
  `RUNBOOK.md`), the **structured logs**, and now the **pushed OTel spans**. The
  session-establishment + CA-sign **SLOs** live on the CP (S21 Part D), where the
  aggregation belongs (the trace pivots to them via `correlation_id`).
- The earlier compensating control (distinct non-zero exit codes) remains.
