//! The OTLP exporter path (Part C / OTEL-CONTRACT §6): when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is set, `telemetry::init` builds the exporter +
//! provider (tonic/ring, lazy connect) without a live collector and without
//! panicking, and the returned guard shuts down cleanly.
//!
//! Dedicated test binary → its own process under nextest, so setting the env var +
//! the global subscriber here cannot collide with other tests. Off-by-default is
//! covered implicitly: every other test runs with no endpoint set.

#[test]
fn otlp_exporter_builds_when_endpoint_is_set_and_shuts_down_without_a_collector() {
    // No collector is listening; the exporter must still build (the tonic channel
    // connects lazily) and the guard must flush + tear down its runtime without
    // hanging (a failed export against a dead port returns promptly).
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317");
    std::env::set_var("OTEL_SERVICE_NAME", "sessionlayer-agent-otlp-test");

    let guard = sessionlayer_agent::telemetry::init(Some("info"));
    // Exercise the OTLP layer.
    tracing::info!("otlp smoke event");
    {
        let span = tracing::info_span!("agent.enroll", sessionlayer.session_id = "sess-otlp");
        let _e = span.enter();
    }
    drop(guard);

    std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    std::env::remove_var("OTEL_SERVICE_NAME");
}
