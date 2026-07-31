#[test]
fn otlp_exporter_builds_when_endpoint_is_set_and_shuts_down_without_a_collector() {
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317");
    std::env::set_var("OTEL_SERVICE_NAME", "sessionlayer-agent-otlp-test");

    let guard = sessionlayer_agent::telemetry::init(Some("info"));
    tracing::info!("otlp smoke event");
    {
        let span = tracing::info_span!("agent.enroll", sessionlayer.session_id = "sess-otlp");
        let _e = span.enter();
    }
    drop(guard);

    std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    std::env::remove_var("OTEL_SERVICE_NAME");
}
