//! Structured logging (`tracing`) + optional OpenTelemetry export (§14).
//!
//! The local `tracing`/fmt subscriber is always installed. When — and only when —
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is set (OTEL-CONTRACT §6) an OTLP/gRPC exporter
//! layer is added so the Agent's spans reach a collector. Export rides tonic on
//! the **ring** TLS backend (never native-TLS — `deny.toml` bans OpenSSL).
//!
//! **Correlation, never content (OTEL-CONTRACT §2.2/§5).** The Agent mints its own
//! `agent.dial_back` / `agent.splice` (+ `agent.enroll` / `agent.renew`) spans and
//! ties them to the platform trace by the `sessionlayer.session_id` it already
//! holds — it does NOT add `traceparent` to the frozen wire or the SLDB1 token, and
//! it NEVER puts SSH plaintext, keys, tokens, OTPs, or recording bytes in a span,
//! attribute, or event. Spans carry IDs, enums, counts, and durations only.
//!
//! The OTLP tonic exporter must be built inside a tokio runtime (it binds its gRPC
//! channel to that runtime's reactor). The subscriber, however, is installed early
//! — before the hardened main runtime — so startup logs (hardening, non-root
//! refusal) are captured. So when export is enabled we build the provider on a
//! small, dedicated telemetry runtime held by the returned [`Guard`].

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Enables the OTLP exporter when set to a non-empty collector endpoint. Unset ⇒
/// exporter off, only the local subscriber runs (OTEL-CONTRACT §6).
const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
/// Overrides the reported `service.name`. Defaults to `sessionlayer-agent`.
const SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";
const DEFAULT_SERVICE_NAME: &str = "sessionlayer-agent";

/// The OTLP collector endpoint the exporter would target, if configured. Exposed so
/// the Tier-0 egress allow-list can permit exactly that destination and no other
/// (the exporter is the Agent's only non-CP/Gateway/loopback egress).
pub fn otlp_endpoint() -> Option<String> {
    std::env::var(OTLP_ENDPOINT_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// Holds the OTLP tracer provider + its dedicated runtime (if export is enabled) so
/// buffered spans are flushed on process exit. A no-op when export is off.
#[must_use = "hold the guard until shutdown so buffered spans are flushed"]
pub struct Guard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    // Dropped after `provider` (declaration order): flush, then tear down the
    // runtime the exporter's gRPC channel is bound to.
    _runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Best-effort flush; a collector that is down must not hang shutdown.
            let _ = provider.shutdown();
        }
    }
}

/// Initialise the global `tracing` subscriber, plus the OTLP exporter layer when
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
///
/// Filter precedence: the explicit `filter` argument (e.g. `--log`), then
/// `RUST_LOG`, then `info`. `try_init` makes a second call (integration tests
/// sharing a process) a harmless no-op.
pub fn init(filter: Option<&str>) -> Guard {
    let env_filter = match filter {
        Some(f) => EnvFilter::new(f),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };
    let fmt_layer = fmt::layer().with_target(true);

    // `Option<Layer>` is itself a `Layer`, so the OTLP layer composes in only when
    // the exporter is configured; otherwise the subscriber is exactly as before.
    let (otel_layer, provider, runtime) = match otlp_pipeline() {
        Some((layer, provider, runtime)) => (Some(layer), Some(provider), Some(runtime)),
        None => (None, None, None),
    };

    // The OTLP layer is added first so its `S` is the bare `Registry` (it is pinned
    // to that in `OtelLayer`); `EnvFilter` is a global per-registry filter so its
    // position does not change what it filters.
    let _ = tracing_subscriber::registry()
        .with(otel_layer)
        .with(env_filter)
        .with(fmt_layer)
        .try_init();

    Guard {
        provider,
        _runtime: runtime,
    }
}

type OtelLayer = tracing_opentelemetry::OpenTelemetryLayer<
    tracing_subscriber::Registry,
    opentelemetry_sdk::trace::Tracer,
>;

/// Build the OTLP tracer + the `tracing` bridge layer + the dedicated runtime its
/// gRPC channel binds to, or `None` when the exporter is disabled or cannot be
/// built. A build failure degrades to local-only logging (a missing collector must
/// never stop the Agent) — it is logged, not fatal.
fn otlp_pipeline() -> Option<(
    OtelLayer,
    opentelemetry_sdk::trace::SdkTracerProvider,
    tokio::runtime::Runtime,
)> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;

    let endpoint = otlp_endpoint()?;
    let service_name = std::env::var(SERVICE_NAME_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());

    // A tiny runtime dedicated to export: the tonic channel binds its reactor here,
    // and the batch processor's own thread drives exports against it. Kept separate
    // from the main runtime, which is built later (after hardening).
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .thread_name("otlp-export")
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            tracing::warn!(error = %err, "could not start the OTLP export runtime — local logging only");
            return None;
        }
    };
    let _enter = runtime.enter();

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
    {
        Ok(e) => e,
        Err(err) => {
            // Never fail closed on telemetry: the exporter is observability, not a
            // security control. Fall back to local logging.
            tracing::warn!(error = %err, "OTLP exporter unavailable — continuing with local logging only");
            return None;
        }
    };

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name)
        .build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    let tracer = provider.tracer(DEFAULT_SERVICE_NAME);
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    drop(_enter);
    Some((layer, provider, runtime))
}
