//! Structured logging (`tracing`) + optional OpenTelemetry export.

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";
const DEFAULT_SERVICE_NAME: &str = "sessionlayer-agent";

pub fn otlp_endpoint() -> Option<String> {
    std::env::var(OTLP_ENDPOINT_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
}

#[must_use = "hold the guard until shutdown so buffered spans are flushed"]
pub struct Guard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    _runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

pub fn init(filter: Option<&str>) -> Guard {
    let env_filter = match filter {
        Some(f) => EnvFilter::new(f),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };
    let fmt_layer = fmt::layer().with_target(true);

    let (otel_layer, provider, runtime) = match otlp_pipeline() {
        Some((layer, provider, runtime)) => (Some(layer), Some(provider), Some(runtime)),
        None => (None, None, None),
    };

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
            // The exporter is observability, not a security control.
            // Fall back to local logging.
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
