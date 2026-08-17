use axum::{extract::Request, middleware::Next, response::Response};
use opentelemetry::trace::TraceContextExt;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use opentelemetry::propagation::Extractor;

pub struct HeaderExtractor<'a>(pub &'a axum::http::HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

pub async fn inject_correlation_id(req: Request, next: Next) -> Response {
    // 1. Grab the trace ID from the active span (which was created by OtelTracingLayer)
    let trace_id = tracing::Span::current()
        .context()
        .span()
        .span_context()
        .trace_id()
        .to_string();

    // 2. Run the handler (the happy path)
    let mut response = next.run(req).await;

    // 3. If we have a valid trace ID, slap it onto the outgoing response headers
    if trace_id != "00000000000000000000000000000000"
        && let Ok(header_val) = axum::http::HeaderValue::from_str(&trace_id)
    {
        response
            .headers_mut()
            .insert("x-correlation-id", header_val);
    }

    response
}
