use knox_common::audit::{AuditEvent, AuditRepository};
use opentelemetry::trace::TraceContextExt;
use tokio::sync::mpsc;
use tracing::{Level, error, event, info, instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

const ZERO_TRACE_ID: &str = "00000000000000000000000000000000";

pub const DEFAULT_AUDIT_BUFFER_SIZE: usize = 1024;

/// Records tenant audit events. `record()` is synchronous and infallible:
/// it emits a structured tracing event (which the OTel bridge exports with
/// the caller's trace context) and queues the event for the background
/// writer. Auditing must never fail or slow down the operation it describes.
///
/// Non-generic on purpose: the repository generic lives only in
/// [`run_audit_writer`], so services holding an `AuditService` gain no new
/// type parameters.
#[derive(Clone)]
pub struct AuditService {
    tx: mpsc::Sender<AuditEvent>,
}

impl AuditService {
    /// Returns the service plus the receiver to hand to [`run_audit_writer`].
    pub fn new(buffer: usize) -> (Self, mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = mpsc::channel(buffer);
        (Self { tx }, rx)
    }

    pub fn record(&self, mut event: AuditEvent) {
        // Fill the correlation id at emission time: record() runs in the
        // caller's task inside the request span, where the OTel trace id
        // reliably resolves (extractors run too early in the tower stack).
        if event.context.correlation_id.is_none() {
            let trace_id = tracing::Span::current()
                .context()
                .span()
                .span_context()
                .trace_id()
                .to_string();
            if trace_id != ZERO_TRACE_ID {
                event.context.correlation_id = Some(trace_id);
            }
        }

        // Emitted here - in the caller's task, inside the request span - so
        // the OpenTelemetry bridge attaches the trace context. Emitting from
        // the writer task would orphan the exported record from its trace.
        // Braced form: `target:` + dotted field names is ambiguous for the
        // shorthand macros when tracing's `log` feature is enabled.
        event!(
            target: "knox::audit",
            Level::INFO,
            {
                audit.tenant_id = %event.tenant_id,
                audit.event_type = event.event_type.as_str(),
                audit.actor_type = event.actor.type_str(),
                audit.actor_id = ?event.actor.id(),
                audit.target_type = event.target_type.as_deref(),
                audit.target_id = event.target_id.as_deref(),
                audit.outcome = event.outcome.as_str(),
                audit.ip = event.context.ip.as_deref(),
                audit.correlation_id = event.context.correlation_id.as_deref(),
                audit.details = %event.details,
            },
            "audit event"
        );

        if let Err(e) = self.tx.try_send(event) {
            // Deliberately non-fatal: the tracing emission above already
            // reached the OTel pipeline, so the event is not fully lost.
            error!("Audit event dropped (buffer full or writer gone): {}", e);
        }
    }
}

/// Drains the audit channel into the repository; spawn once at startup.
/// A single writer caps audit persistence at one DB connection and keeps
/// inserts off the request hot path.
#[instrument(skip_all)]
pub async fn run_audit_writer<R: AuditRepository>(repo: R, mut rx: mpsc::Receiver<AuditEvent>) {
    while let Some(event) = rx.recv().await {
        if let Err(e) = repo.insert(&event).await {
            error!(
                "Failed to persist audit event '{}' for tenant {}: {}",
                event.event_type.as_str(),
                event.tenant_id,
                e
            );
        }
    }
    info!("Audit writer stopped: channel closed");
}
