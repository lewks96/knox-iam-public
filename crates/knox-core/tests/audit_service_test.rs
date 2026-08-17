use async_trait::async_trait;
use knox_common::audit::{
    AuditActor, AuditContext, AuditEvent, AuditEventFilter, AuditEventType, AuditOutcome,
    AuditRepository, StoredAuditEvent,
};
use knox_common::error::RepositoryError;
use knox_core::audit::{AuditService, run_audit_writer};
use mockall::mock;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};
use uuid::Uuid;

mock! {
    pub AuditRepo {}
    #[async_trait]
    impl AuditRepository for AuditRepo {
        async fn insert(&self, event: &AuditEvent) -> Result<(), RepositoryError>;
        async fn list(&self, filter: &AuditEventFilter) -> Result<Vec<StoredAuditEvent>, RepositoryError>;
    }
}

fn make_event(tenant_id: Uuid) -> AuditEvent {
    AuditEvent::new(
        tenant_id,
        AuditEventType::AuthLogin,
        AuditActor::Anonymous,
        AuditOutcome::Failure,
        AuditContext {
            ip: Some("10.0.0.1".into()),
            user_agent: Some("test".into()),
            correlation_id: Some("abc123".into()),
        },
    )
}

// ---------------------------------------------------------------------------
// Channel behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_record_delivers_event_to_channel() {
    let tenant_id = Uuid::new_v4();
    let (service, mut rx) = AuditService::new(8);

    service.record(make_event(tenant_id));

    let received = rx.recv().await.expect("Event should be queued");
    assert_eq!(received.tenant_id, tenant_id);
    assert_eq!(received.event_type, AuditEventType::AuthLogin);
    assert_eq!(received.outcome, AuditOutcome::Failure);
    assert_eq!(received.context.ip.as_deref(), Some("10.0.0.1"));
}

#[tokio::test]
async fn test_record_on_full_buffer_drops_without_panicking() {
    let tenant_id = Uuid::new_v4();
    let (service, mut rx) = AuditService::new(1);

    // Second and third record hit a full channel - must not panic or block.
    service.record(make_event(tenant_id));
    service.record(make_event(tenant_id));
    service.record(make_event(tenant_id));

    assert!(rx.recv().await.is_some());
    assert!(
        rx.try_recv().is_err(),
        "Overflow events should have been dropped"
    );
}

#[tokio::test]
async fn test_record_with_closed_writer_is_non_fatal() {
    let tenant_id = Uuid::new_v4();
    let (service, rx) = AuditService::new(4);
    drop(rx); // writer gone

    // Must not panic.
    service.record(make_event(tenant_id));
}

// ---------------------------------------------------------------------------
// Writer behavior
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_writer_persists_events() {
    let tenant_id = Uuid::new_v4();
    let (service, rx) = AuditService::new(8);

    let mut repo = MockAuditRepo::new();
    repo.expect_insert()
        .times(2)
        .withf(move |e: &AuditEvent| e.tenant_id == tenant_id)
        .returning(|_| Ok(()));

    service.record(make_event(tenant_id));
    service.record(make_event(tenant_id));
    drop(service); // close the channel so the writer exits

    run_audit_writer(repo, rx).await;
}

#[tokio::test]
async fn test_writer_continues_after_repo_errors() {
    let tenant_id = Uuid::new_v4();
    let (service, rx) = AuditService::new(8);

    let mut repo = MockAuditRepo::new();
    // Every insert fails; the writer must still drain all events and exit
    // cleanly rather than dying on the first error.
    repo.expect_insert()
        .times(3)
        .returning(|_| Err(RepositoryError::Database("db down".into())));

    for _ in 0..3 {
        service.record(make_event(tenant_id));
    }
    drop(service);

    run_audit_writer(repo, rx).await;
}

// ---------------------------------------------------------------------------
// Tracing emission (the OTel-facing sink)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FieldCollector(HashMap<String, String>);

impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{:?}", value));
    }
}

struct CaptureLayer {
    events: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() == "knox::audit" {
            let mut collector = FieldCollector::default();
            event.record(&mut collector);
            self.events.lock().unwrap().push(collector.0);
        }
    }
}

#[tokio::test]
async fn test_record_emits_tracing_event_for_otel() {
    let tenant_id = Uuid::new_v4();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = Registry::default().with(CaptureLayer {
        events: captured.clone(),
    });

    let (service, mut rx) = AuditService::new(8);
    tracing::subscriber::with_default(subscriber, || {
        service.record(make_event(tenant_id));
    });

    let events = captured.lock().unwrap();
    assert_eq!(events.len(), 1, "One knox::audit event should be emitted");
    let fields = &events[0];
    assert_eq!(
        fields.get("audit.event_type").map(String::as_str),
        Some("\"auth.login\"")
    );
    assert_eq!(
        fields.get("audit.outcome").map(String::as_str),
        Some("\"failure\"")
    );
    assert_eq!(
        fields.get("audit.tenant_id").map(String::as_str),
        Some(format!("{}", tenant_id).as_str())
    );

    // The channel sink got the same event.
    assert!(rx.recv().await.is_some());
}
