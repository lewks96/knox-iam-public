use knox_common::audit::{
    AuditActor, AuditContext, AuditEvent, AuditEventFilter, AuditEventType, AuditOutcome,
    AuditRepository,
};
use knox_common::tenant::TenantRepository;
use knox_storage::audit::repository::KnoxAuditRepository;
use knox_storage::audit::store::PgAuditStore;
use knox_storage::tenant::cache::RedisTenantCache;
use knox_storage::tenant::repository::KnoxTenantRepository;
use knox_storage::tenant::store::PgTenantStore;
use redis::Client;
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use std::env;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

async fn setup() -> (impl AuditRepository, impl TenantRepository) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://admin:password@localhost:5432/knox".to_string());
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    let client = Client::open(redis_url).unwrap();
    let manager = client.get_connection_manager().await.unwrap();

    let tenant_repo = KnoxTenantRepository::new(
        PgTenantStore::new(pool.clone()),
        RedisTenantCache::new(manager),
    );

    let audit_repo = KnoxAuditRepository::new(PgAuditStore::new(pool));

    (audit_repo, tenant_repo)
}

async fn create_tenant(tenant_repo: &impl TenantRepository) -> Uuid {
    let suffix = Uuid::new_v4();
    tenant_repo
        .create(
            &format!("Audit Test Corp {}", suffix),
            &format!("audit-test-{}", suffix),
            &format!("https://audit-test-{}.example.test", suffix),
            None,
            false,
        )
        .await
        .expect("Failed to create tenant")
        .id
}

fn make_event(
    tenant_id: Uuid,
    event_type: AuditEventType,
    actor: AuditActor,
    outcome: AuditOutcome,
    at: OffsetDateTime,
) -> AuditEvent {
    let mut event = AuditEvent::new(
        tenant_id,
        event_type,
        actor,
        outcome,
        AuditContext {
            ip: Some("10.1.2.3".into()),
            user_agent: Some("integration-test".into()),
            correlation_id: Some("cid-123".into()),
        },
    )
    .with_target("identity", Uuid::new_v4().to_string());
    event.occurred_at = at;
    event
}

fn base_filter(tenant_id: Uuid) -> AuditEventFilter {
    AuditEventFilter {
        tenant_id,
        from: None,
        to: None,
        event_type: None,
        actor_id: None,
        outcome: None,
        limit: 100,
        cursor: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_insert_and_list_newest_first() {
    let (audit_repo, tenant_repo) = setup().await;
    let tenant_id = create_tenant(&tenant_repo).await;
    let now = OffsetDateTime::now_utc();

    for i in 0..3 {
        audit_repo
            .insert(&make_event(
                tenant_id,
                AuditEventType::AuthLogin,
                AuditActor::Anonymous,
                AuditOutcome::Failure,
                now - Duration::minutes(i),
            ))
            .await
            .expect("insert failed");
    }

    let events = audit_repo.list(&base_filter(tenant_id)).await.unwrap();
    assert_eq!(events.len(), 3);
    assert!(
        events
            .windows(2)
            .all(|w| w[0].occurred_at >= w[1].occurred_at),
        "Events must be newest-first"
    );
    assert_eq!(events[0].event_type, "auth.login");
    assert_eq!(events[0].outcome, "failure");
    assert_eq!(events[0].actor_type, "anonymous");
    assert_eq!(events[0].ip.as_deref(), Some("10.1.2.3"));
    assert_eq!(events[0].correlation_id.as_deref(), Some("cid-123"));
}

#[tokio::test]
#[serial]
async fn test_filters() {
    let (audit_repo, tenant_repo) = setup().await;
    let tenant_id = create_tenant(&tenant_repo).await;
    let actor_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    audit_repo
        .insert(&make_event(
            tenant_id,
            AuditEventType::AuthLogin,
            AuditActor::Identity(actor_id),
            AuditOutcome::Success,
            now,
        ))
        .await
        .unwrap();
    audit_repo
        .insert(&make_event(
            tenant_id,
            AuditEventType::TokenIssued,
            AuditActor::Client(Uuid::new_v4()),
            AuditOutcome::Success,
            now - Duration::hours(2),
        ))
        .await
        .unwrap();
    audit_repo
        .insert(&make_event(
            tenant_id,
            AuditEventType::AuthLogin,
            AuditActor::Anonymous,
            AuditOutcome::Failure,
            now - Duration::hours(4),
        ))
        .await
        .unwrap();

    // event_type filter
    let mut filter = base_filter(tenant_id);
    filter.event_type = Some("token.issued".into());
    let events = audit_repo.list(&filter).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "token.issued");

    // outcome filter
    let mut filter = base_filter(tenant_id);
    filter.outcome = Some("failure".into());
    let events = audit_repo.list(&filter).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "failure");

    // actor filter
    let mut filter = base_filter(tenant_id);
    filter.actor_id = Some(actor_id);
    let events = audit_repo.list(&filter).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor_id, Some(actor_id));

    // time window: only the middle event
    let mut filter = base_filter(tenant_id);
    filter.from = Some(now - Duration::hours(3));
    filter.to = Some(now - Duration::hours(1));
    let events = audit_repo.list(&filter).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "token.issued");
}

#[tokio::test]
#[serial]
async fn test_cursor_pagination_no_gaps_or_overlap() {
    let (audit_repo, tenant_repo) = setup().await;
    let tenant_id = create_tenant(&tenant_repo).await;
    let now = OffsetDateTime::now_utc();

    for i in 0..7 {
        audit_repo
            .insert(&make_event(
                tenant_id,
                AuditEventType::AuthLogin,
                AuditActor::Anonymous,
                AuditOutcome::Failure,
                now - Duration::seconds(i * 10),
            ))
            .await
            .unwrap();
    }

    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let mut filter = base_filter(tenant_id);
        filter.limit = 3;
        filter.cursor = cursor;
        let page = audit_repo.list(&filter).await.unwrap();
        if page.is_empty() {
            break;
        }
        cursor = page.last().map(|e| (e.occurred_at, e.id));
        let full_page = page.len() == 3;
        seen.extend(page.into_iter().map(|e| e.id));
        if !full_page {
            break;
        }
    }

    assert_eq!(seen.len(), 7, "Pagination must cover every event");
    let unique: std::collections::HashSet<&Uuid> = seen.iter().collect();
    assert_eq!(unique.len(), 7, "Pagination must not repeat events");
}

#[tokio::test]
#[serial]
async fn test_tenant_isolation() {
    let (audit_repo, tenant_repo) = setup().await;
    let tenant_a = create_tenant(&tenant_repo).await;
    let tenant_b = create_tenant(&tenant_repo).await;

    audit_repo
        .insert(&make_event(
            tenant_a,
            AuditEventType::AuthLogin,
            AuditActor::Anonymous,
            AuditOutcome::Failure,
            OffsetDateTime::now_utc(),
        ))
        .await
        .unwrap();

    let events_b = audit_repo.list(&base_filter(tenant_b)).await.unwrap();
    assert!(
        events_b.is_empty(),
        "Tenant B must never see tenant A's events"
    );
}
