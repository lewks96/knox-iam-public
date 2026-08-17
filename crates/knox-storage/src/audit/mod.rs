pub mod repository;
pub mod store;

use async_trait::async_trait;
use knox_common::audit::{AuditEvent, AuditEventFilter, StoredAuditEvent};
use knox_common::error::RepositoryError;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct DbAuditEvent {
    id: Uuid,
    tenant_id: Uuid,
    occurred_at: OffsetDateTime,
    event_type: String,
    actor_type: String,
    actor_id: Option<Uuid>,
    target_type: Option<String>,
    target_id: Option<String>,
    outcome: String,
    ip: Option<String>,
    user_agent: Option<String>,
    correlation_id: Option<String>,
    details: serde_json::Value,
}

impl From<DbAuditEvent> for StoredAuditEvent {
    fn from(db: DbAuditEvent) -> Self {
        StoredAuditEvent {
            id: db.id,
            tenant_id: db.tenant_id,
            occurred_at: db.occurred_at,
            event_type: db.event_type,
            actor_type: db.actor_type,
            actor_id: db.actor_id,
            target_type: db.target_type,
            target_id: db.target_id,
            outcome: db.outcome,
            ip: db.ip,
            user_agent: db.user_agent,
            correlation_id: db.correlation_id,
            details: db.details,
        }
    }
}

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn insert(&self, event: &AuditEvent) -> Result<(), RepositoryError>;
    async fn list(
        &self,
        filter: &AuditEventFilter,
    ) -> Result<Vec<StoredAuditEvent>, RepositoryError>;
}
