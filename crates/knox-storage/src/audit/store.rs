use crate::audit::{AuditStore, DbAuditEvent};
use async_trait::async_trait;
use knox_common::audit::{AuditEvent, AuditEventFilter, StoredAuditEvent};
use knox_common::error::RepositoryError;
use sqlx::PgPool;
use tracing::instrument;

#[derive(Clone)]
pub struct PgAuditStore {
    pool: PgPool,
}

impl PgAuditStore {
    #[instrument(skip(pool))]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditStore for PgAuditStore {
    #[instrument(skip(self, event))]
    async fn insert(&self, event: &AuditEvent) -> Result<(), RepositoryError> {
        sqlx::query!(
            r#"
            INSERT INTO audit_events (
                tenant_id, occurred_at, event_type, actor_type, actor_id,
                target_type, target_id, outcome, ip, user_agent,
                correlation_id, details
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            event.tenant_id,
            event.occurred_at,
            event.event_type.as_str(),
            event.actor.type_str(),
            event.actor.id(),
            event.target_type.as_deref(),
            event.target_id.as_deref(),
            event.outcome.as_str(),
            event.context.ip.as_deref(),
            event.context.user_agent.as_deref(),
            event.context.correlation_id.as_deref(),
            event.details,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn list(
        &self,
        filter: &AuditEventFilter,
    ) -> Result<Vec<StoredAuditEvent>, RepositoryError> {
        let (cursor_at, cursor_id) = match filter.cursor {
            Some((at, id)) => (Some(at), Some(id)),
            None => (None, None),
        };

        let rows = sqlx::query_as!(
            DbAuditEvent,
            r#"
            SELECT
                id, tenant_id, occurred_at, event_type, actor_type, actor_id,
                target_type, target_id, outcome, ip, user_agent,
                correlation_id, details
            FROM audit_events
            WHERE tenant_id = $1
              AND ($2::timestamptz IS NULL OR occurred_at >= $2)
              AND ($3::timestamptz IS NULL OR occurred_at <= $3)
              AND ($4::text IS NULL OR event_type = $4)
              AND ($5::uuid IS NULL OR actor_id = $5)
              AND ($6::text IS NULL OR outcome = $6)
              AND ($7::timestamptz IS NULL OR (occurred_at, id) < ($7, $8))
            ORDER BY occurred_at DESC, id DESC
            LIMIT $9
            "#,
            filter.tenant_id,
            filter.from,
            filter.to,
            filter.event_type.as_deref(),
            filter.actor_id,
            filter.outcome.as_deref(),
            cursor_at,
            cursor_id,
            filter.limit as i64,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }
}
