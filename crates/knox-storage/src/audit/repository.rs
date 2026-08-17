use crate::audit::AuditStore;
use async_trait::async_trait;
use knox_common::audit::{AuditEvent, AuditEventFilter, AuditRepository, StoredAuditEvent};
use knox_common::error::RepositoryError;
use tracing::instrument;

/// Append-only event log with time-range reads: nothing benefits from a
/// cache, so this is a straight passthrough to the store.
#[derive(Clone)]
pub struct KnoxAuditRepository<S> {
    store: S,
}

impl<S> KnoxAuditRepository<S>
where
    S: AuditStore + Send + Sync,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

#[async_trait]
impl<S> AuditRepository for KnoxAuditRepository<S>
where
    S: AuditStore + Send + Sync,
{
    #[instrument(skip(self, event))]
    async fn insert(&self, event: &AuditEvent) -> Result<(), RepositoryError> {
        self.store.insert(event).await
    }

    #[instrument(skip(self))]
    async fn list(
        &self,
        filter: &AuditEventFilter,
    ) -> Result<Vec<StoredAuditEvent>, RepositoryError> {
        self.store.list(filter).await
    }
}
