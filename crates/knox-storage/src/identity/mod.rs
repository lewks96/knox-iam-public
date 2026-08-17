pub mod cache;
pub mod repository;
pub mod store;

use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::identity::{Identity, IdentityFilter, IdentityKind, IdentityUpdates, Status};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct DbIdentity {
    id: Uuid,
    tenant_id: Uuid,
    pool_id: Uuid,
    kind: IdentityKind,
    username: String,
    email: Option<String>,
    password_hash: Option<String>,
    email_verified: bool,
    first_name: Option<String>,
    last_name: Option<String>,
    metadata: serde_json::Value,
    custom_attributes: serde_json::Value,
    status: Status,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<DbIdentity> for Identity {
    fn from(db: DbIdentity) -> Self {
        Identity {
            id: db.id,
            tenant_id: db.tenant_id,
            pool_id: db.pool_id,
            kind: db.kind,
            username: db.username,
            email: db.email,
            password_hash: db.password_hash,
            email_verified: db.email_verified,
            first_name: db.first_name,
            last_name: db.last_name,
            metadata: db.metadata,
            custom_attributes: db.custom_attributes,
            status: db.status,
            created_at: db.created_at,
            updated_at: db.updated_at,
        }
    }
}

#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn create(&self, identity: &Identity) -> Result<Identity, RepositoryError>;

    // We break "get" down into specific lookups for efficiency in SQL.
    // Every one is pool-scoped: an unscoped `WHERE id = $1` would let an admin
    // read across tenants by UUID, and an unscoped username lookup is ambiguous
    // now that uniqueness is per-pool.
    async fn get_by_id(&self, pool_id: Uuid, id: Uuid)
    -> Result<Option<Identity>, RepositoryError>;
    async fn get_by_email(
        &self,
        pool_id: Uuid,
        email: &str,
    ) -> Result<Option<Identity>, RepositoryError>;
    async fn get_by_username(
        &self,
        pool_id: Uuid,
        username: &str,
    ) -> Result<Option<Identity>, RepositoryError>;

    async fn update(
        &self,
        pool_id: Uuid,
        id: Uuid,
        updates: &IdentityUpdates,
    ) -> Result<Identity, RepositoryError>;
    async fn delete(&self, pool_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;

    async fn list(&self, filter: &IdentityFilter) -> Result<(Vec<Identity>, u64), RepositoryError>;
}

/// Caches only `id -> Identity`. Handle lookups (username/email) deliberately go
/// to Postgres — see the note on `RedisIdentityCache`.
#[async_trait]
pub trait IdentityCache: Send + Sync {
    async fn get_by_id(&self, pool_id: Uuid, id: Uuid)
    -> Result<Option<Identity>, RepositoryError>;
    async fn set(&self, identity: &Identity) -> Result<(), RepositoryError>;
    async fn delete(&self, pool_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
}
