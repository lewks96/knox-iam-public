use crate::error::RepositoryError;
use crate::identity::Status;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// What a pool is for.
///
/// The distinction is load-bearing rather than descriptive: the management API
/// is reachable only by tokens minted for a `Staff` pool, so an end user cannot
/// hold a console session however their tenant's clients are configured.
///
/// Immutable once set. A pool's kind is baked into every token minted through
/// clients bound to it, so flipping it would retroactively change what those
/// tokens mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "pool_kind", rename_all = "lowercase")
)]
#[serde(rename_all = "lowercase")]
pub enum PoolKind {
    /// Administrative identities: the people who use the Knox console.
    /// Exactly one per tenant, provisioned with the tenant.
    Staff,
    /// A tenant's own application end users. The expected home of almost every
    /// identity on the platform.
    Customer,
}

/// A directory of identities inside a tenant.
///
/// Identities are unique per pool, not per tenant, so the same email can belong
/// to a tenant's admin and to an unrelated end user of that tenant's app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPool {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub slug: String,
    pub name: String,
    pub kind: PoolKind,
    pub description: Option<String>,
    pub config: serde_json::Value,
    pub status: Status,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct CreatePool {
    pub tenant_id: Uuid,
    pub slug: String,
    pub name: String,
    pub kind: PoolKind,
    pub description: Option<String>,
}

#[async_trait]
pub trait PoolRepository: Send + Sync {
    async fn create(&self, pool: &CreatePool) -> Result<IdentityPool, RepositoryError>;
    async fn get(&self, id: Uuid) -> Result<Option<IdentityPool>, RepositoryError>;
    /// Scoped by tenant so a pool id from one tenant can never resolve against
    /// another — the composite FK guarantees the pair is consistent.
    async fn get_in_tenant(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<IdentityPool>, RepositoryError>;
    async fn get_by_slug(
        &self,
        tenant_id: Uuid,
        slug: &str,
    ) -> Result<Option<IdentityPool>, RepositoryError>;
    /// The tenant's single staff pool — the one the console binds to.
    async fn get_staff_pool(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<IdentityPool>, RepositoryError>;
    async fn list(&self, tenant_id: Uuid) -> Result<Vec<IdentityPool>, RepositoryError>;
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
}
