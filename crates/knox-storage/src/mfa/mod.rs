pub mod cache;
pub mod repository;
pub mod store;

use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::mfa::{MfaMethod, MfaMethodKind, NewMfaMethod};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct DbMfaMethod {
    id: Uuid,
    tenant_id: Uuid,
    identity_id: Uuid,
    method: MfaMethodKind,
    secret_enc: Option<Vec<u8>>,
    public_data: serde_json::Value,
    last_used_step: Option<i64>,
    verified_at: Option<OffsetDateTime>,
    last_used_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<DbMfaMethod> for MfaMethod {
    fn from(db: DbMfaMethod) -> Self {
        MfaMethod {
            id: db.id,
            tenant_id: db.tenant_id,
            identity_id: db.identity_id,
            method: db.method,
            secret_enc: db.secret_enc,
            public_data: db.public_data,
            last_used_step: db.last_used_step,
            verified_at: db.verified_at,
            last_used_at: db.last_used_at,
            created_at: db.created_at,
            updated_at: db.updated_at,
        }
    }
}

#[async_trait]
pub trait MfaStore: Send + Sync {
    async fn create_method(&self, method: &NewMfaMethod) -> Result<MfaMethod, RepositoryError>;
    async fn get_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<Option<MfaMethod>, RepositoryError>;
    async fn get_method_by_kind(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        kind: MfaMethodKind,
    ) -> Result<Option<MfaMethod>, RepositoryError>;
    async fn list_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethod>, RepositoryError>;
    async fn list_verified_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethod>, RepositoryError>;
    async fn mark_verified(
        &self,
        tenant_id: Uuid,
        method_id: Uuid,
    ) -> Result<MfaMethod, RepositoryError>;
    async fn delete_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<(), RepositoryError>;
    async fn claim_totp_step(
        &self,
        tenant_id: Uuid,
        method_id: Uuid,
        step: i64,
    ) -> Result<bool, RepositoryError>;
    async fn replace_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code_hashes: &[String],
    ) -> Result<(), RepositoryError>;
    async fn consume_backup_code(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, RepositoryError>;
    async fn count_unused_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<u64, RepositoryError>;
    async fn delete_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), RepositoryError>;
}

#[async_trait]
pub trait MfaCache: Send + Sync {
    async fn get_verified_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Option<Vec<MfaMethod>>, RepositoryError>;
    async fn set_verified_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        methods: &[MfaMethod],
    ) -> Result<(), RepositoryError>;
    async fn invalidate(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), RepositoryError>;
}
