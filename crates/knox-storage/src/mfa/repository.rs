use crate::mfa::{MfaCache, MfaStore};
use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::mfa::{MfaMethod, MfaMethodKind, MfaRepository, NewMfaMethod};
use tracing::{error, instrument};
use uuid::Uuid;

/// Cache-before-DB repository. Only the verified-methods lookup (the
/// per-login hot path) is cached; verification state changes (step claims,
/// backup code consumption) always hit the store because correctness depends
/// on their atomicity.
#[derive(Clone)]
pub struct KnoxMfaRepository<S, C> {
    store: S,
    cache: C,
}

impl<S, C> KnoxMfaRepository<S, C>
where
    S: MfaStore + Send + Sync,
    C: MfaCache + Send + Sync,
{
    pub fn new(store: S, cache: C) -> Self {
        Self { store, cache }
    }

    async fn invalidate_cache(&self, tenant_id: Uuid, identity_id: Uuid) {
        if let Err(e) = self.cache.invalidate(tenant_id, identity_id).await {
            error!(
                "MFA cache invalidation failed for identity '{}': {}",
                identity_id, e
            );
        }
    }
}

#[async_trait]
impl<S, C> MfaRepository for KnoxMfaRepository<S, C>
where
    S: MfaStore + Send + Sync,
    C: MfaCache + Send + Sync,
{
    #[instrument(skip(self, method))]
    async fn create_method(&self, method: &NewMfaMethod) -> Result<MfaMethod, RepositoryError> {
        let created = self.store.create_method(method).await?;
        self.invalidate_cache(method.tenant_id, method.identity_id)
            .await;
        Ok(created)
    }

    #[instrument(skip(self))]
    async fn get_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<Option<MfaMethod>, RepositoryError> {
        self.store
            .get_method(tenant_id, identity_id, method_id)
            .await
    }

    #[instrument(skip(self))]
    async fn get_method_by_kind(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        kind: MfaMethodKind,
    ) -> Result<Option<MfaMethod>, RepositoryError> {
        self.store
            .get_method_by_kind(tenant_id, identity_id, kind)
            .await
    }

    #[instrument(skip(self))]
    async fn list_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethod>, RepositoryError> {
        self.store.list_methods(tenant_id, identity_id).await
    }

    #[instrument(skip(self))]
    async fn list_verified_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethod>, RepositoryError> {
        match self
            .cache
            .get_verified_methods(tenant_id, identity_id)
            .await
        {
            Ok(Some(methods)) => return Ok(methods),
            Ok(None) => {}
            Err(e) => error!("MFA cache read failed: {}", e),
        }

        let methods = self
            .store
            .list_verified_methods(tenant_id, identity_id)
            .await?;

        if let Err(e) = self
            .cache
            .set_verified_methods(tenant_id, identity_id, &methods)
            .await
        {
            error!("MFA cache set failed: {}", e);
        }

        Ok(methods)
    }

    #[instrument(skip(self))]
    async fn mark_verified(
        &self,
        tenant_id: Uuid,
        method_id: Uuid,
    ) -> Result<MfaMethod, RepositoryError> {
        let updated = self.store.mark_verified(tenant_id, method_id).await?;
        self.invalidate_cache(tenant_id, updated.identity_id).await;
        Ok(updated)
    }

    #[instrument(skip(self))]
    async fn delete_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<(), RepositoryError> {
        self.store
            .delete_method(tenant_id, identity_id, method_id)
            .await?;
        self.invalidate_cache(tenant_id, identity_id).await;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn claim_totp_step(
        &self,
        tenant_id: Uuid,
        method_id: Uuid,
        step: i64,
    ) -> Result<bool, RepositoryError> {
        self.store.claim_totp_step(tenant_id, method_id, step).await
    }

    #[instrument(skip(self, code_hashes))]
    async fn replace_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code_hashes: &[String],
    ) -> Result<(), RepositoryError> {
        self.store
            .replace_backup_codes(tenant_id, identity_id, code_hashes)
            .await
    }

    #[instrument(skip(self, code_hash))]
    async fn consume_backup_code(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, RepositoryError> {
        self.store
            .consume_backup_code(tenant_id, identity_id, code_hash)
            .await
    }

    #[instrument(skip(self))]
    async fn count_unused_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<u64, RepositoryError> {
        self.store
            .count_unused_backup_codes(tenant_id, identity_id)
            .await
    }

    #[instrument(skip(self))]
    async fn delete_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), RepositoryError> {
        self.store.delete_backup_codes(tenant_id, identity_id).await
    }
}
