use crate::key::cache::KeyCache;
use crate::key::store::KeyStore;
use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::key::{CreateKeyParams, KeyRepository, KeyState, TenantKey};
use tracing::{debug, error, instrument};
use uuid::Uuid;

#[derive(Clone)]
pub struct KnoxKeyRepository<S, C> {
    store: S,
    cache: C,
}

impl<S, C> KnoxKeyRepository<S, C>
where
    S: KeyStore + Send + Sync,
    C: KeyCache + Send + Sync,
{
    pub fn new(store: S, cache: C) -> Self {
        Self { store, cache }
    }
}

#[async_trait]
impl<S, C> KeyRepository for KnoxKeyRepository<S, C>
where
    S: KeyStore + Send + Sync,
    C: KeyCache + Send + Sync,
{
    #[instrument(skip(self, params))]
    async fn create(&self, params: CreateKeyParams) -> Result<TenantKey, RepositoryError> {
        let tenant_id = params.tenant_id;
        let key = self.store.create(params).await?;
        debug!("New key created: {} for tenant {}", key.id, key.tenant_id);

        // Cache the new key
        if let Err(e) = self.cache.set(&key).await {
            error!("Key cache set failed after creation: {}", e);
        }
        if let Err(e) = self.cache.set_by_kid(&key).await {
            error!("Key cache set_by_kid failed after creation: {}", e);
        }

        // Invalidate the JWKS and active key caches since we have a new key
        if let Err(e) = self.cache.delete_jwks(tenant_id).await {
            error!("Failed to invalidate JWKS cache: {}", e);
        }
        if let Err(e) = self.cache.delete_active_for_tenant(tenant_id).await {
            error!("Failed to invalidate active key cache: {}", e);
        }

        Ok(key)
    }

    #[instrument(skip(self))]
    async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError> {
        // Check cache first
        if let Some(cached) = self.cache.get(id).await? {
            debug!("Get key cache hit: {}", id);
            return Ok(Some(cached));
        }

        debug!("Get key cache miss, checking store: {}", id);
        let key = self.store.get(id).await?;

        // Populate cache on miss
        if let Some(ref k) = key {
            if let Err(e) = self.cache.set(k).await {
                error!("Key cache set failed after get: {}", e);
            }
        }

        Ok(key)
    }

    #[instrument(skip(self))]
    async fn get_by_kid(
        &self,
        tenant_id: Uuid,
        kid: &str,
    ) -> Result<Option<TenantKey>, RepositoryError> {
        // Check cache first
        if let Some(cached) = self.cache.get_by_kid(tenant_id, kid).await? {
            debug!(
                "Get key by kid cache hit: tenant={}, kid={}",
                tenant_id, kid
            );
            return Ok(Some(cached));
        }

        debug!(
            "Get key by kid cache miss, checking store: tenant={}, kid={}",
            tenant_id, kid
        );
        let key = self.store.get_by_kid(tenant_id, kid).await?;

        // Populate cache on miss
        if let Some(ref k) = key {
            if let Err(e) = self.cache.set_by_kid(k).await {
                error!("Key cache set_by_kid failed after get: {}", e);
            }
        }

        Ok(key)
    }

    #[instrument(skip(self))]
    async fn get_active_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantKey>, RepositoryError> {
        // Check cache first (short TTL for active keys due to rotation)
        if let Some(cached) = self.cache.get_active_for_tenant(tenant_id).await? {
            debug!("Get active key cache hit: tenant={}", tenant_id);
            return Ok(Some(cached));
        }

        debug!(
            "Get active key cache miss, checking store: tenant={}",
            tenant_id
        );
        let key = self.store.get_active_for_tenant(tenant_id).await?;

        // Populate cache on miss
        if let Some(ref k) = key {
            if let Err(e) = self.cache.set_active_for_tenant(k).await {
                error!("Active key cache set failed: {}", e);
            }
        }

        Ok(key)
    }

    #[instrument(skip(self))]
    async fn list_for_jwks(&self, tenant_id: Uuid) -> Result<Vec<TenantKey>, RepositoryError> {
        // Check cache first
        if let Some(cached) = self.cache.get_jwks(tenant_id).await? {
            debug!("JWKS cache hit: tenant={}", tenant_id);
            return Ok(cached);
        }

        debug!("JWKS cache miss, checking store: tenant={}", tenant_id);
        let keys = self.store.list_for_jwks(tenant_id).await?;

        // Populate cache on miss
        if let Err(e) = self.cache.set_jwks(tenant_id, &keys).await {
            error!("JWKS cache set failed: {}", e);
        }

        Ok(keys)
    }

    #[instrument(skip(self))]
    async fn list(
        &self,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<TenantKey>, u64), RepositoryError> {
        // List operations are not cached (pagination makes caching complex)
        debug!(
            "Listing keys: tenant={}, page={}, page_size={}",
            tenant_id, page, page_size
        );
        self.store.list(tenant_id, page, page_size).await
    }

    #[instrument(skip(self))]
    async fn update_state(
        &self,
        id: Uuid,
        new_state: KeyState,
    ) -> Result<TenantKey, RepositoryError> {
        debug!("Updating key state: id={}, new_state={:?}", id, new_state);
        let updated = self.store.update_state(id, new_state).await?;

        // Update caches
        if let Err(e) = self.cache.set(&updated).await {
            error!("Key cache update failed: {}", e);
            let _ = self.cache.delete(id).await;
        }
        if let Err(e) = self.cache.set_by_kid(&updated).await {
            error!("Key cache set_by_kid update failed: {}", e);
            let _ = self
                .cache
                .delete_by_kid(updated.tenant_id, &updated.kid)
                .await;
        }

        // Invalidate tenant-level caches
        if let Err(e) = self.cache.delete_jwks(updated.tenant_id).await {
            error!("Failed to invalidate JWKS cache: {}", e);
        }
        if let Err(e) = self.cache.delete_active_for_tenant(updated.tenant_id).await {
            error!("Failed to invalidate active key cache: {}", e);
        }

        Ok(updated)
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError> {
        // Get the key first to know the tenant_id and kid for cache invalidation
        let key = self.store.get(id).await?;

        debug!("Deleting key: {}", id);
        self.store.delete(id).await?;

        // Invalidate all related caches
        let _ = self.cache.delete(id).await;
        if let Some(k) = key {
            let _ = self.cache.delete_by_kid(k.tenant_id, &k.kid).await;
            let _ = self.cache.delete_jwks(k.tenant_id).await;
            let _ = self.cache.delete_active_for_tenant(k.tenant_id).await;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError> {
        debug!("Revoking all keys for tenant: {}", tenant_id);
        self.store.revoke_all_for_tenant(tenant_id).await?;

        // Invalidate all caches for the tenant
        if let Err(e) = self.cache.invalidate_all_for_tenant(tenant_id).await {
            error!("Failed to invalidate tenant caches: {}", e);
        }

        Ok(())
    }
}
