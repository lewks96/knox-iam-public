use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::key::TenantKey;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::instrument;
use uuid::Uuid;

const JWKS_CACHE_TTL: u64 = 3600;

const ACTIVE_KEY_CACHE_TTL: u64 = 300;

const KEY_CACHE_TTL: u64 = 1800;

#[async_trait]
pub trait KeyCache: Send + Sync {
    async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
    async fn set(&self, key: &TenantKey) -> Result<(), RepositoryError>;
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
    async fn get_by_kid(
        &self,
        tenant_id: Uuid,
        kid: &str,
    ) -> Result<Option<TenantKey>, RepositoryError>;
    async fn set_by_kid(&self, key: &TenantKey) -> Result<(), RepositoryError>;
    async fn delete_by_kid(&self, tenant_id: Uuid, kid: &str) -> Result<(), RepositoryError>;
    async fn get_active_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantKey>, RepositoryError>;
    async fn set_active_for_tenant(&self, key: &TenantKey) -> Result<(), RepositoryError>;
    async fn delete_active_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
    async fn get_jwks(&self, tenant_id: Uuid) -> Result<Option<Vec<TenantKey>>, RepositoryError>;
    async fn set_jwks(&self, tenant_id: Uuid, keys: &[TenantKey]) -> Result<(), RepositoryError>;
    async fn delete_jwks(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
    async fn invalidate_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
}

#[derive(Clone)]
pub struct RedisKeyCache {
    manager: ConnectionManager,
}

impl RedisKeyCache {
    #[instrument(skip(manager))]
    pub fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }

    fn key_by_id(&self, id: Uuid) -> String {
        format!("key:id:{}", id)
    }

    fn key_by_kid(&self, tenant_id: Uuid, kid: &str) -> String {
        format!("key:tenant:{}:kid:{}", tenant_id, kid)
    }

    fn key_active(&self, tenant_id: Uuid) -> String {
        format!("key:tenant:{}:active", tenant_id)
    }

    fn key_jwks(&self, tenant_id: Uuid) -> String {
        format!("key:tenant:{}:jwks", tenant_id)
    }
}

#[async_trait]
impl KeyCache for RedisKeyCache {
    #[instrument(skip(self))]
    async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_by_id(id);

        let data: Option<String> = conn
            .get(&cache_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| RepositoryError::Database(format!("Cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self, key))]
    async fn set(&self, key: &TenantKey) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_by_id(key.id);
        let json =
            serde_json::to_string(key).map_err(|e| RepositoryError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&cache_key, json, KEY_CACHE_TTL)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_by_id(id);

        let _: () = conn
            .del(&cache_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_by_kid(
        &self,
        tenant_id: Uuid,
        kid: &str,
    ) -> Result<Option<TenantKey>, RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_by_kid(tenant_id, kid);

        let data: Option<String> = conn
            .get(&cache_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| RepositoryError::Database(format!("Cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self, key))]
    async fn set_by_kid(&self, key: &TenantKey) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_by_kid(key.tenant_id, &key.kid);
        let json =
            serde_json::to_string(key).map_err(|e| RepositoryError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&cache_key, json, KEY_CACHE_TTL)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_by_kid(&self, tenant_id: Uuid, kid: &str) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_by_kid(tenant_id, kid);

        let _: () = conn
            .del(&cache_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_active_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantKey>, RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_active(tenant_id);

        let data: Option<String> = conn
            .get(&cache_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| RepositoryError::Database(format!("Cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self, key))]
    async fn set_active_for_tenant(&self, key: &TenantKey) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_active(key.tenant_id);
        let json =
            serde_json::to_string(key).map_err(|e| RepositoryError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&cache_key, json, ACTIVE_KEY_CACHE_TTL)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_active_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_active(tenant_id);

        let _: () = conn
            .del(&cache_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_jwks(&self, tenant_id: Uuid) -> Result<Option<Vec<TenantKey>>, RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_jwks(tenant_id);

        let data: Option<String> = conn
            .get(&cache_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| RepositoryError::Database(format!("Cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self, keys))]
    async fn set_jwks(&self, tenant_id: Uuid, keys: &[TenantKey]) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_jwks(tenant_id);
        let json =
            serde_json::to_string(keys).map_err(|e| RepositoryError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&cache_key, json, JWKS_CACHE_TTL)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_jwks(&self, tenant_id: Uuid) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let cache_key = self.key_jwks(tenant_id);

        let _: () = conn
            .del(&cache_key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn invalidate_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError> {
        // Invalidate the JWKS cache and active key cache.
        // Individual key caches will expire naturally or be invalidated on access.
        let _ = self.delete_jwks(tenant_id).await;
        let _ = self.delete_active_for_tenant(tenant_id).await;
        Ok(())
    }
}
