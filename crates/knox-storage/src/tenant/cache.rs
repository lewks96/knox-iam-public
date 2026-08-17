use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::tenant::Tenant;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::instrument;
use uuid::Uuid;

const CACHE_TTL: u64 = 86400; // 24 Hours (Tenants change rarely)

#[async_trait]
pub trait TenantCache: Send + Sync {
    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError>;
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError>;
    async fn set(&self, tenant: &Tenant) -> Result<(), RepositoryError>;
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
}

#[derive(Clone)]
pub struct RedisTenantCache {
    manager: ConnectionManager,
}

impl RedisTenantCache {
    #[instrument(skip(manager))]
    pub fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }

    fn key(&self, id: Uuid) -> String {
        // v2: the cached shape gained `issuer`; older entries would fail to
        // deserialise as "cache corrupt" rather than falling back to Postgres.
        format!("tenant:v2:{}", id)
    }

    fn slug_key(&self, slug: &str) -> String {
        format!("tenant:v2:slug:{}", slug)
    }
}

#[async_trait]
impl TenantCache for RedisTenantCache {
    #[instrument(skip(self))]
    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.key(id);

        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| RepositoryError::Database(format!("Cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self))]
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.slug_key(slug);

        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| RepositoryError::Database(format!("Cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self))]
    async fn set(&self, tenant: &Tenant) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let json =
            serde_json::to_string(tenant).map_err(|e| RepositoryError::Database(e.to_string()))?;

        // Cache under both UUID key and slug key
        let _: () = conn
            .set_ex(&self.key(tenant.id), &json, CACHE_TTL)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&self.slug_key(&tenant.slug), &json, CACHE_TTL)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError> {
        // We need the slug to also delete the slug key — fetch it from UUID key first
        if let Ok(Some(tenant)) = self.get(id).await {
            let mut conn = self.manager.clone();
            let _: () = conn
                .del(&self.slug_key(&tenant.slug))
                .await
                .map_err(|e| RepositoryError::Database(e.to_string()))?;
        }

        let mut conn = self.manager.clone();
        let _: () = conn
            .del(&self.key(id))
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }
}
