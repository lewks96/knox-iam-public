use async_trait::async_trait;
use knox_common::client::Client;
use knox_common::error::RepositoryError;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::instrument;
use uuid::Uuid;

const CACHE_TTL_SECONDS: u64 = 3600; // 1 Hour

#[async_trait]
pub trait ClientCache: Send + Sync {
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError>;
    async fn get_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Client>, RepositoryError>;
    async fn set(&self, client: &Client) -> Result<(), RepositoryError>;
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
}

#[derive(Clone)]
pub struct RedisClientCache {
    manager: ConnectionManager,
}

impl RedisClientCache {
    #[instrument(skip(manager))]
    pub fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }

    // Isolate by tenant to prevent cross-tenant cache poisoning
    #[instrument(skip(self))]
    fn key(&self, tenant_id: Uuid, id: Uuid) -> String {
        format!("t:{}:client:{}", tenant_id, id)
    }

    fn name_key(&self, tenant_id: Uuid, name: &str) -> String {
        format!("t:{}:client:name:{}", tenant_id, name)
    }
}

#[async_trait]
impl ClientCache for RedisClientCache {
    #[instrument(skip(self))]
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.key(tenant_id, id);

        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| RepositoryError::Database(format!("Client cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self))]
    async fn get_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Client>, RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.name_key(tenant_id, name);

        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| RepositoryError::Database(format!("Client cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self))]
    async fn set(&self, client: &Client) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let json =
            serde_json::to_string(client).map_err(|e| RepositoryError::Database(e.to_string()))?;

        // Cache under both UUID key and name key
        let _: () = conn
            .set_ex(
                &self.key(client.tenant_id, client.id),
                &json,
                CACHE_TTL_SECONDS,
            )
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(
                &self.name_key(client.tenant_id, &client.name),
                &json,
                CACHE_TTL_SECONDS,
            )
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError> {
        // Fetch name from UUID key first so we can evict the name key too
        if let Ok(Some(client)) = self.get(tenant_id, id).await {
            let mut conn = self.manager.clone();
            let _: () = conn
                .del(&self.name_key(tenant_id, &client.name))
                .await
                .map_err(|e| RepositoryError::Database(e.to_string()))?;
        }

        let mut conn = self.manager.clone();
        let _: () = conn
            .del(&self.key(tenant_id, id))
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }
}
