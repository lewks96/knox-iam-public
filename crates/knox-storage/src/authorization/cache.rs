use async_trait::async_trait;
use knox_common::error::RepositoryError;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::instrument;
use uuid::Uuid;

const AUTH_TTL: u64 = 300; // 5 Minutes (Auth perms should be fresher than User profile)

#[async_trait]
pub trait AuthorizationCache: Send + Sync {
    async fn get_permissions(
        &self,
        identity_id: Uuid,
    ) -> Result<Option<Vec<String>>, RepositoryError>;
    async fn set_permissions(
        &self,
        identity_id: Uuid,
        perms: &[String],
    ) -> Result<(), RepositoryError>;
    async fn invalidate(&self, identity_id: Uuid) -> Result<(), RepositoryError>;
}

#[derive(Clone)]
pub struct RedisAuthorizationCache {
    manager: ConnectionManager,
}

impl RedisAuthorizationCache {
    #[instrument(skip(manager))]
    pub fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }

    // Note: We might strictly need tenant_id here for keynames if we want full isolation,
    // but permissions are usually tied to the unique Identity ID anyway.
    #[instrument(skip(self))]
    fn key(&self, identity_id: Uuid) -> String {
        format!("auth:perms:{}", identity_id)
    }
}

#[async_trait]
impl AuthorizationCache for RedisAuthorizationCache {
    #[instrument(skip(self))]
    async fn get_permissions(
        &self,
        identity_id: Uuid,
    ) -> Result<Option<Vec<String>>, RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.key(identity_id);
        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => {
                serde_json::from_str(&json).map_err(|e| RepositoryError::Database(e.to_string()))
            }
            None => Ok(None),
        }
    }

    #[instrument(skip(self))]
    async fn set_permissions(
        &self,
        identity_id: Uuid,
        perms: &[String],
    ) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.key(identity_id);
        let json =
            serde_json::to_string(perms).map_err(|e| RepositoryError::Database(e.to_string()))?;
        let _: () = conn
            .set_ex(&key, json, AUTH_TTL)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn invalidate(&self, identity_id: Uuid) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.key(identity_id);
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }
}
