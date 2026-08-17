use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::token::{AuthCodeCache, AuthCodeContext};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::instrument;

#[derive(Clone)]
pub struct RedisAuthCodeCache {
    manager: ConnectionManager,
}

impl RedisAuthCodeCache {
    #[instrument(skip(manager))]
    pub fn new(manager: ConnectionManager) -> Self {
        Self { manager }
    }

    // The key format. Since the code is already a secure hash,
    // it's safe to use directly in the key name.
    #[instrument(skip(self))]
    fn key(&self, hashed_code: &str) -> String {
        format!("auth_code:{}", hashed_code)
    }
}

#[async_trait]
impl AuthCodeCache for RedisAuthCodeCache {
    #[instrument(skip(self, value))]
    async fn set_value(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let _: () = conn
            .set_ex(key, value, ttl_seconds)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_value(&self, key: &str) -> Result<Option<String>, RepositoryError> {
        let mut conn = self.manager.clone();
        let value: Option<String> = conn
            .get(key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(value)
    }

    #[instrument(skip(self))]
    async fn get_and_delete_value(&self, key: &str) -> Result<Option<String>, RepositoryError> {
        let mut conn = self.manager.clone();
        let value: Option<String> = conn
            .get_del(key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(value)
    }

    #[instrument(skip(self))]
    async fn increment_value(&self, key: &str, ttl_seconds: u64) -> Result<u64, RepositoryError> {
        let mut conn = self.manager.clone();
        let count: u64 = conn
            .incr(key, 1u64)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        // Only the creator of the key sets the TTL, so retries can't extend it.
        if count == 1 {
            let _: () = conn
                .expire(key, ttl_seconds as i64)
                .await
                .map_err(|e| RepositoryError::Database(e.to_string()))?;
        }
        Ok(count)
    }

    #[instrument(skip(self))]
    async fn touch_value(&self, key: &str, ttl_seconds: u64) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        // EXPIRE on a missing key returns 0 and changes nothing, which is the
        // behaviour the trait promises. The counter this refreshes must outlive
        // the sessions stamped with it, so its TTL is set here rather than at
        // INCR time (where it is applied only on creation).
        let _: bool = conn
            .expire(key, ttl_seconds as i64)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self, context))]
    async fn set_code(
        &self,
        hashed_code: &str,
        context: &AuthCodeContext,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.key(hashed_code);

        // Serialize the context (User ID, Client ID, PKCE, etc.)
        let json = serde_json::to_string(context).map_err(|e| {
            RepositoryError::Database(format!("Failed to serialize auth context: {}", e))
        })?;

        // SETEX saves the string and sets the timeout in one atomic step
        let _: () = conn
            .set_ex(&key, json, ttl_seconds)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn exchange_code(
        &self,
        hashed_code: &str,
    ) -> Result<Option<AuthCodeContext>, RepositoryError> {
        let mut conn = self.manager.clone();
        let key = self.key(hashed_code);

        let data: Option<String> = conn
            .get_del(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => {
                let context: AuthCodeContext = serde_json::from_str(&json).map_err(|e| {
                    RepositoryError::Database(format!("Corrupt auth context: {}", e))
                })?;
                Ok(Some(context))
            }
            None => Ok(None), // Code either expired or was already used
        }
    }
}
