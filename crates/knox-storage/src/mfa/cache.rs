use crate::mfa::MfaCache;
use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::mfa::MfaMethod;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::instrument;
use uuid::Uuid;

const CACHE_TTL_SECONDS: u64 = 900; // 15 minutes

#[derive(Clone)]
pub struct RedisMfaCache {
    conn: ConnectionManager,
}

impl RedisMfaCache {
    #[instrument(skip(conn))]
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }

    fn key(&self, tenant_id: Uuid, identity_id: Uuid) -> String {
        format!("t:{}:mfa:verified:{}", tenant_id, identity_id)
    }
}

#[async_trait]
impl MfaCache for RedisMfaCache {
    #[instrument(skip(self))]
    async fn get_verified_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Option<Vec<MfaMethod>>, RepositoryError> {
        let mut conn = self.conn.clone();
        let key = self.key(tenant_id, identity_id);

        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        match data {
            Some(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| RepositoryError::Database(format!("Cache corrupt: {}", e))),
            None => Ok(None),
        }
    }

    #[instrument(skip(self, methods))]
    async fn set_verified_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        methods: &[MfaMethod],
    ) -> Result<(), RepositoryError> {
        let mut conn = self.conn.clone();
        let key = self.key(tenant_id, identity_id);

        let json =
            serde_json::to_string(methods).map_err(|e| RepositoryError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, json, CACHE_TTL_SECONDS)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn invalidate(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), RepositoryError> {
        let mut conn = self.conn.clone();
        let key = self.key(tenant_id, identity_id);
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }
}
