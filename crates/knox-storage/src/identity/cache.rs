use crate::identity::IdentityCache;
use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::identity::Identity;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tracing::instrument;
use uuid::Uuid;

const CACHE_TTL_SECONDS: usize = 3600; // 1 hour TTL for cache entries

/// Identity cache, keyed by **pool** rather than tenant.
///
/// The pool scoping is not cosmetic. Uniqueness now lives at `(pool_id, username)`,
/// so a tenant-keyed entry for `alice@acme.com` would be ambiguous between a staff
/// identity and an end user of the same tenant — a cross-pool authentication
/// bypass through the cache, entirely bypassing the SQL predicates.
///
/// Only `id -> Identity` is cached. There was previously an `email -> id` pointer
/// (and a `username -> id` pointer that `set` never actually wrote, so username
/// lookups always missed). Pointers are not invalidated when an identity is
/// renamed, which means a stale pointer resolves an old username to a live
/// identity — fine for a cache, not fine for the thing that decides who you are.
/// Handle lookups go to Postgres, which has a unique index on exactly that key;
/// the id lookups that dominate the request path stay cached.
#[derive(Clone)]
pub struct RedisIdentityCache {
    conn: ConnectionManager,
}

impl RedisIdentityCache {
    #[instrument(skip(conn))]
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }

    #[instrument(skip(self))]
    fn key(&self, pool_id: Uuid, id: Uuid) -> String {
        format!("p:{}:i:id:{}", pool_id, id)
    }
}

#[async_trait]
impl IdentityCache for RedisIdentityCache {
    #[instrument(skip(self))]
    async fn get_by_id(
        &self,
        pool_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Identity>, RepositoryError> {
        let mut conn = self.conn.clone();
        let key = self.key(pool_id, id);

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
    async fn set(&self, identity: &Identity) -> Result<(), RepositoryError> {
        let mut conn = self.conn.clone();

        let key = self.key(identity.pool_id, identity.id);
        let json = serde_json::to_string(identity)
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, &json, CACHE_TTL_SECONDS as u64)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, pool_id: Uuid, id: Uuid) -> Result<(), RepositoryError> {
        let mut conn = self.conn.clone();
        let key = self.key(pool_id, id);
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;
        Ok(())
    }
}
