use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::token::{
    AuthCodeCache, AuthCodeContext, RefreshToken, RefreshTokenStore, TokenRepository,
};
use tracing::{debug, instrument};
use uuid::Uuid;

#[derive(Clone)]
pub struct KnoxTokenRepository<C, S> {
    cache: C,
    store: S,
}

impl<C, S> KnoxTokenRepository<C, S>
where
    C: AuthCodeCache + Send + Sync,
    S: RefreshTokenStore + Send + Sync,
{
    #[instrument(skip(cache, store))]
    pub fn new(cache: C, store: S) -> Self {
        Self { cache, store }
    }
}

#[async_trait]
impl<C, S> TokenRepository for KnoxTokenRepository<C, S>
where
    C: AuthCodeCache + Send + Sync,
    S: RefreshTokenStore + Send + Sync,
{
    #[instrument(skip(self, value))]
    async fn store_transient_string(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError> {
        self.cache.set_value(key, value, ttl_seconds).await
    }

    #[instrument(skip(self))]
    async fn read_transient_string(&self, key: &str) -> Result<Option<String>, RepositoryError> {
        self.cache.get_value(key).await
    }

    #[instrument(skip(self))]
    async fn get_and_delete_transient_string(
        &self,
        key: &str,
    ) -> Result<Option<String>, RepositoryError> {
        self.cache.get_and_delete_value(key).await
    }

    #[instrument(skip(self))]
    async fn increment_transient_counter(
        &self,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<u64, RepositoryError> {
        self.cache.increment_value(key, ttl_seconds).await
    }

    #[instrument(skip(self))]
    async fn touch_transient(&self, key: &str, ttl_seconds: u64) -> Result<(), RepositoryError> {
        self.cache.touch_value(key, ttl_seconds).await
    }

    #[instrument(skip(self, context))]
    async fn save_auth_code(
        &self,
        hashed_code: &str,
        context: &AuthCodeContext,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError> {
        debug!(
            "Saving auth code with hash {} for client {} and user {} with TTL {} seconds",
            hashed_code, context.client_id, context.identity_id, ttl_seconds
        );
        self.cache.set_code(hashed_code, context, ttl_seconds).await
    }

    #[instrument(skip(self))]
    async fn exchange_auth_code(
        &self,
        hashed_code: &str,
    ) -> Result<Option<AuthCodeContext>, RepositoryError> {
        debug!("Exchanging auth code with hash {}", hashed_code);
        self.cache.exchange_code(hashed_code).await
    }

    #[instrument(skip(self, token))]
    async fn save_refresh_token(
        &self,
        token: &RefreshToken,
    ) -> Result<RefreshToken, RepositoryError> {
        debug!(
            "Saving refresh token with ID {} for client {} and user {}",
            token.id, token.client_id, token.identity_id
        );
        self.store.create(token).await
    }

    #[instrument(skip(self))]
    async fn get_refresh_token(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, RepositoryError> {
        debug!(
            "Retrieving refresh token for tenant {} with hash {}",
            tenant_id, token_hash
        );
        self.store.get_by_hash(tenant_id, token_hash).await
    }

    #[instrument(skip(self))]
    async fn revoke_refresh_token(&self, id: Uuid) -> Result<(), RepositoryError> {
        debug!("Revoking refresh token with ID {}", id);
        self.store.revoke(id).await
    }

    #[instrument(skip(self))]
    async fn revoke_token_family(&self, family_id: Uuid) -> Result<(), RepositoryError> {
        debug!("Revoking refresh token family with ID {}", family_id);
        self.store.revoke_family(family_id).await
    }

    #[instrument(skip(self))]
    async fn revoke_all_for_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), RepositoryError> {
        debug!(
            "Revoking all refresh tokens for identity {} in tenant {}",
            identity_id, tenant_id
        );
        self.store
            .revoke_all_for_identity(tenant_id, identity_id)
            .await
    }
}
