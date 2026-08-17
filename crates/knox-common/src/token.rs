use crate::error::RepositoryError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

//TODO: Refactor this to a generic redis cache thing

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeContext {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub identity_id: Uuid,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub pkce_code_challenge: String,
    pub pkce_code_challenge_method: String,
    pub nonce: Option<String>,
    /// Methods presented at the login this code descends from (RFC 8176), and
    /// when. Copied from the SSO session at authorize time — the token endpoint
    /// has no other way to reach them, and `created_at` below is the age of the
    /// *code*, not of the authentication.
    ///
    /// Defaulted so codes issued before this field existed still redeem.
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub auth_time: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[async_trait]
pub trait AuthCodeCache: Send + Sync {
    async fn set_value(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError>;
    async fn get_value(&self, key: &str) -> Result<Option<String>, RepositoryError>;
    async fn get_and_delete_value(&self, key: &str) -> Result<Option<String>, RepositoryError>;
    /// Atomic INCR; sets the TTL when the key is first created.
    /// Returns the post-increment value.
    async fn increment_value(&self, key: &str, ttl_seconds: u64) -> Result<u64, RepositoryError>;
    /// Sets/refreshes the TTL on an existing key (Redis EXPIRE). A no-op if the
    /// key does not exist. Needed because `increment_value` sets the TTL only on
    /// creation, so a counter that must outlive its first write is extended here.
    async fn touch_value(&self, key: &str, ttl_seconds: u64) -> Result<(), RepositoryError>;
    async fn set_code(
        &self,
        hashed_code: &str,
        context: &AuthCodeContext,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError>;
    async fn exchange_code(
        &self,
        hashed_code: &str,
    ) -> Result<Option<AuthCodeContext>, RepositoryError>;
}

// =========================================================================
//  Refresh Tokens (Destined for Postgres)
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub identity_id: Uuid,
    pub token_hash: String,
    pub scopes: Vec<String>,
    /// The authentication this token family descends from, carried so `amr`,
    /// `acr` and `auth_time` survive rotation. Without it those claims would
    /// disappear at the first refresh, and a resource server could not tell a
    /// refreshed multi-factor session from a single-factor one.
    pub amr: Vec<String>,
    pub auth_time: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub family_id: Uuid,
    #[serde(with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    pub updated_at: OffsetDateTime,
}

#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    async fn create(&self, token: &RefreshToken) -> Result<RefreshToken, RepositoryError>;
    async fn get_by_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, RepositoryError>;
    async fn revoke(&self, id: Uuid) -> Result<(), RepositoryError>;
    async fn revoke_family(&self, family_id: Uuid) -> Result<(), RepositoryError>;
    async fn revoke_all_for_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), RepositoryError>;
}

#[async_trait]
pub trait TokenRepository: Send + Sync {
    async fn store_transient_string(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError>;

    async fn read_transient_string(&self, key: &str) -> Result<Option<String>, RepositoryError>;

    async fn get_and_delete_transient_string(
        &self,
        key: &str,
    ) -> Result<Option<String>, RepositoryError>;

    /// Atomic INCR; sets the TTL when the key is first created.
    /// Returns the post-increment value.
    async fn increment_transient_counter(
        &self,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<u64, RepositoryError>;

    /// Sets/refreshes the TTL on an existing transient key. A no-op if absent.
    async fn touch_transient(&self, key: &str, ttl_seconds: u64) -> Result<(), RepositoryError>;

    async fn exchange_auth_code(
        &self,
        hashed_code: &str,
    ) -> Result<Option<AuthCodeContext>, RepositoryError>;

    // Old
    #[deprecated(note = "Use generic methods instead for better flexibility")]
    async fn save_auth_code(
        &self,
        hashed_code: &str,
        context: &AuthCodeContext,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError>;

    async fn save_refresh_token(
        &self,
        token: &RefreshToken,
    ) -> Result<RefreshToken, RepositoryError>;
    async fn get_refresh_token(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, RepositoryError>;
    async fn revoke_refresh_token(&self, id: Uuid) -> Result<(), RepositoryError>;
    async fn revoke_token_family(&self, family_id: Uuid) -> Result<(), RepositoryError>;
    async fn revoke_all_for_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), RepositoryError>;
}
