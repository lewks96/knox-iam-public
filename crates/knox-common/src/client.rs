use crate::error::RepositoryError;
use crate::identity::Status;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Public,
    Confidential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: Uuid, // Acts as client_id
    pub tenant_id: Uuid,
    /// The identity pool this client authenticates against.
    ///
    /// This is what makes the console unreachable to end users: credential
    /// lookup during login happens inside this pool, so an identity in a
    /// different pool is not rejected — it is invisible.
    ///
    /// Carried by pure `client_credentials` clients too, where it is unused; a
    /// nullable column would put an `Option` branch at every enforcement point,
    /// which is where fail-open bugs live.
    pub pool_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub logo_uri: Option<String>,

    pub client_type: ClientType,
    pub client_secret_hash: Option<String>,
    pub token_endpoint_auth_method: String,

    pub allow_refresh_tokens: bool,

    pub grant_types: Vec<String>, // Change to enum!
    pub response_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,

    pub require_pkce: bool,
    pub require_auth_time: bool,

    pub access_token_ttl: i32,
    pub refresh_token_ttl: i32,
    pub id_token_ttl: i32,
    pub auth_code_ttl: i32,
    pub token_version: i32,

    pub jwks_uri: Option<String>,
    pub jwks: Option<serde_json::Value>,
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_san_dns: Option<String>,
    pub tls_client_auth_san_uri: Option<String>,
    pub tls_client_auth_san_ip: Option<String>,
    pub tls_client_auth_san_email: Option<String>,

    pub status: Status,
    pub metadata: serde_json::Value,
    pub custom_attributes: serde_json::Value,

    #[serde(with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    pub updated_at: OffsetDateTime,
}

/// `name` is intentionally omitted — it is immutable after creation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientUpdates {
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub client_secret_hash: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub allow_refresh_tokens: Option<bool>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub require_pkce: Option<bool>,
    pub require_auth_time: Option<bool>,
    pub access_token_ttl: Option<i32>,
    pub refresh_token_ttl: Option<i32>,
    pub id_token_ttl: Option<i32>,
    pub auth_code_ttl: Option<i32>,
    pub token_version: Option<i32>, // Useful for rotation
    pub status: Option<Status>,
    pub metadata: Option<serde_json::Value>,
    pub custom_attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct ClientFilter {
    pub tenant_id: Uuid,
    pub page: u32,
    pub page_size: u32,
    pub status: Option<Status>,
}

#[async_trait]
pub trait ClientRepository: Send + Sync {
    async fn create(&self, client: &Client) -> Result<Client, RepositoryError>;
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError>;
    async fn get_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Client>, RepositoryError>;
    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        updates: &ClientUpdates,
    ) -> Result<Client, RepositoryError>;
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
    async fn list(&self, filter: &ClientFilter) -> Result<(Vec<Client>, u64), RepositoryError>;
}
