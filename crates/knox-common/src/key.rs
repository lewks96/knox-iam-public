use crate::error::RepositoryError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "key_state", rename_all = "lowercase")
)]
pub enum KeyState {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeyUse {
    #[default]
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
}

impl KeyUse {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyUse::Signature => "sig",
            KeyUse::Encryption => "enc",
        }
    }
}

impl std::fmt::Display for KeyUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for KeyUse {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sig" => Ok(KeyUse::Signature),
            "enc" => Ok(KeyUse::Encryption),
            _ => Err(format!("Invalid key use: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum KeyAlgorithm {
    #[default]
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
}

impl KeyAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAlgorithm::RS256 => "RS256",
            KeyAlgorithm::RS384 => "RS384",
            KeyAlgorithm::RS512 => "RS512",
            KeyAlgorithm::ES256 => "ES256",
            KeyAlgorithm::ES384 => "ES384",
        }
    }

    pub fn key_type(&self) -> &'static str {
        match self {
            KeyAlgorithm::RS256 | KeyAlgorithm::RS384 | KeyAlgorithm::RS512 => "RSA",
            KeyAlgorithm::ES256 | KeyAlgorithm::ES384 => "EC",
        }
    }
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for KeyAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RS256" => Ok(KeyAlgorithm::RS256),
            "RS384" => Ok(KeyAlgorithm::RS384),
            "RS512" => Ok(KeyAlgorithm::RS512),
            "ES256" => Ok(KeyAlgorithm::ES256),
            "ES384" => Ok(KeyAlgorithm::ES384),
            _ => Err(format!("Unsupported algorithm: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantKey {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub kid: String,
    pub use_type: String,
    pub kty: String,
    pub alg: String,
    pub public_key_pem: String,
    pub x509_cert_pem: Option<String>,
    #[serde(with = "serde_bytes_base64")]
    pub encrypted_private_key: Vec<u8>,
    pub state: KeyState,
    #[serde(with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct CreateKeyParams {
    pub tenant_id: Uuid,
    pub kid: String,
    pub use_type: String,
    pub kty: String,
    pub alg: String,
    pub public_key_pem: String,
    pub x509_cert_pem: Option<String>,
    pub encrypted_private_key: Vec<u8>,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default)]
pub struct KeyStateUpdate {
    pub state: Option<KeyState>,
}

#[derive(Debug, Clone)]
pub struct GeneratedKeyPair {
    pub public_key_pem: String,
    pub private_key_pem: String,
    pub algorithm: KeyAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<JwksKey>,
}

#[derive(Debug, Clone)]
pub struct KeyEncryptionError(pub String);

impl std::fmt::Display for KeyEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key encryption error: {}", self.0)
    }
}

impl std::error::Error for KeyEncryptionError {}

#[async_trait]
pub trait KeyEncryptionProvider: Send + Sync {
    async fn encrypt(
        &self,
        plaintext_key_pem: &str,
        context: Option<&[u8]>,
    ) -> Result<Vec<u8>, KeyEncryptionError>;
    async fn decrypt(
        &self,
        encrypted_blob: &[u8],
        context: Option<&[u8]>,
    ) -> Result<String, KeyEncryptionError>;
    fn provider_id(&self) -> &str;
}

#[async_trait]
pub trait KeyRepository: Send + Sync {
    async fn create(&self, params: CreateKeyParams) -> Result<TenantKey, RepositoryError>;
    async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
    async fn get_by_kid(
        &self,
        tenant_id: Uuid,
        kid: &str,
    ) -> Result<Option<TenantKey>, RepositoryError>;
    async fn get_active_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantKey>, RepositoryError>;
    async fn list_for_jwks(&self, tenant_id: Uuid) -> Result<Vec<TenantKey>, RepositoryError>;
    async fn list(
        &self,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<TenantKey>, u64), RepositoryError>;
    async fn update_state(
        &self,
        id: Uuid,
        new_state: KeyState,
    ) -> Result<TenantKey, RepositoryError>;
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
    async fn revoke_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
}

mod serde_bytes_base64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::{Engine, engine::general_purpose::STANDARD};
        STANDARD.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
