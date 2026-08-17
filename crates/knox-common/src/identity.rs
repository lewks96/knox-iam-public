use crate::error::RepositoryError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))] // Only derive if sqlx feature is on
#[cfg_attr(feature = "sqlx", sqlx(type_name = "status", rename_all = "lowercase"))]
pub enum Status {
    Active,
    Disabled,
    Inactive,
    Suspended,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "identity_kind", rename_all = "snake_case")
)]
pub enum IdentityKind {
    Human,
    Machine,
    ServiceAccount,
}

/// A verification option offered to a user during the MFA step of login.
/// Superset of `mfa::MfaMethodKind`: backup codes are a verification option
/// but not an enrollable method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MfaOption {
    Totp,
    WebAuthn,
    Sms,
    #[serde(rename = "backup_code")]
    BackupCode,
}

impl From<crate::mfa::MfaMethodKind> for MfaOption {
    fn from(kind: crate::mfa::MfaMethodKind) -> Self {
        match kind {
            crate::mfa::MfaMethodKind::Totp => MfaOption::Totp,
            crate::mfa::MfaMethodKind::WebAuthn => MfaOption::WebAuthn,
            crate::mfa::MfaMethodKind::Sms => MfaOption::Sms,
        }
    }
}

pub type MfaOptions = Vec<MfaOption>;

#[derive(Debug, Clone, Serialize)]
pub struct MfaRequiredDetails {
    #[serde(rename = "mfa_token")]
    pub token: String,
    pub user_id: Uuid,
    #[serde(rename = "methods")]
    pub options: MfaOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The directory this identity lives in. Uniqueness of `username`/`email` is
    /// scoped to this, not to `tenant_id`.
    ///
    /// `tenant_id` is retained as a denormalised scope tag for roles, audit and
    /// listing; a composite foreign key `(pool_id, tenant_id)` makes the pair
    /// provably consistent, so it is never a second source of truth.
    pub pool_id: Uuid,
    pub kind: IdentityKind,

    pub username: String,
    pub email: Option<String>,

    pub password_hash: Option<String>,

    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,

    pub metadata: serde_json::Value,
    pub custom_attributes: serde_json::Value,

    pub status: Status,

    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// The API-safe representation of an identity.
///
/// `Identity` is also the internal authentication and cache model, so it must
/// retain `password_hash` and remain serializable for Redis. HTTP responses use
/// this separate type instead: adding a credential field to the internal model
/// can no longer expose it merely because a handler returns that model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicIdentity {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub pool_id: Uuid,
    pub kind: IdentityKind,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub metadata: serde_json::Value,
    pub custom_attributes: serde_json::Value,
    pub status: Status,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<Identity> for PublicIdentity {
    fn from(identity: Identity) -> Self {
        Self {
            id: identity.id,
            tenant_id: identity.tenant_id,
            pool_id: identity.pool_id,
            kind: identity.kind,
            username: identity.username,
            email: identity.email,
            email_verified: identity.email_verified,
            first_name: identity.first_name,
            last_name: identity.last_name,
            metadata: identity.metadata,
            custom_attributes: identity.custom_attributes,
            status: identity.status,
            created_at: identity.created_at,
            updated_at: identity.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityUpdates {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub email_verified: Option<bool>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub custom_attributes: Option<serde_json::Value>,
    pub status: Option<Status>,
}

#[derive(Debug, Clone)]
pub struct IdentityFilter {
    pub tenant_id: Uuid,
    /// `None` lists every pool in the tenant. Admin surfaces pass the caller's
    /// pool so a staff listing never mixes in end users.
    pub pool_id: Option<Uuid>,
    pub page: u32,
    pub page_size: u32,
    pub status: Option<Status>,
    pub query: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityHandle {
    Id(Uuid),
    Email(String),
    Username(String),
}

/// Handle-based lookups are scoped by **pool**, not tenant.
///
/// A handle only means something inside a directory: since uniqueness moved to
/// `(pool_id, username)`, a tenant-scoped `get_by_username` would be a multi-row
/// query and would return an arbitrary one of the matches. Listing stays
/// tenant-scoped (via `IdentityFilter`), because "every identity in this tenant"
/// is still a coherent question.
#[async_trait]
pub trait IdentityRepository: Send + Sync {
    async fn create(&self, identity: &Identity) -> Result<Identity, RepositoryError>;
    async fn get(
        &self,
        pool_id: Uuid,
        handle: IdentityHandle,
    ) -> Result<Option<Identity>, RepositoryError>;
    async fn delete(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<(), RepositoryError>;
    async fn update(
        &self,
        pool_id: Uuid,
        handle: IdentityHandle,
        updates: &IdentityUpdates,
    ) -> Result<Identity, RepositoryError>;
    async fn exists(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<bool, RepositoryError>;
    async fn list(&self, filter: IdentityFilter) -> Result<(Vec<Identity>, u64), RepositoryError>;
    async fn count(&self, tenant_id: Uuid, filter: Option<String>) -> Result<u64, RepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_identity_never_serializes_password_hash() {
        let now = OffsetDateTime::now_utc();
        let identity = Identity {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            pool_id: Uuid::new_v4(),
            kind: IdentityKind::Human,
            username: "alice".into(),
            email: Some("alice@example.test".into()),
            password_hash: Some("$argon2id$must-not-leak".into()),
            email_verified: true,
            first_name: Some("Alice".into()),
            last_name: None,
            metadata: serde_json::json!({}),
            custom_attributes: serde_json::json!({}),
            status: Status::Active,
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_value(PublicIdentity::from(identity)).unwrap();
        assert!(json.get("password_hash").is_none());
        assert_eq!(json["username"], "alice");
    }
}
