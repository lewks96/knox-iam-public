use crate::error::RepositoryError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// A concrete enrollable MFA method kind, mirroring the MFA_METHOD database enum.
/// Distinct from `identity::MfaOption`, which is the API-level verification
/// option set (it additionally includes backup codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "mfa_method", rename_all = "lowercase")
)]
pub enum MfaMethodKind {
    Totp,
    WebAuthn,
    Sms,
}

/// A stored MFA enrollment. Contains the encrypted secret - never expose this
/// through the API; use `MfaMethodSummary` instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaMethod {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
    pub method: MfaMethodKind,
    pub secret_enc: Option<Vec<u8>>,
    pub public_data: serde_json::Value,
    pub last_used_step: Option<i64>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub verified_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// API-safe projection of an enrollment (no secret material).
#[derive(Debug, Clone, Serialize)]
pub struct MfaMethodSummary {
    pub id: Uuid,
    pub method: MfaMethodKind,
    #[serde(with = "time::serde::rfc3339::option")]
    pub verified_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<&MfaMethod> for MfaMethodSummary {
    fn from(m: &MfaMethod) -> Self {
        Self {
            id: m.id,
            method: m.method,
            verified_at: m.verified_at,
            last_used_at: m.last_used_at,
            created_at: m.created_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewMfaMethod {
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
    pub method: MfaMethodKind,
    pub secret_enc: Option<Vec<u8>>,
    pub public_data: serde_json::Value,
}

#[async_trait]
pub trait MfaRepository: Send + Sync {
    /// For singleton kinds (totp/sms) this replaces an existing UNVERIFIED
    /// enrollment of the same kind and returns `RepositoryError::Duplicate`
    /// if a verified one already exists. Plain insert for webauthn.
    async fn create_method(&self, method: &NewMfaMethod) -> Result<MfaMethod, RepositoryError>;

    async fn get_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<Option<MfaMethod>, RepositoryError>;

    async fn get_method_by_kind(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        kind: MfaMethodKind,
    ) -> Result<Option<MfaMethod>, RepositoryError>;

    async fn list_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethod>, RepositoryError>;

    async fn list_verified_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethod>, RepositoryError>;

    async fn mark_verified(
        &self,
        tenant_id: Uuid,
        method_id: Uuid,
    ) -> Result<MfaMethod, RepositoryError>;

    async fn delete_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<(), RepositoryError>;

    /// Atomic TOTP replay guard: claims `step` if it is strictly greater than
    /// the stored `last_used_step` (or none is stored). Returns whether the
    /// step was claimed. Also bumps `last_used_at`.
    async fn claim_totp_step(
        &self,
        tenant_id: Uuid,
        method_id: Uuid,
        step: i64,
    ) -> Result<bool, RepositoryError>;

    /// Replaces all backup codes for an identity with the given hashes.
    async fn replace_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code_hashes: &[String],
    ) -> Result<(), RepositoryError>;

    /// Atomically marks a matching unused code as used. Returns whether a
    /// code was consumed.
    async fn consume_backup_code(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, RepositoryError>;

    async fn count_unused_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<u64, RepositoryError>;

    async fn delete_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), RepositoryError>;
}
