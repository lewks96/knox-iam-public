use crate::error::RepositoryError;
use async_trait::async_trait;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// Audit event taxonomy. Only used on the write path - stored and served as
/// its dotted string form so rows written by newer builds always render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    /// Password verification during login.
    AuthLogin,
    /// Password accepted but a second factor is required.
    AuthMfaChallenge,
    /// MFA code verification during login.
    AuthMfaVerify,
    /// MFA verification attempt limit exceeded.
    AuthMfaLockout,
    MfaEnrollStarted,
    MfaEnrolled,
    MfaRemoved,
    MfaBackupCodesRegenerated,
    /// OAuth2 token grant (any grant type; grant in details).
    TokenIssued,
    /// A rotated-out refresh token was presented again; family revoked.
    TokenRefreshReuseDetected,
    IdentityCreated,
    IdentityUpdated,
    IdentityDeleted,
    ClientCreated,
    ClientUpdated,
    ClientDeleted,
    /// A new identity pool. Worth its own event: a pool decides which
    /// credentials are even checkable against which client.
    PoolCreated,
    TenantCreated,
    /// Cascades to every identity, client, key and audit row the tenant owned.
    TenantDeleted,
    /// A valid token for one tenant was used against another tenant's routes.
    AuthzCrossTenantDenied,
    // Reserved: no routes emit these yet.
    RoleAssigned,
    RoleRevoked,
    PasswordChanged,
    /// A reset link was issued (admin-initiated or self-service). The reset has
    /// not happened yet — `PasswordChanged` records that, if and when the link
    /// is redeemed.
    PasswordResetRequested,
    /// An administrator cleared an identity's MFA enrolment (break-glass for a
    /// user locked out of their second factor). Distinct from `MfaRemoved`,
    /// which is the self-service action.
    MfaReset,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthLogin => "auth.login",
            Self::AuthMfaChallenge => "auth.mfa_challenge",
            Self::AuthMfaVerify => "auth.mfa_verify",
            Self::AuthMfaLockout => "auth.mfa_lockout",
            Self::MfaEnrollStarted => "mfa.enroll_started",
            Self::MfaEnrolled => "mfa.enrolled",
            Self::MfaRemoved => "mfa.removed",
            Self::MfaBackupCodesRegenerated => "mfa.backup_codes_regenerated",
            Self::TokenIssued => "token.issued",
            Self::TokenRefreshReuseDetected => "token.refresh_reuse_detected",
            Self::IdentityCreated => "identity.created",
            Self::IdentityUpdated => "identity.updated",
            Self::IdentityDeleted => "identity.deleted",
            Self::PoolCreated => "pool.created",
            Self::TenantCreated => "tenant.created",
            Self::TenantDeleted => "tenant.deleted",
            Self::ClientCreated => "client.created",
            Self::ClientUpdated => "client.updated",
            Self::ClientDeleted => "client.deleted",
            Self::AuthzCrossTenantDenied => "authz.cross_tenant_denied",
            Self::RoleAssigned => "role.assigned",
            Self::RoleRevoked => "role.revoked",
            Self::PasswordChanged => "identity.password_changed",
            Self::PasswordResetRequested => "identity.password_reset_requested",
            Self::MfaReset => "mfa.reset",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

impl AuditOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditActor {
    Identity(Uuid),
    Client(Uuid),
    /// Unauthenticated caller (e.g. a failed login where no identity matched).
    Anonymous,
}

impl AuditActor {
    pub fn type_str(&self) -> &'static str {
        match self {
            Self::Identity(_) => "identity",
            Self::Client(_) => "client",
            Self::Anonymous => "anonymous",
        }
    }

    pub fn id(&self) -> Option<Uuid> {
        match self {
            Self::Identity(id) | Self::Client(id) => Some(*id),
            Self::Anonymous => None,
        }
    }
}

/// Request-scoped context captured at the HTTP edge and carried to the
/// emission point. All fields best-effort.
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// OTel trace id (hex) - matches the x-correlation-id response header.
    pub correlation_id: Option<String>,
}

/// An event to record. `occurred_at` is captured at emission time, not write
/// time, because writes are buffered.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub tenant_id: Uuid,
    pub occurred_at: OffsetDateTime,
    pub event_type: AuditEventType,
    pub actor: AuditActor,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub outcome: AuditOutcome,
    pub context: AuditContext,
    /// Identifiers and small facts only - never secrets, credentials, or PII
    /// field values.
    pub details: serde_json::Value,
}

impl AuditEvent {
    pub fn new(
        tenant_id: Uuid,
        event_type: AuditEventType,
        actor: AuditActor,
        outcome: AuditOutcome,
        context: AuditContext,
    ) -> Self {
        Self {
            tenant_id,
            occurred_at: OffsetDateTime::now_utc(),
            event_type,
            actor,
            target_type: None,
            target_id: None,
            outcome,
            context,
            details: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    pub fn with_target(mut self, target_type: &str, target_id: impl Into<String>) -> Self {
        self.target_type = Some(target_type.to_string());
        self.target_id = Some(target_id.into());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

/// A persisted event as served by the query API. String-typed fields are
/// returned verbatim from storage for forward compatibility.
#[derive(Debug, Clone, Serialize)]
pub struct StoredAuditEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    pub event_type: String,
    pub actor_type: String,
    pub actor_id: Option<Uuid>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub outcome: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub correlation_id: Option<String>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct AuditEventFilter {
    pub tenant_id: Uuid,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    pub event_type: Option<String>,
    pub actor_id: Option<Uuid>,
    pub outcome: Option<String>,
    pub limit: u32,
    /// Keyset cursor: return events strictly older than (occurred_at, id).
    pub cursor: Option<(OffsetDateTime, Uuid)>,
}

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn insert(&self, event: &AuditEvent) -> Result<(), RepositoryError>;
    /// Newest-first, keyset-paginated.
    async fn list(
        &self,
        filter: &AuditEventFilter,
    ) -> Result<Vec<StoredAuditEvent>, RepositoryError>;
}
