use crate::error::RepositoryError;
use crate::identity::Status;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    /// Canonical OIDC issuer. Stored, not derived: it is the tenant's permanent
    /// identity and must not shift when deployment config does.
    pub issuer: String,
    pub description: Option<String>,
    /// Owns platform-wide (cross-tenant) operations. Exactly one tenant per
    /// deployment carries this, enforced by a partial unique index.
    pub is_platform: bool,
    pub status: Status,
    pub config: TenantConfiguration,
    #[serde(with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TenantUpdates {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<Status>,
    pub config: Option<TenantConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthorizationConfiguration {
    pub allow_plain_pkce: bool,
    pub auth_code_ttl_seconds: u32,
    /// Withhold every scope beyond self-service from an identity with no
    /// verified MFA method.
    ///
    /// This governs what a *token* may carry rather than who may sign in, which
    /// is why it lives here and not beside the MFA settings in
    /// `AuthenticationConfiguration`. An admin without a second factor still
    /// authenticates and still gets a session — the session just cannot mint
    /// administrative scopes, which leaves them able to reach MFA enrollment
    /// and nothing else.
    ///
    /// Defaults off: switching it on retroactively strips admin scopes from
    /// every unenrolled identity in the tenant at their next token refresh, so
    /// it is a decision an operator makes deliberately, per tenant.
    pub require_admin_mfa: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthenticationConfiguration {
    pub sso_cookie_name: String,
    pub sso_cookie_secure: bool,
    pub sso_cookie_same_site_lax: bool,
    pub sso_cookie_lifetime_seconds: Duration,
    pub sso_cookie_domain: Option<String>,
    pub sso_cookie_path: Option<String>,
    pub mfa_token_lifetime_seconds: Duration,
    /// Issuer shown in authenticator apps for TOTP enrollments.
    /// Falls back to the tenant slug when unset.
    pub totp_issuer: Option<String>,
    /// Maximum failed verification attempts per MFA token before lockout.
    pub mfa_max_verification_attempts: u32,
    /// Failed password attempts allowed for one tenant+pool+username in the
    /// configured window before authentication returns 429.
    pub login_max_attempts_per_account: u32,
    /// Failed password attempts allowed across the whole tenant. This catches
    /// distributed attacks that remain below each source-IP threshold.
    pub login_max_attempts_per_tenant: u32,
    /// Failed password attempts allowed from one source IP across the tenant.
    pub login_max_attempts_per_ip: u32,
    /// Fixed window for the Redis-backed login counters.
    pub login_attempt_window_seconds: Duration,
    pub should_return_cookie_in_body: bool,
    pub should_return_cookie_on_re_auth: bool,
    /// How long a password-reset token is valid. Short by design: it is a bearer
    /// credential for the account, so the window to redeem a leaked link is kept
    /// narrow.
    pub password_reset_token_lifetime_seconds: Duration,
    /// Template for the reset link handed to the user (admin flow) or emailed
    /// (self-service). `{token}` and `{issuer}` are substituted. `None` uses
    /// `{issuer}/reset-password?token={token}`.
    pub password_reset_url_template: Option<String>,
    /// Whether the unauthenticated `POST /api/authenticate/password/forgot`
    /// endpoint is live. Off by default: with no mailer wired up it cannot yet
    /// deliver a link to the user, so enabling it is a deliberate per-tenant
    /// decision once email exists. The admin-initiated reset path does not
    /// depend on this.
    pub self_service_password_reset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfiguration {
    /// How long audit events are kept before the daily prune job deletes
    /// them. Read directly from the tenants JSONB by the pg_cron job.
    pub retention_days: u32,
}

impl Default for AuditConfiguration {
    fn default() -> Self {
        Self { retention_days: 90 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TenantConfiguration {
    pub authentication_configuration: AuthenticationConfiguration,
    pub authorization_configuration: AuthorizationConfiguration,
    pub audit_configuration: AuditConfiguration,
}

impl Default for AuthenticationConfiguration {
    fn default() -> Self {
        Self {
            sso_cookie_name: "knox_sso".to_string(),
            sso_cookie_secure: true,
            sso_cookie_same_site_lax: true,
            sso_cookie_domain: None,
            sso_cookie_path: Some("/".into()),
            mfa_token_lifetime_seconds: Duration::seconds(300),
            totp_issuer: None,
            mfa_max_verification_attempts: 5,
            login_max_attempts_per_account: 10,
            login_max_attempts_per_tenant: 1000,
            login_max_attempts_per_ip: 100,
            login_attempt_window_seconds: Duration::seconds(300),
            should_return_cookie_in_body: true,
            should_return_cookie_on_re_auth: false,
            sso_cookie_lifetime_seconds: Duration::seconds(3600),
            password_reset_token_lifetime_seconds: Duration::seconds(900),
            password_reset_url_template: None,
            self_service_password_reset: false,
        }
    }
}

impl Default for AuthorizationConfiguration {
    fn default() -> Self {
        Self {
            allow_plain_pkce: false,
            auth_code_ttl_seconds: 600, // 10 minutes
            require_admin_mfa: false,
        }
    }
}

#[async_trait]
pub trait TenantRepository: Send + Sync {
    async fn create(
        &self,
        name: &str,
        slug: &str,
        issuer: &str,
        description: Option<String>,
        is_platform: bool,
    ) -> Result<Tenant, RepositoryError>;
    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError>;
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError>;
    async fn update(&self, id: Uuid, updates: &TenantUpdates) -> Result<Tenant, RepositoryError>;
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
    async fn list(&self, page: u32, page_size: u32) -> Result<(Vec<Tenant>, u64), RepositoryError>;
}
