use crate::error::AppError;
use crate::middleware::auth::ClaimsExt;
use knox_common::tenant::TenantConfiguration;
use knox_core::roles::IDENTITY_UPDATE_SCOPE;
use knox_core::token::JwtClaims;
use serde::Serialize;
use uuid::Uuid;

pub mod audit;
pub mod authentication;
pub mod client;
pub mod identity;
pub mod mfa;
pub mod oidc;
pub mod pool;
pub mod tenant;

#[derive(Debug, Serialize)]
pub struct GenericResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The identity id for a self-service operation: always the subject of the
/// access token, never an id from the path or body. Requires `IdentityUpdate`,
/// the scope every self-service route (MFA enrolment, password change) gates on.
/// Shared so those routes cannot drift on what "self" means.
pub fn self_identity_id(claims: &JwtClaims) -> Result<Uuid, AppError> {
    claims.require_scope(IDENTITY_UPDATE_SCOPE)?;
    Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::BadRequest("Token subject is not a user identity".into()))
}

/// The reset link handed to the user (admin flow) or emailed (self-service).
/// `{issuer}` and `{token}` are substituted into the tenant's template, or the
/// default path when it sets none.
pub fn build_reset_url(config: &TenantConfiguration, issuer: &str, token: &str) -> String {
    let template = config
        .authentication_configuration
        .password_reset_url_template
        .clone()
        .unwrap_or_else(|| "{issuer}/reset-password?token={token}".to_string());
    template
        .replace("{issuer}", issuer)
        .replace("{token}", token)
}
