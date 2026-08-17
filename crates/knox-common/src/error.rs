use crate::identity::MfaRequiredDetails;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Entity not found")]
    NotFound,
    #[error("Duplicate entry: {0}")]
    Duplicate(String),
}

#[derive(Error, Debug)]
pub enum OIDCError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Invalid grant for client")]
    InvalidGrant,

    #[error("Invalid secret")]
    InvalidClientSecret,

    #[error("Unauthorized client")]
    UnauthorizedClient,

    #[error("Access denied")]
    AccessDenied,

    #[error("Unsupported response type")]
    UnsupportedResponseType,

    #[error("Invalid scope")]
    InvalidScope,

    #[error("Server error: {0}")]
    ServerError(String),
}

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("OIDC error: {0}")]
    OIDC(#[from] OIDCError),

    #[error("Storage error: {0}")]
    Repository(#[from] RepositoryError),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Redirect URI mismatch")]
    RedirectUriMismatch,

    #[error("SSO Token Expired")]
    SsoTokenExpired,

    #[error("Invalid SSO Token")]
    InvalidSsoToken,

    #[error("Identity already exists")]
    DuplicateIdentity,

    #[error("Operation not permitted")]
    Forbidden,

    #[error("Internal server error")]
    Internal(String),

    #[error("MFA Required: {0:?}")]
    MfaRequired(MfaRequiredDetails),

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("Invalid MFA token")]
    InvalidMfaToken,

    #[error("Too many MFA verification attempts")]
    MfaTooManyAttempts,

    #[error("Too many authentication attempts")]
    TooManyAuthenticationAttempts,

    #[error("MFA method already enrolled")]
    MfaAlreadyEnrolled,

    #[error("MFA method not enrolled")]
    MfaNotEnrolled,

    #[error("Invalid Auth Code")]
    InvalidAuthCode,

    #[error("Invalid or expired password reset token")]
    InvalidResetToken,
}
