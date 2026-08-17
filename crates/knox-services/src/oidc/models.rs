use knox_common::client::Client;
use knox_common::identity::IdentityKind;
use knox_core::token::AuthenticationContext;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub sso_token: String,
    /// The client's name, used as the OAuth `client_id`.
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    pub scope: Vec<String>,
    pub nonce: Option<String>,
    pub max_age: Option<u32>,
    pub acr_values: Option<Vec<String>>,
    /// OIDC Core §3.1.2.1. Only `login` and `none` are acted on; any other
    /// value is ignored, as the spec allows for unsupported values.
    pub prompt: Option<String>,
}

#[derive(Debug, Clone)]
pub enum CodeChallengeMethod {
    S256,
    Plain, // Deprecate?
}

impl From<CodeChallengeMethod> for String {
    fn from(value: CodeChallengeMethod) -> Self {
        match value {
            CodeChallengeMethod::S256 => "S256".into(),
            CodeChallengeMethod::Plain => "plain".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TokenGrantRequest {
    ClientCredentials {
        /// The client's name, used as the OAuth `client_id`.
        client_id: String,
        client_secret: String,
        scope: Option<String>,
    },
    AuthorizationCode {
        client_id: String,
        client_secret: Option<String>,
        code: String,
        redirect_uri: Option<String>,
        code_verifier: String,
    },
    RefreshToken {
        client_id: String,
        client_secret: Option<String>,
        refresh_token: String,
    },
}

#[derive(Debug, Clone)]
pub struct MintingContext {
    pub tenant_id: Uuid,
    pub client: Client,
    pub subject: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub identity_id: Option<Uuid>,
    pub refresh_token_family_id: Option<Uuid>,
    /// How the user authenticated, when there was a user. `None` for
    /// `client_credentials`.
    pub auth: Option<AuthenticationContext>,
    /// Identity profile attributes available for OIDC ID token standard claims.
    /// Populated on the user-bearing grants; empty for `client_credentials`.
    /// Which of these actually reach the ID token is decided by the granted
    /// scopes at mint time, not here.
    pub email: Option<String>,
    pub email_verified: bool,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub code: String,
    pub redirect_uri: String,
    pub state: String,
}

pub enum AuthorizeResult {
    Success(AuthorizeResponse),
    SessionInvalid,
    ReAuthRequired,
    UnauthorizedScope,
    RedirectUriMismatch,
    InvalidPrincipalType(IdentityKind),
    InvalidRequest,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}
