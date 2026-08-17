use crate::middleware::audit_context::AuditCtx;
use crate::middleware::auth::RequireBearer;
use crate::middleware::tenant_host::TenantConfig;
use crate::middleware::tenant_host::TenantId;
use crate::{error::AppError, state::SharedState};
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
use base64::{Engine, engine::general_purpose::STANDARD};
use knox_common::error::{OIDCError, ServiceError};
use knox_common::tenant::TenantConfiguration;
use knox_core::roles::OIDC_SCOPES;
use knox_services::TokenGrantRequest;
use knox_services::oidc::models::{AuthorizeRequest, AuthorizeResult, CodeChallengeMethod};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, instrument};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct TokenRequestForm {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthorizeRequestParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    /// OAuth 2.0 requires this. Knox only implements the code flow, so a present
    /// value other than `code` is rejected; an absent one is treated as `code`
    /// for compatibility with existing relying parties.
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub max_age: Option<u32>,
    pub acr_values: Option<String>,
    pub response_mode: Option<String>,
    pub prompt: Option<String>,
    pub login_hint: Option<String>,
}

/// Adds the caching headers RFC 6749 §5.1 requires on every token-endpoint
/// response — success or error — so tokens are never stored by a cache.
fn apply_no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

/// An RFC 6749 §5.2 error response: `{"error":"…","error_description":"…"}` with
/// the correct status and the no-store headers §5.1 requires.
fn oauth_error(status: StatusCode, code: &str, description: &str) -> Response {
    let mut resp = (
        status,
        Json(json!({ "error": code, "error_description": description })),
    )
        .into_response();
    apply_no_store(resp.headers_mut());
    resp
}

/// Maps a token-grant failure to its RFC 6749 §5.2 error code. Internal faults
/// collapse to `server_error` with a generic message so nothing leaks; every
/// other variant names the specific reason the grant was refused.
fn token_error(error: &ServiceError) -> Response {
    let (status, code) = match error {
        ServiceError::OIDC(OIDCError::InvalidClientSecret) => {
            (StatusCode::UNAUTHORIZED, "invalid_client")
        }
        ServiceError::OIDC(OIDCError::InvalidGrant) => (StatusCode::BAD_REQUEST, "invalid_grant"),
        ServiceError::OIDC(OIDCError::UnauthorizedClient) => {
            (StatusCode::BAD_REQUEST, "unauthorized_client")
        }
        ServiceError::OIDC(OIDCError::InvalidScope) => (StatusCode::BAD_REQUEST, "invalid_scope"),
        ServiceError::OIDC(OIDCError::InvalidRequest(_)) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        ServiceError::OIDC(OIDCError::UnsupportedResponseType) => {
            (StatusCode::BAD_REQUEST, "unsupported_response_type")
        }
        ServiceError::OIDC(OIDCError::AccessDenied) => (StatusCode::FORBIDDEN, "access_denied"),
        // A bad, expired, or reused code or refresh token, or a redirect_uri that
        // no longer matches — all "the presented grant is invalid".
        ServiceError::InvalidAuthCode
        | ServiceError::RedirectUriMismatch
        | ServiceError::InvalidCredentials => (StatusCode::BAD_REQUEST, "invalid_grant"),
        // The identity holds none of the requested scopes.
        ServiceError::Forbidden => (StatusCode::BAD_REQUEST, "invalid_scope"),
        ServiceError::Validation(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let description = if status.is_server_error() {
        "The authorization server encountered an unexpected condition".to_string()
    } else {
        error.to_string()
    };
    oauth_error(status, code, &description)
}

fn extract_client_credentials(
    headers: &HeaderMap,
    form: &TokenRequestForm,
) -> Result<(String, Option<String>), AppError> {
    // Try Basic auth header first
    if let Some(auth_header) = headers.get("authorization") {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| AppError::BadRequest("Invalid Authorization header".into()))?;

        if let Some(basic_creds) = auth_str.strip_prefix("Basic ") {
            let decoded = STANDARD
                .decode(basic_creds.trim())
                .map_err(|_| AppError::BadRequest("Invalid Basic auth encoding".into()))?;
            let decoded_str = String::from_utf8(decoded)
                .map_err(|_| AppError::BadRequest("Invalid Basic auth encoding".into()))?;

            let (client_id, client_secret) = decoded_str
                .split_once(':')
                .ok_or_else(|| AppError::BadRequest("Invalid Basic auth format".into()))?;

            return Ok((client_id.to_string(), Some(client_secret.to_string())));
        }
    }

    // Fall back to form body
    let client_id = form
        .client_id
        .clone()
        .ok_or_else(|| AppError::BadRequest("client_id required".into()))?;

    Ok((client_id, form.client_secret.clone()))
}

#[instrument(
    name = "knox.oauth2.token",
    skip_all,
    fields(
        knox.operation = "oauth2_token",
        knox.tenant_id = %tenant_id,
        knox.grant_type = %form.grant_type
    )
)]
pub async fn token_endpoint(
    TenantId {
        id: tenant_id,
        issuer: tenant_issuer,
        is_platform: tenant_is_platform,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    AuditCtx(audit_ctx): AuditCtx,
    State(state): State<SharedState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequestForm>,
) -> Response {
    debug!(grant_type = %form.grant_type, "Processing token request");

    let (client_id, client_secret) = match extract_client_credentials(&headers, &form) {
        Ok(creds) => creds,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Malformed client credentials",
            );
        }
    };

    let grant_request = match form.grant_type.as_str() {
        "client_credentials" => {
            let Some(secret) = client_secret else {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "client_secret is required for client_credentials",
                );
            };
            TokenGrantRequest::ClientCredentials {
                client_id,
                client_secret: secret,
                scope: form.scope,
            }
        }
        "authorization_code" => {
            let (Some(code), Some(code_verifier)) = (form.code, form.code_verifier) else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code and code_verifier are required for authorization_code",
                );
            };
            TokenGrantRequest::AuthorizationCode {
                client_id,
                client_secret,
                code,
                redirect_uri: form.redirect_uri,
                code_verifier,
            }
        }
        "refresh_token" => {
            let Some(refresh_token) = form.refresh_token else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                );
            };
            TokenGrantRequest::RefreshToken {
                client_id,
                client_secret,
                refresh_token,
            }
        }
        other => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                &format!("Unsupported grant_type: {other}"),
            );
        }
    };

    match state
        .oidc_service
        .handle_token_request(
            tenant_id,
            tenant_is_platform,
            &tenant_issuer,
            grant_request,
            &config.authorization_configuration,
            &audit_ctx,
        )
        .await
    {
        Ok(response) => {
            let mut resp = (StatusCode::OK, Json(response)).into_response();
            apply_no_store(resp.headers_mut());
            resp
        }
        Err(e) => token_error(&e),
    }
}

#[instrument(
    name = "knox.oauth2.authorize",
    skip_all,
    fields(
        knox.operation = "oauth2_authorize_get",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn authorize_endpoint_get(
    TenantId {
        id: tenant_id,
        slug: _tenant_slug,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    State(state): State<SharedState>,
    jar: CookieJar,
    Query(params): Query<AuthorizeRequestParams>,
) -> Result<impl IntoResponse, AppError> {
    handle_authorize(tenant_id, config, state, jar, params).await
}

#[instrument(
    name = "knox.oauth2.authorize",
    skip_all,
    fields(
        knox.operation = "oauth2_authorize_post",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn authorize_endpoint_post(
    TenantId {
        id: tenant_id,
        slug: _tenant_slug,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    State(state): State<SharedState>,
    jar: CookieJar,
    Form(params): Form<AuthorizeRequestParams>,
) -> Result<impl IntoResponse, AppError> {
    handle_authorize(tenant_id, config, state, jar, params).await
}

#[instrument(skip_all, fields(knox.tenant_id = %tenant_id))]
async fn handle_authorize(
    tenant_id: Uuid,
    config: TenantConfiguration,
    state: SharedState,
    jar: CookieJar,
    params: AuthorizeRequestParams,
) -> Result<impl IntoResponse, AppError> {
    let params_clone = params.clone();

    // Only the code flow exists. `response_type` is validated before the
    // redirect_uri is (which the service does), so a rejection here can't be
    // safely redirected — hence a direct 400 rather than an error redirect.
    if let Some(ref rt) = params.response_type {
        if rt != "code" {
            return Err(AppError::BadRequest(format!(
                "unsupported_response_type: {rt}"
            )));
        }
    }

    if let Some(ref mode) = params.response_mode {
        if mode != "query" {
            return Err(AppError::BadRequest(format!(
                "Unsupported response_mode: {}",
                mode
            )));
        }
    }

    // `prompt=none` (OIDC Core §3.1.2.1) forbids showing any UI: if the request
    // cannot be satisfied silently the relying party gets `login_required` back
    // at its redirect_uri rather than the user getting a login page.
    let silent = params.prompt.as_deref() == Some("none");

    let sso_token =
        if let Some(sso_token) = jar.get(&config.authentication_configuration.sso_cookie_name) {
            sso_token.value().to_string()
        } else if silent {
            // No session and no UI allowed. The error may only be handed back to a
            // *registered* redirect_uri (RFC 6749 §4.1.2.1) — unlike the paths below,
            // this one runs before the service has validated it, so check it here or
            // an attacker's redirect_uri would receive the redirect.
            return Ok(silent_login_required(&state, tenant_id, &params_clone).await);
        } else {
            let location = login_redirect(&params_clone, false);
            return Ok((StatusCode::FOUND, [("Location", location)]).into_response());
        };

    let authorize_request = AuthorizeRequest {
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: match params.code_challenge_method.as_deref() {
            Some("S256") | None => CodeChallengeMethod::S256,
            Some(m) => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported code_challenge_method: {}",
                    m
                )));
            }
        },
        scope: params
            .scope
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        nonce: params.nonce,
        max_age: params.max_age,
        acr_values: params
            .acr_values
            .map(|s| s.split_whitespace().map(str::to_owned).collect()),
        prompt: params.prompt,
        sso_token,
    };

    let result = state
        .oidc_service
        .handle_authorize_request(
            tenant_id,
            authorize_request,
            &config.authorization_configuration,
        )
        .await?;

    match result {
        AuthorizeResult::Success(response) => {
            let location = format!(
                "{}?code={}&state={}",
                response.redirect_uri, response.code, response.state,
            );
            Ok((StatusCode::FOUND, [("Location", location)]).into_response())
        }
        AuthorizeResult::SessionInvalid => {
            if silent {
                return Ok(error_redirect(
                    &params_clone,
                    "login_required",
                    Some("No active session"),
                ));
            }
            let location = login_redirect(&params_clone, false);
            Ok((StatusCode::FOUND, [("Location", location)]).into_response())
        }
        AuthorizeResult::ReAuthRequired => {
            if silent {
                return Ok(error_redirect(
                    &params_clone,
                    "login_required",
                    Some("Re-authentication required"),
                ));
            }
            let location = login_redirect(&params_clone, true);
            Ok((StatusCode::FOUND, [("Location", location)]).into_response())
        }
        // The redirect_uri failed validation, so it is exactly the URI Knox must
        // NOT redirect to — the error is shown to the user instead.
        AuthorizeResult::RedirectUriMismatch => {
            Err(AppError::BadRequest("Invalid redirect_uri".into()))
        }
        AuthorizeResult::UnauthorizedScope => Ok(error_redirect(
            &params_clone,
            "invalid_scope",
            Some("The client is not permitted one or more requested scopes"),
        )),
        AuthorizeResult::InvalidPrincipalType(_) => Ok(error_redirect(
            &params_clone,
            "unauthorized_client",
            Some("This client cannot be used by this principal"),
        )),
        // Malformed request (bad PKCE challenge, empty scope). The redirect_uri
        // was validated before this is returned, so the error is safe to hand
        // back to the relying party rather than crashing the handler.
        AuthorizeResult::InvalidRequest => Ok(error_redirect(
            &params_clone,
            "invalid_request",
            Some("The request is missing a required parameter or is otherwise malformed"),
        )),
    }
}

/// Handles `prompt=none` with no session: the error may only be redirected to a
/// registered `redirect_uri`, so an unknown client or unregistered URI is shown
/// to the user (400) rather than redirected to.
async fn silent_login_required(
    state: &SharedState,
    tenant_id: Uuid,
    params: &AuthorizeRequestParams,
) -> Response {
    match state
        .client_service
        .get_active_client_by_name(tenant_id, &params.client_id)
        .await
    {
        Ok(client) if client.redirect_uris.contains(&params.redirect_uri) => error_redirect(
            params,
            "login_required",
            Some("Authentication is required but prompt=none was requested"),
        ),
        _ => AppError::BadRequest("Invalid client_id or redirect_uri".into()).into_response(),
    }
}

/// Where to send an unauthenticated user so they can log in and *resume* this
/// authorize request.
///
/// `return_to` carries the original authorize URL; once the login page has
/// established the SSO cookie it bounces back there, and the second pass through
/// `/oauth2/authorize` issues the code to the relying party. Without it a
/// server-initiated authorize strands the user on the dashboard and the RP never
/// receives its code.
///
/// Only `return_to` is passed: it already encodes client_id, redirect_uri, state
/// and the PKCE challenge, so the login page needs nothing else. It is always a
/// host-relative path, which is what lets the login page reject anything absolute
/// as an open-redirect attempt.
///
/// Note that `prompt` and `max_age` are deliberately absent from the resumed URL
/// — see [`params_to_authorize_url`].
fn login_redirect(params: &AuthorizeRequestParams, prompt_login: bool) -> String {
    let authorize_url = params_to_authorize_url(params);
    let return_to = urlencoding::encode(&authorize_url);
    if prompt_login {
        format!("/login?prompt=login&return_to={return_to}")
    } else {
        format!("/login?return_to={return_to}")
    }
}

/// Rebuilds the authorize URL for the login page to resume.
///
/// `prompt` and `max_age` are deliberately dropped. Both exist to demand a
/// fresh credential check, and this URL is only ever reached *after* one has
/// happened — carrying them over would re-demand what was just satisfied.
///
/// For `max_age` that is not merely redundant but non-terminating: the check is
/// `age > max_age`, so `max_age=0` rejects a session minted milliseconds ago.
/// Left in, the login page and `/oauth2/authorize` would bounce the user
/// between them forever, with no reachable state that ever satisfies the
/// condition.
fn params_to_authorize_url(params: &AuthorizeRequestParams) -> String {
    let mut parts = vec![
        format!("client_id={}", urlencoding::encode(&params.client_id)),
        format!("redirect_uri={}", urlencoding::encode(&params.redirect_uri)),
        format!("state={}", urlencoding::encode(&params.state)),
        format!(
            "code_challenge={}",
            urlencoding::encode(&params.code_challenge)
        ),
        "response_type=code".to_string(),
    ];

    if let Some(ref scope) = params.scope {
        parts.push(format!("scope={}", urlencoding::encode(scope)));
    }
    if let Some(ref method) = params.code_challenge_method {
        parts.push(format!(
            "code_challenge_method={}",
            urlencoding::encode(method)
        ));
    }
    if let Some(ref nonce) = params.nonce {
        parts.push(format!("nonce={}", urlencoding::encode(nonce)));
    }
    if let Some(ref acr) = params.acr_values {
        parts.push(format!("acr_values={}", urlencoding::encode(acr)));
    }

    format!("/oauth2/authorize?{}", parts.join("&"))
}

/// Hands an OAuth error back to the relying party at its own redirect_uri,
/// which is where a client is entitled to look for it. Used for conditions the
/// RP asked us not to resolve interactively.
fn error_redirect(
    params: &AuthorizeRequestParams,
    error: &str,
    description: Option<&str>,
) -> Response {
    let mut location = format!(
        "{}?error={}&state={}",
        params.redirect_uri,
        error,
        urlencoding::encode(&params.state),
    );
    if let Some(desc) = description {
        location.push_str(&format!("&error_description={}", urlencoding::encode(desc)));
    }
    (StatusCode::FOUND, [("Location", location)]).into_response()
}

#[instrument(
    name = "knox.jwks",
    skip_all,
    fields(
        knox.operation = "jwks_get",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn get_jwks(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
) -> Result<impl IntoResponse, AppError> {
    let jwks = state.key_service.get_jwks(tenant_id).await?;
    Ok((StatusCode::OK, Json(jwks)))
}

/// The UserInfo claims Knox can return (OpenID Connect Core §5.3). `sub` is
/// always present; the rest are released according to the access token's
/// scopes — `email` for the email claims, `profile` for the name ones — and
/// omitted when absent so a caller never sees a null for a claim it wasn't
/// granted or the identity doesn't have.
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    family_name: Option<String>,
}

/// `GET|POST /oauth2/userinfo` — OpenID Connect UserInfo endpoint (Core §5.3).
///
/// Authenticated by the access token alone via `RequireBearer` (not
/// `RequireAuth`): the caller is an end user presenting their own token, which
/// the management-API staff gate would wrongly reject. The token must carry the
/// `openid` scope, and its `sub` must resolve to an identity in the token's
/// pool — a `client_credentials` token has no user and so cannot call this.
#[instrument(
    name = "knox.userinfo",
    skip_all,
    fields(knox.operation = "userinfo_get", knox.tenant_id = %claims.tenant_id)
)]
pub async fn userinfo_endpoint(
    RequireBearer(claims): RequireBearer,
    State(state): State<SharedState>,
) -> Result<Response, AppError> {
    if !claims.scopes.iter().any(|s| s == "openid") {
        // RFC 6750 §3: a Bearer-protected resource refusing a token for want of
        // scope answers 403 with the reason in a WWW-Authenticate challenge.
        let mut resp = AppError::Forbidden("The access token must carry the 'openid' scope".into())
            .into_response();
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"insufficient_scope\", scope=\"openid\""),
        );
        return Ok(resp);
    }

    let identity_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Token subject is not an identity".into()))?;
    let identity = state
        .identity_service
        .get_identity(claims.pool_id, identity_id)
        .await
        .map_err(|_| AppError::Unauthorized("Token subject not found".into()))?;

    let email_scoped = claims.scopes.iter().any(|s| s == "email");
    let profile_scoped = claims.scopes.iter().any(|s| s == "profile");

    let name = match (&identity.first_name, &identity.last_name) {
        (Some(f), Some(l)) => Some(format!("{f} {l}")),
        (Some(f), None) => Some(f.clone()),
        (None, Some(l)) => Some(l.clone()),
        (None, None) => None,
    };

    let response = UserInfoResponse {
        sub: identity.id.to_string(),
        email: if email_scoped {
            identity.email.clone()
        } else {
            None
        },
        // Only meaningful alongside an email claim.
        email_verified: if email_scoped && identity.email.is_some() {
            Some(identity.email_verified)
        } else {
            None
        },
        name: if profile_scoped { name } else { None },
        preferred_username: if profile_scoped {
            Some(identity.username.clone())
        } else {
            None
        },
        given_name: if profile_scoped {
            identity.first_name.clone()
        } else {
            None
        },
        family_name: if profile_scoped {
            identity.last_name.clone()
        } else {
            None
        },
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// OpenID Provider Metadata (OpenID Connect Discovery 1.0, §3).
///
/// Only what Knox actually implements is advertised — a relying party is
/// entitled to treat every URL here as callable. There is still no
/// `end_session_endpoint`, `revocation_endpoint` or `introspection_endpoint`
/// because those routes do not exist yet. `scopes_supported` lists only the
/// standard OIDC scopes: RBAC permission scopes are per-tenant and per-client,
/// not a fixed deployment-wide set, so advertising them here would misrepresent
/// what any given client may request.
#[derive(Debug, Serialize)]
pub struct OpenIdConfiguration {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
    scopes_supported: Vec<&'static str>,
    claims_supported: Vec<&'static str>,
}

#[instrument(
    name = "knox.openid_configuration",
    skip_all,
    fields(
        knox.operation = "openid_configuration_get",
        knox.tenant_slug = %tenant_slug
    )
)]
pub async fn get_openid_configuration(
    TenantId {
        slug: tenant_slug,
        issuer,
        ..
    }: TenantId,
) -> Result<impl IntoResponse, AppError> {
    // `issuer` must byte-match the `iss` claim Knox mints. Both now read the
    // same stored value on the tenant row, so they cannot drift.
    let config = OpenIdConfiguration {
        authorization_endpoint: format!("{issuer}/oauth2/authorize"),
        token_endpoint: format!("{issuer}/oauth2/token"),
        userinfo_endpoint: format!("{issuer}/oauth2/userinfo"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        issuer,
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "client_credentials", "refresh_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec!["RS256"],
        // Basic header, form body, or neither (public clients using PKCE).
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        code_challenge_methods_supported: vec!["S256"],
        scopes_supported: OIDC_SCOPES.to_vec(),
        // The claims that can appear in an ID token or UserInfo response.
        claims_supported: vec![
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "azp",
            "at_hash",
            "email",
            "email_verified",
            "name",
            "preferred_username",
            "given_name",
            "family_name",
        ],
    };

    Ok((StatusCode::OK, Json(config)))
}

pub fn oidc_routes() -> Router<SharedState> {
    Router::new()
        .route("/.well-known/jwks.json", get(get_jwks))
        .route(
            "/.well-known/openid-configuration",
            get(get_openid_configuration),
        )
        .route("/oauth2/token", post(token_endpoint))
        .route(
            "/oauth2/authorize",
            get(authorize_endpoint_get).post(authorize_endpoint_post),
        )
        .route(
            "/oauth2/userinfo",
            get(userinfo_endpoint).post(userinfo_endpoint),
        )
}
