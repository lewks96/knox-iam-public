use crate::error::AppError;
use crate::handlers::build_reset_url;
use crate::middleware::audit_context::AuditCtx;
use crate::middleware::tenant_host::TenantConfig;
use crate::middleware::tenant_host::TenantId;
use crate::state::SharedState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;
use knox_common::error::ServiceError;
use knox_common::identity::{IdentityHandle, MfaOption};
use knox_common::tenant::AuthenticationConfiguration;
use knox_core::authentication::PasswordResetOutcome;
use knox_core::token::TransientKind;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::Duration;
use tracing::{instrument, warn};

#[derive(Debug, Deserialize)]
pub struct AuthenticationParams {
    username: String,
    password: String,
    /// Which OAuth client is being logged into. Required, because it is the only
    /// thing that says which identity pool these credentials should be checked
    /// against — and the login endpoint mints a session before any client is
    /// otherwise involved.
    client_id: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerificationParams {
    mfa_token: String,
    method: MfaOption,
    code: String,
    client_id: String,
}

#[derive(Debug, Serialize)]
pub struct SSOResponse {
    sso: String,
}

fn login_counter_key(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

fn login_window(conf: &AuthenticationConfiguration) -> Duration {
    if conf.login_attempt_window_seconds.is_positive() {
        conf.login_attempt_window_seconds
    } else {
        Duration::seconds(300)
    }
}

async fn counter_is_limited(
    state: &SharedState,
    kind: TransientKind,
    key: &str,
    limit: u32,
) -> Result<bool, AppError> {
    let count: Option<u64> = state
        .token_service
        .retrieve_transient_token(kind, key)
        .await?;
    Ok(count.unwrap_or(0) >= u64::from(limit.max(1)))
}

async fn increment_login_failure(
    state: &SharedState,
    kind: TransientKind,
    key: &str,
    window: Duration,
) -> Result<u64, AppError> {
    state
        .token_service
        .increment_transient_counter(kind, key, window)
        .await
        .map_err(Into::into)
}

/// Sets the SSO cookie and returns the token in the body when the tenant
/// config asks for it. Shared by the password and MFA login paths.
fn sso_ok_response(conf: &AuthenticationConfiguration, jar: CookieJar, sso: String) -> Response {
    let cookie = Cookie::build((conf.sso_cookie_name.clone(), sso.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .max_age(conf.sso_cookie_lifetime_seconds);
    let updated_jar = jar.add(cookie);

    let result = if conf.should_return_cookie_in_body {
        SSOResponse { sso }
    } else {
        SSOResponse { sso: "".into() }
    };
    (StatusCode::OK, updated_jar, Json(result)).into_response()
}

#[instrument(
    name = "knox.authenticate",
    skip_all,
    fields(
        knox.operation = "authenticate",
        knox.tenant_id = %tenant_id,
        knox.username = %params.username
    )
)]
pub async fn authenticate_basic(
    TenantId {
        id: tenant_id,
        issuer: tenant_issuer,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    jar: CookieJar,
    AuditCtx(audit_ctx): AuditCtx,
    State(state): State<SharedState>,
    Json(params): Json<AuthenticationParams>,
) -> Result<impl IntoResponse, AppError> {
    let conf = config.authentication_configuration.clone();
    let window = login_window(&conf);
    let tenant_id_string = tenant_id.to_string();
    let tenant_key = login_counter_key(&[&tenant_id_string]);
    let ip_key = audit_ctx
        .ip
        .as_deref()
        .map(|ip| login_counter_key(&[&tenant_id_string, ip]));

    if counter_is_limited(
        &state,
        TransientKind::LoginTenantAttempts,
        &tenant_key,
        conf.login_max_attempts_per_tenant,
    )
    .await?
    {
        return Err(ServiceError::TooManyAuthenticationAttempts.into());
    }

    if let Some(key) = &ip_key
        && counter_is_limited(
            &state,
            TransientKind::LoginIpAttempts,
            key,
            conf.login_max_attempts_per_ip,
        )
        .await?
    {
        return Err(ServiceError::TooManyAuthenticationAttempts.into());
    }

    // Resolving the client first is what makes the pool boundary structural: the
    // credential lookup below is confined to this client's pool, so an identity
    // in another pool of the same tenant is never even a candidate. A generic
    // error keeps an unknown client_id from being distinguishable from bad
    // credentials.
    let client = match state
        .client_service
        .get_active_client_by_name(tenant_id, &params.client_id)
        .await
    {
        Ok(client) => client,
        Err(_) => {
            let tenant_attempts = increment_login_failure(
                &state,
                TransientKind::LoginTenantAttempts,
                &tenant_key,
                window,
            )
            .await?;
            let ip_attempts = if let Some(key) = &ip_key {
                increment_login_failure(&state, TransientKind::LoginIpAttempts, key, window).await?
            } else {
                0
            };
            if tenant_attempts >= u64::from(conf.login_max_attempts_per_tenant.max(1))
                || ip_attempts >= u64::from(conf.login_max_attempts_per_ip.max(1))
            {
                return Err(ServiceError::TooManyAuthenticationAttempts.into());
            }
            return Err(AppError::Unauthorized("Invalid credentials".into()));
        }
    };
    let pool_id = client.pool_id;
    let account_key = login_counter_key(&[
        &tenant_id.to_string(),
        &pool_id.to_string(),
        &params.username.to_lowercase(),
    ]);

    if counter_is_limited(
        &state,
        TransientKind::LoginAccountAttempts,
        &account_key,
        conf.login_max_attempts_per_account,
    )
    .await?
    {
        return Err(ServiceError::TooManyAuthenticationAttempts.into());
    }

    // An existing SSO cookie deliberately grants NOTHING here.
    //
    // This endpoint used to short-circuit when the caller already held a valid
    // session for the same username, returning 200 without reaching the check
    // below. That made it impossible to re-authenticate anyone: the password
    // went unverified, an enrolled second factor was never demanded, and no
    // `auth.login` audit event was written, because all of that lives in
    // `authenticate_user_sso`. It also deadlocked `max_age`/`prompt=login`,
    // where `/oauth2/authorize` bounces to the login page for a fresh
    // credential check that this path then declined to perform — so the login
    // page bounced straight back, forever.
    //
    // Presenting credentials must verify them. Signing in while already signed
    // in now mints a new session, which is exactly what re-authentication means.

    match state
        .auth_service
        .authenticate_user_sso(
            tenant_id,
            pool_id,
            &tenant_issuer,
            IdentityHandle::Username(params.username),
            &params.password,
            config,
            &audit_ctx,
        )
        .await
    {
        Ok(sso) => {
            let _: Option<u64> = state
                .token_service
                .take_transient_token(TransientKind::LoginAccountAttempts, &account_key)
                .await?;
            Ok(sso_ok_response(&conf, jar, sso))
        }
        Err(e) => {
            if let ServiceError::MfaRequired(c) = e {
                let _: Option<u64> = state
                    .token_service
                    .take_transient_token(TransientKind::LoginAccountAttempts, &account_key)
                    .await?;
                Ok((StatusCode::OK, Json(c)).into_response())
            } else if matches!(
                e,
                ServiceError::InvalidCredentials | ServiceError::Forbidden
            ) {
                let account_attempts = increment_login_failure(
                    &state,
                    TransientKind::LoginAccountAttempts,
                    &account_key,
                    window,
                )
                .await?;
                let tenant_attempts = increment_login_failure(
                    &state,
                    TransientKind::LoginTenantAttempts,
                    &tenant_key,
                    window,
                )
                .await?;
                let ip_attempts = if let Some(key) = &ip_key {
                    increment_login_failure(&state, TransientKind::LoginIpAttempts, key, window)
                        .await?
                } else {
                    0
                };

                if account_attempts >= u64::from(conf.login_max_attempts_per_account.max(1))
                    || tenant_attempts >= u64::from(conf.login_max_attempts_per_tenant.max(1))
                    || ip_attempts >= u64::from(conf.login_max_attempts_per_ip.max(1))
                {
                    Err(ServiceError::TooManyAuthenticationAttempts.into())
                } else {
                    Err(ServiceError::InvalidCredentials.into())
                }
            } else {
                Err(e.into())
            }
        }
    }
}

#[instrument(
    name = "knox.authenticate.mfa",
    skip_all,
    fields(
        knox.operation = "authenticate_mfa",
        knox.tenant_id = %tenant_id,
        knox.mfa_method = ?params.method
    )
)]
pub async fn authenticate_mfa(
    TenantId {
        id: tenant_id,
        issuer: tenant_issuer,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    jar: CookieJar,
    AuditCtx(audit_ctx): AuditCtx,
    State(state): State<SharedState>,
    Json(params): Json<MfaVerificationParams>,
) -> Result<impl IntoResponse, AppError> {
    // The pool the MFA token was minted against must match the client
    // completing the flow — checked inside authenticate_user_mfa.
    let client = state
        .client_service
        .get_active_client_by_name(tenant_id, &params.client_id)
        .await
        .map_err(|_| AppError::Unauthorized("Invalid credentials".into()))?;

    let sso = state
        .auth_service
        .authenticate_user_mfa(
            tenant_id,
            client.pool_id,
            &tenant_issuer,
            &params.mfa_token,
            params.method,
            &params.code,
            &config,
            &audit_ctx,
        )
        .await?;

    Ok(sso_ok_response(
        &config.authentication_configuration,
        jar,
        sso,
    ))
}

// ── Password reset (unauthenticated) ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordParams {
    username: String,
    /// Names the client, and so the pool the handle is looked up in — exactly as
    /// the login endpoint uses it.
    client_id: String,
}

/// `POST /api/authenticate/password/forgot` — request a reset link.
///
/// Always answers `200 {}`, whether or not the handle exists, so it cannot be
/// used to enumerate accounts. Gated behind `self_service_password_reset`
/// (off by default): with no mailer wired up there is nowhere to deliver the
/// link, so until email exists the tenant keeps this closed and the console does
/// not advertise it.
#[instrument(
    name = "knox.authenticate.forgot_password",
    skip_all,
    fields(knox.operation = "forgot_password", knox.tenant_id = %tenant_id)
)]
pub async fn forgot_password(
    TenantId {
        id: tenant_id,
        issuer,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    AuditCtx(audit_ctx): AuditCtx,
    State(state): State<SharedState>,
    Json(params): Json<ForgotPasswordParams>,
) -> Result<impl IntoResponse, AppError> {
    if !config
        .authentication_configuration
        .self_service_password_reset
    {
        // Not enabled for this tenant — indistinguishable from "no such route".
        return Err(AppError::NotFound);
    }

    // Client → pool, same resolution as login; confines the lookup to one
    // directory. An unknown client is the only shape that answers non-200 here,
    // because it is a request error, not an account signal.
    let client = state
        .client_service
        .get_active_client_by_name(tenant_id, &params.client_id)
        .await
        .map_err(|_| AppError::BadRequest("Unknown client".into()))?;

    if let Some((token, _expires_at, identity_id)) = state
        .auth_service
        .request_password_reset_by_username(
            tenant_id,
            client.pool_id,
            &params.username,
            &config,
            &audit_ctx,
        )
        .await?
    {
        let reset_url = build_reset_url(&config, &issuer, &token);
        // No mailer yet: the link has nowhere to go, so it is logged for dev
        // recovery. This is why the feature ships off by default — a real
        // deployment must not rely on links landing in the log.
        warn!(
            identity_id = %identity_id,
            "self_service_password_reset is on but no mailer is configured; reset link (deliver manually): {}",
            reset_url
        );
    }

    Ok((StatusCode::OK, Json(json!({}))))
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordParams {
    token: String,
    new_password: String,
}

/// `POST /api/authenticate/password/reset` — redeem a reset link.
///
/// With no second factor the password is set outright. With one, the password
/// is left untouched and a reset-scoped MFA challenge is returned in the same
/// shape `/api/authenticate` uses, to be completed at `/password/reset/mfa`.
#[instrument(
    name = "knox.authenticate.reset_password",
    skip_all,
    fields(knox.operation = "reset_password", knox.tenant_id = %tenant_id)
)]
pub async fn reset_password(
    TenantId {
        id: tenant_id,
        issuer,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    AuditCtx(audit_ctx): AuditCtx,
    State(state): State<SharedState>,
    Json(params): Json<ResetPasswordParams>,
) -> Result<impl IntoResponse, AppError> {
    let outcome = state
        .auth_service
        .reset_password_with_token(
            tenant_id,
            &issuer,
            &params.token,
            &params.new_password,
            &config,
            &audit_ctx,
        )
        .await?;

    let body = match outcome {
        PasswordResetOutcome::Completed => json!({ "mfa_required": false }),
        PasswordResetOutcome::MfaRequired(details) => json!({
            "mfa_required": true,
            "mfa_token": details.token,
            "methods": details.options,
        }),
    };
    Ok((StatusCode::OK, Json(body)))
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordMfaParams {
    mfa_token: String,
    method: MfaOption,
    code: String,
    new_password: String,
}

/// `POST /api/authenticate/password/reset/mfa` — second factor for a reset.
/// The new password is resubmitted here rather than carried through the
/// challenge, so nothing password-shaped is ever stored between the two steps.
#[instrument(
    name = "knox.authenticate.reset_password.mfa",
    skip_all,
    fields(knox.operation = "reset_password_mfa", knox.tenant_id = %tenant_id, knox.mfa_method = ?params.method)
)]
pub async fn reset_password_mfa(
    TenantId {
        id: tenant_id,
        issuer,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    AuditCtx(audit_ctx): AuditCtx,
    State(state): State<SharedState>,
    Json(params): Json<ResetPasswordMfaParams>,
) -> Result<impl IntoResponse, AppError> {
    state
        .auth_service
        .complete_password_reset_mfa(
            tenant_id,
            &issuer,
            &params.mfa_token,
            params.method,
            &params.code,
            &params.new_password,
            &config,
            &audit_ctx,
        )
        .await?;
    Ok((StatusCode::OK, Json(json!({}))))
}

pub fn authentication_routes() -> Router<SharedState> {
    Router::new()
        .route("/", post(authenticate_basic))
        .route("/mfa", post(authenticate_mfa))
        .route("/password/forgot", post(forgot_password))
        .route("/password/reset", post(reset_password))
        .route("/password/reset/mfa", post(reset_password_mfa))
}
