use crate::middleware::audit_context::AuditCtx;
use crate::middleware::tenant_host::{resolve_tenant_by_id, resolve_tenant_opt};
use axum::{extract::FromRequestParts, http::request::Parts};
use knox_common::audit::{AuditEvent, AuditEventType, AuditOutcome};
use knox_common::pool::PoolKind;
use knox_core::token::JwtClaims;
use tracing::{debug, error, instrument, warn};
use uuid::Uuid;

use crate::{error::AppError, state::SharedState};

/// A verified Bearer token for the management surface: everything `RequireBearer`
/// checks, plus the requirement that the token belongs to a staff pool.
#[derive(Debug, Clone)]
pub struct RequireAuth(pub JwtClaims);

/// A verified Bearer token of *any* pool — the permissive sibling of
/// `RequireAuth`. Use it on end-user-facing routes (e.g. `/oauth2/userinfo`)
/// where a customer-pool identity presenting its own access token is exactly the
/// intended caller, and the staff-pool gate would wrongly reject it.
#[derive(Debug, Clone)]
pub struct RequireBearer(pub JwtClaims);

impl FromRequestParts<SharedState> for RequireBearer {
    type Rejection = AppError;

    #[instrument(skip(state, parts))]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        Ok(RequireBearer(verify_bearer_token(parts, state).await?))
    }
}

impl FromRequestParts<SharedState> for RequireAuth {
    type Rejection = AppError;

    #[instrument(skip(state, parts))]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let claims = verify_bearer_token(parts, state).await?;

        // `/api/*` is the management surface, and every route behind RequireAuth
        // is part of it. A tenant's end users hold perfectly valid tokens for
        // their own application's clients; those tokens must not reach the
        // console's API. RBAC would deny most calls anyway, but "the token is
        // refused at the door" is the property worth having — and it is the one
        // that was missing.
        //
        // End-user self-service (profile, password, MFA enrolment) instead uses
        // `RequireBearer`, which omits exactly this gate.
        if claims.pool_kind != PoolKind::Staff {
            warn!(
                "Non-staff token (pool {}) rejected at management API for tenant {}",
                claims.pool_id, claims.tenant_id
            );
            let AuditCtx(audit_ctx) = AuditCtx::from_request_parts(parts, state)
                .await
                .unwrap_or_else(|e| match e {});
            state.audit_service.record(
                AuditEvent::new(
                    claims.tenant_id,
                    AuditEventType::AuthzCrossTenantDenied,
                    crate::middleware::audit_context::actor_from_claims(&claims),
                    AuditOutcome::Denied,
                    audit_ctx,
                )
                .with_details(serde_json::json!({
                    "reason": "non_staff_pool",
                    "pool_id": claims.pool_id,
                })),
            );
            return Err(AppError::Forbidden(
                "This token cannot access the management API".into(),
            ));
        }

        Ok(RequireAuth(claims))
    }
}

/// Verifies a Bearer access token and returns its claims, having checked
/// signature, issuer, tenant, token version, and that the token's pool matches
/// the client that minted it — everything *except* which surface may use it.
/// `RequireAuth` adds the staff-pool gate on top; `RequireBearer` does not.
#[instrument(skip(state, parts))]
async fn verify_bearer_token(
    parts: &mut Parts,
    state: &SharedState,
) -> Result<JwtClaims, AppError> {
    let auth_header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Authorization header must be a Bearer token".into(),
        ));
    }
    let token = auth_header["Bearer ".len()..].to_string();
    debug!("Extracted token: {}", token);

    // Resolve the tenant once, shared with TenantId/TenantConfig via request
    // extensions. The slug is load-bearing beyond identification: the issuer
    // is per-tenant, so verifying the token requires knowing which tenant's
    // issuer to expect.
    let tenant = match resolve_tenant_opt(parts, state).await? {
        Some(tenant) => tenant,
        None => {
            // Routes without a tenant in the request (e.g. /tenant) carry it
            // in the token instead.
            warn!("Request carries no tenant; extracting tenant_id from JWT payload");
            let tenant_id = extract_tenant_id_from_jwt(&token)?;
            resolve_tenant_by_id(parts, state, tenant_id).await?
        }
    };

    // NOTE on audience: `aud` currently carries the client UUID and doubles
    // as the client lookup key below, so validating it here could only ever
    // compare it against itself. The check that actually has teeth is the
    // pool check further down. Making `aud` meaningful means minting
    // `aud = "knox-api"` and moving the client id to an `azp` claim — worth
    // doing, but independent of this.
    let claims = state
        .token_service
        .verify_jwt(tenant.id, &tenant.issuer, &token, None)
        .await
        .map_err(|e| {
            warn!("JWT verification failed: {}", e);
            AppError::Unauthorized("Invalid or expired token".into())
        })?;

    debug!("Token claims: {:?}", claims);

    // Only meaningful when the tenant came from the request — if it came from
    // the token, comparing it against the token is tautological.
    if tenant.from_request {
        let route_tenant_id = tenant.id;

        if claims.tenant_id != route_tenant_id {
            error!(
                "SECURITY: Cross-tenant access attempt! Token Tenant: {}, Route Tenant: {}",
                claims.tenant_id, route_tenant_id
            );
            // Recorded against the tenant whose resources were targeted.
            let AuditCtx(audit_ctx) = AuditCtx::from_request_parts(parts, state)
                .await
                .unwrap_or_else(|e| match e {});
            state.audit_service.record(
                AuditEvent::new(
                    route_tenant_id,
                    AuditEventType::AuthzCrossTenantDenied,
                    crate::middleware::audit_context::actor_from_claims(&claims),
                    AuditOutcome::Denied,
                    audit_ctx,
                )
                .with_details(serde_json::json!({"token_tenant_id": claims.tenant_id})),
            );
            return Err(AppError::Forbidden(
                "Token does not have access to this tenant".into(),
            ));
        }
    }

    // Validate token version against the current client version
    // Parse the audience claim as a UUID (client_id)
    let client_id = Uuid::parse_str(&claims.aud)
        .map_err(|_| AppError::Unauthorized("Invalid client ID in token".into()))?;

    let client = state
        .client_service
        .get_active_client(tenant.id, client_id)
        .await
        .map_err(|e| {
            warn!("Failed to fetch client during token validation: {}", e);
            AppError::Unauthorized("Invalid client".into())
        })?;

    state
        .token_service
        .validate_token_version(&claims, &client)
        .map_err(|e| {
            warn!("Token version validation failed: {}", e);
            AppError::Unauthorized("Token has been revoked".into())
        })?;

    // The token's pool must agree with the pool of the client that minted
    // it. This is free — the client is already loaded — and it means the
    // `pool_kind` claim below cannot be stale: if a client were re-pointed at
    // a different pool, tokens carrying the old pair stop verifying.
    if claims.pool_id != client.pool_id {
        warn!(
            "Token pool {} does not match client {} pool {}",
            claims.pool_id, client.id, client.pool_id
        );
        return Err(AppError::Unauthorized(
            "Token is not valid for this client".into(),
        ));
    }

    // Interactive access tokens carry auth_time; client_credentials tokens
    // do not. Re-read user subjects so a status change or deletion takes
    // effect immediately instead of waiting for access-token expiry.
    if claims.auth_time.is_some() {
        let identity_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Unauthorized("Invalid identity subject".into()))?;
        let identity = state
            .identity_service
            .get_identity(claims.pool_id, identity_id)
            .await
            .map_err(|_| AppError::Unauthorized("Identity is not active".into()))?;
        if identity.status != knox_common::identity::Status::Active {
            return Err(AppError::Unauthorized("Identity is not active".into()));
        }
    }

    Ok(claims)
}

pub trait ClaimsExt {
    fn require_scope(&self, scope: &str) -> Result<(), AppError>;
    fn require_any_scope(&self, scopes: &[&str]) -> Result<(), AppError>;
}

impl ClaimsExt for JwtClaims {
    fn require_scope(&self, scope: &str) -> Result<(), AppError> {
        if self.scopes.contains(&scope.to_string()) {
            Ok(())
        } else {
            warn!("AuthZ failure: User {} missing scope {}", self.sub, scope);
            Err(AppError::Forbidden(format!("Requires scope: {}", scope)))
        }
    }

    fn require_any_scope(&self, scopes: &[&str]) -> Result<(), AppError> {
        if scopes.iter().any(|&s| self.scopes.contains(&s.to_string())) {
            Ok(())
        } else {
            warn!(
                "AuthZ failure: User {} missing one of scopes {:?}",
                self.sub, scopes
            );
            Err(AppError::Forbidden(format!(
                "Requires one of scopes: {:?}",
                scopes
            )))
        }
    }
}

#[derive(serde::Deserialize)]
struct PartialClaims {
    tenant_id: Uuid,
}

fn extract_tenant_id_from_jwt(token: &str) -> Result<Uuid, AppError> {
    let payload_b64 = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AppError::Unauthorized("Malformed JWT".into()))?;

    let payload_bytes = base64url_decode(payload_b64)
        .map_err(|_| AppError::Unauthorized("Invalid JWT payload encoding".into()))?;

    let partial: PartialClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AppError::Unauthorized("JWT payload missing tenant_id".into()))?;

    Ok(partial.tenant_id)
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, ()> {
    // Base64url → standard Base64: swap alphabet chars and re-add padding.
    let mut b64 = input.replace('-', "+").replace('_', "/");
    match b64.len() % 4 {
        2 => b64.push_str("=="),
        3 => b64.push('='),
        0 => {}
        _ => return Err(()),
    }

    // RFC 4648 standard base64 decode table
    let mut buf = Vec::with_capacity(b64.len() * 3 / 4);
    let bytes = b64.as_bytes();

    for chunk in bytes.chunks(4) {
        let mut sextet = [0u8; 4];
        for (i, &b) in chunk.iter().enumerate() {
            sextet[i] = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => return Err(()),
            };
        }
        buf.push((sextet[0] << 2) | (sextet[1] >> 4));
        if chunk.len() > 2 && chunk[2] != b'=' {
            buf.push((sextet[1] << 4) | (sextet[2] >> 2));
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            buf.push((sextet[2] << 6) | sextet[3]);
        }
    }

    Ok(buf)
}
