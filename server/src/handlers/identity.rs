use crate::handlers::{GenericResponse, build_reset_url, self_identity_id};
use crate::{
    error::AppError,
    middleware::audit_context::{AuditCtx, actor_from_claims},
    middleware::auth::{ClaimsExt, RequireAuth},
    middleware::tenant_host::{TenantConfig, TenantId},
    state::SharedState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, patch, post},
};
use knox_common::audit::{AuditEvent, AuditEventType, AuditOutcome};
use knox_common::identity::{MfaOption, PublicIdentity, Status};
use knox_core::authentication::ChangePasswordOutcome;
use knox_core::identity::{
    CreateIdentityRequest, IdentitySearchRequest, RoleAssignmentRequest, UpdateIdentityRequest,
};
use knox_core::roles::{
    IDENTITY_CREATE_SCOPE, IDENTITY_DELETE_SCOPE, IDENTITY_READ_SCOPE, IDENTITY_UPDATE_SCOPE,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, to_value};
use time::OffsetDateTime;
use tracing::{debug, instrument};
use uuid::Uuid;

/// Targets a pool other than the caller's own, for admins managing a tenant's
/// end users from the console.
#[derive(Debug, Deserialize)]
pub struct PoolQuery {
    pub pool_id: Option<Uuid>,
}

/// Resolves which pool an operation acts on: the caller's own unless another is
/// named, and then only one belonging to the caller's tenant. `get_pool` is
/// tenant-scoped, so a pool id from another tenant resolves to nothing rather
/// than crossing the boundary.
async fn resolve_pool(
    state: &SharedState,
    tenant_id: Uuid,
    caller_pool: Uuid,
    requested: Option<Uuid>,
) -> Result<Uuid, AppError> {
    match requested {
        None => Ok(caller_pool),
        Some(p) if p == caller_pool => Ok(caller_pool),
        Some(p) => {
            state.tenant_service.get_pool(tenant_id, p).await?;
            Ok(p)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IdentityPath {
    pub identity_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct RolePath {
    pub identity_id: Uuid,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateIdentityDto {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    /// Roles to grant on creation — this is how an administrator is made.
    ///
    /// Every identity also gets `IdentitySelf` regardless; these are additional.
    /// Subject to the same no-escalation rule as `POST /identity/{id}/roles`:
    /// you cannot grant a role carrying permissions you do not hold yourself.
    pub roles: Option<Vec<String>>,
    /// Which directory to create the identity in. Defaults to the caller's own
    /// pool, so an admin creating a user through the console gets another staff
    /// member unless they deliberately target an end-user pool.
    pub pool_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIdentityDto {
    pub email: Option<String>,
    pub username: Option<String>,
    pub status: Option<Status>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub metadata: Option<Value>,
    pub custom_attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ListIdentitiesQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub query: Option<String>,
    pub status: Option<Status>,
    /// Defaults to the caller's own pool. The console is a staff surface, so
    /// listing must not silently mix in a tenant's end users.
    pub pool_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct ListIdentitiesResponse {
    pub items: Vec<PublicIdentity>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

#[instrument(
    name = "knox.identity.create",
    skip_all,
    fields(
        knox.operation = "identity_create",
        knox.tenant_id = %tenant_id,
        knox.email = %payload.email
    )
)]
pub async fn create_identity(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    Json(payload): Json<CreateIdentityDto>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Creating new identity for email: {}", payload.email);
    claims.require_scope(IDENTITY_CREATE_SCOPE)?;

    let pool_id = resolve_pool(&state, tenant_id, claims.pool_id, payload.pool_id).await?;

    // Checked before the identity exists, so a rejected grant cannot leave a
    // half-provisioned account behind.
    for role in payload.roles.iter().flatten() {
        state
            .identity_service
            .ensure_can_grant(tenant_id, role, &claims.scopes)
            .await?;
    }

    let obj = CreateIdentityRequest {
        tenant_id,
        pool_id,
        email: payload.email.clone(),
        username: payload.email.clone(),
        password: payload.password.clone(),
        initial_roles: payload.roles.clone(),
        first_name: payload.first_name.clone(),
        last_name: payload.last_name.clone(),
    };

    let identity = state.identity_service.create_user(obj).await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::IdentityCreated,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("identity", identity.id.to_string()),
    );

    Ok((StatusCode::CREATED, Json(PublicIdentity::from(identity))))
}

#[instrument(
    name = "knox.identity.update",
    skip_all,
    fields(
        knox.operation = "identity_update",
        knox.tenant_id = %tenant_id,
        knox.identity_id = %identity_id
    )
)]
pub async fn update_identity(
    TenantId { id: tenant_id, .. }: TenantId,
    TenantConfig(config): TenantConfig,
    Path(IdentityPath { identity_id }): Path<IdentityPath>,
    Query(pool_q): Query<PoolQuery>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    Json(update_payload): Json<UpdateIdentityDto>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Updating identity: {}", identity_id);
    claims.require_scope(IDENTITY_UPDATE_SCOPE)?;

    if claims.sub != identity_id.to_string()
        && !claims.scopes.contains(&IDENTITY_CREATE_SCOPE.to_string())
    {
        debug!(
            "User {} attempted to update another identity {} without elevated scope",
            claims.sub, identity_id
        );
        return Err(AppError::Forbidden(
            "Cannot update another identity without elevated scope".into(),
        ));
    }

    let requested_status = update_payload.status;
    let update = UpdateIdentityRequest {
        email: update_payload.email,
        username: update_payload.username,
        first_name: update_payload.first_name,
        last_name: update_payload.last_name,
        status: requested_status,
        metadata: update_payload.metadata,
        custom_attributes: update_payload.custom_attributes,
    };

    let pool_id = resolve_pool(&state, tenant_id, claims.pool_id, pool_q.pool_id).await?;
    let updated = state
        .identity_service
        .update_identity(pool_id, identity_id, update.clone())
        .await?;

    if requested_status.is_some() && updated.status != Status::Active {
        state
            .auth_service
            .revoke_all_sessions(tenant_id, identity_id, &config)
            .await?;
    }

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::IdentityUpdated,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("identity", identity_id.to_string())
        .with_details(to_value(update).unwrap_or(Value::Null)),
    );

    Ok((StatusCode::OK, Json(PublicIdentity::from(updated))))
}

#[instrument(
    name = "knox.identity.delete",
    skip_all,
    fields(
        knox.operation = "identity_delete",
        knox.tenant_id = %tenant_id,
        knox.identity_id = %identity_id
    )
)]
pub async fn delete_identity(
    TenantId { id: tenant_id, .. }: TenantId,
    TenantConfig(config): TenantConfig,
    Path(IdentityPath { identity_id }): Path<IdentityPath>,
    Query(pool_q): Query<PoolQuery>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    State(state): State<SharedState>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Deleting identity: {}", identity_id);
    claims.require_scope(IDENTITY_DELETE_SCOPE)?;

    // Non-admins can only delete themselves
    if claims.sub != identity_id.to_string()
        && !claims.scopes.contains(&IDENTITY_CREATE_SCOPE.to_string())
    {
        debug!(
            "User {} attempted to delete another identity {} without elevated scope",
            claims.sub, identity_id
        );
        return Err(AppError::Forbidden(
            "Cannot delete another identity without elevated scope".into(),
        ));
    }

    debug!("Authorization checks passed, proceeding with deletion");
    let pool_id = resolve_pool(&state, tenant_id, claims.pool_id, pool_q.pool_id).await?;
    state
        .auth_service
        .revoke_all_sessions(tenant_id, identity_id, &config)
        .await?;
    state
        .identity_service
        .delete_identity(pool_id, identity_id)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::IdentityDeleted,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("identity", identity_id.to_string()),
    );

    Ok((
        StatusCode::OK,
        Json(GenericResponse {
            message: "Identity deleted".into(),
            detail: None,
        }),
    ))
}

#[instrument(
    name = "knox.identity.list",
    skip_all,
    fields(
        knox.operation = "identity_list",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn list_identities(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    Query(query): Query<ListIdentitiesQuery>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Listing identities for tenant: {}", tenant_id);
    claims.require_scope(IDENTITY_READ_SCOPE)?;

    // Only admins can list all identities
    if !claims.scopes.contains(&IDENTITY_CREATE_SCOPE.to_string()) {
        debug!(
            "User {} attempted to list identities without elevated scope",
            claims.sub
        );
        return Err(AppError::Forbidden(
            "Cannot list identities without elevated scope".into(),
        ));
    }

    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20).min(100);

    let pool_id = resolve_pool(&state, tenant_id, claims.pool_id, query.pool_id).await?;

    let req = IdentitySearchRequest {
        tenant_id,
        pool_id: Some(pool_id),
        page,
        page_size,
        query: query.query,
        status: query.status,
    };

    let (identities, total) = state.identity_service.list_identities(req).await?;

    Ok((
        StatusCode::OK,
        Json(ListIdentitiesResponse {
            items: identities.into_iter().map(PublicIdentity::from).collect(),
            total,
            page,
            page_size,
        }),
    ))
}

#[instrument(
    name = "knox.identity.get",
    skip_all,
    fields(
        knox.operation = "identity_get",
        knox.tenant_id = %tenant_id,
        knox.identity_id = %identity_id
    )
)]
pub async fn get_identity(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(identity_id): Path<Uuid>,
    Query(pool_q): Query<PoolQuery>,
    RequireAuth(claims): RequireAuth,
    State(state): State<SharedState>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Fetching identity: {}", identity_id);
    claims.require_scope(IDENTITY_READ_SCOPE)?;

    // Non-admins can only read themselves
    if claims.sub != identity_id.to_string()
        && !claims.scopes.contains(&IDENTITY_CREATE_SCOPE.to_string())
    {
        debug!(
            "User {} attempted to read another identity {} without elevated scope",
            claims.sub, identity_id
        );
        return Err(AppError::Forbidden(
            "Cannot read another identity without elevated scope".into(),
        ));
    }
    debug!("Authorization checks passed, proceeding with fetch");

    let identity = state
        .identity_service
        .get_identity(
            resolve_pool(&state, tenant_id, claims.pool_id, pool_q.pool_id).await?,
            identity_id,
        )
        .await?;

    Ok((StatusCode::OK, Json(PublicIdentity::from(identity))))
}

#[derive(Debug, Deserialize)]
pub struct AssignRoleDto {
    pub role: String,
}

#[instrument(
    name = "knox.identity.roles.list",
    skip(state, claims),
    fields(knox.operation = "identity_roles_list", knox.tenant_id = %tenant_id)
)]
pub async fn list_identity_roles(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(IdentityPath { identity_id }): Path<IdentityPath>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(IDENTITY_READ_SCOPE)?;
    if claims.sub != identity_id.to_string()
        && !claims.scopes.contains(&IDENTITY_CREATE_SCOPE.to_string())
    {
        return Err(AppError::Forbidden(
            "Cannot read another identity without elevated scope".into(),
        ));
    }
    let roles = state
        .identity_service
        .get_identity_roles(tenant_id, identity_id)
        .await?;
    Ok((StatusCode::OK, Json(roles)))
}

#[instrument(
    name = "knox.identity.roles.assign",
    skip(state, claims, payload),
    fields(knox.operation = "identity_role_assign", knox.tenant_id = %tenant_id)
)]
pub async fn assign_identity_role(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(IdentityPath { identity_id }): Path<IdentityPath>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    Json(payload): Json<AssignRoleDto>,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(IDENTITY_UPDATE_SCOPE)?;

    state
        .identity_service
        .assign_role(
            RoleAssignmentRequest {
                tenant_id,
                identity_id,
                role_name: payload.role.clone(),
            },
            &claims.scopes,
        )
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::RoleAssigned,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("identity", identity_id.to_string())
        .with_details(to_value(&payload.role).unwrap_or(Value::Null)),
    );

    Ok((
        StatusCode::OK,
        Json(GenericResponse {
            message: format!("Role '{}' assigned", payload.role),
            detail: None,
        }),
    ))
}

#[instrument(
    name = "knox.identity.roles.revoke",
    skip(state, claims),
    fields(knox.operation = "identity_role_revoke", knox.tenant_id = %tenant_id)
)]
pub async fn revoke_identity_role(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(RolePath { identity_id, role }): Path<RolePath>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(IDENTITY_UPDATE_SCOPE)?;

    state
        .identity_service
        .revoke_role(
            RoleAssignmentRequest {
                tenant_id,
                identity_id,
                role_name: role.clone(),
            },
            &claims.scopes,
        )
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::RoleRevoked,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("identity", identity_id.to_string())
        .with_details(to_value(&role).unwrap_or(Value::Null)),
    );

    Ok((
        StatusCode::OK,
        Json(GenericResponse {
            message: format!("Role '{}' revoked", role),
            detail: None,
        }),
    ))
}

/// Every role defined in the tenant, so an admin UI can offer a picker rather
/// than asking for role names to be typed from memory.
#[instrument(
    name = "knox.roles.list",
    skip(state, claims),
    fields(knox.operation = "roles_list", knox.tenant_id = %tenant_id)
)]
pub async fn list_roles(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(IDENTITY_READ_SCOPE)?;
    let roles = state.identity_service.list_roles(tenant_id).await?;
    Ok((StatusCode::OK, Json(roles)))
}

pub fn role_routes() -> Router<SharedState> {
    Router::new().route("/", get(list_roles))
}

// ── Password change (self-service) ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MfaVerificationDto {
    pub method: MfaOption,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordDto {
    pub current_password: String,
    pub new_password: String,
    /// Present on the second submission when the account has a verified factor.
    /// Absent on the first: the handler answers `{ "mfa_required": true }` and
    /// the client resubmits with a code.
    pub mfa: Option<MfaVerificationDto>,
}

/// `POST /api/identity/me/password` — change your own password.
///
/// Always acts on the token subject, never a path id. The service verifies the
/// current password first, then the second factor when enrolled, then revokes
/// every session — including this caller's, so a 200 here means the next
/// management call will 401 and the UI must send the user back to sign in.
#[instrument(
    name = "knox.identity.change_password",
    skip_all,
    fields(knox.operation = "identity_change_password", knox.tenant_id = %tenant_id)
)]
pub async fn change_own_password(
    TenantId { id: tenant_id, .. }: TenantId,
    TenantConfig(config): TenantConfig,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    Json(payload): Json<ChangePasswordDto>,
) -> Result<impl IntoResponse, AppError> {
    let identity_id = self_identity_id(&claims)?;
    let mfa = payload.mfa.map(|m| (m.method, m.code));

    let outcome = state
        .auth_service
        .change_own_password(
            tenant_id,
            claims.pool_id,
            identity_id,
            &payload.current_password,
            &payload.new_password,
            mfa,
            &config,
            &audit_ctx,
        )
        .await?;

    let body = match outcome {
        ChangePasswordOutcome::MfaRequired(methods) => {
            json!({ "mfa_required": true, "methods": methods })
        }
        ChangePasswordOutcome::Completed => json!({ "mfa_required": false }),
    };
    Ok((StatusCode::OK, Json(body)))
}

// ── Password reset (admin-initiated) ─────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ResetLinkResponse {
    pub reset_url: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// `POST /api/identity/{identity_id}/password/reset` — issue a one-time reset
/// link for another identity. The administrator receives the link, never a
/// password, and delivers it out of band. Nothing changes until the link is
/// redeemed (which then still demands the user's second factor).
#[instrument(
    name = "knox.identity.reset_password",
    skip_all,
    fields(knox.operation = "identity_reset_password", knox.tenant_id = %tenant_id, knox.identity_id = %identity_id)
)]
pub async fn admin_create_reset_link(
    TenantId {
        id: tenant_id,
        issuer,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    Path(IdentityPath { identity_id }): Path<IdentityPath>,
    Query(pool_q): Query<PoolQuery>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(IDENTITY_UPDATE_SCOPE)?;
    // Same bar as editing another identity: resetting your own needs nothing
    // more, resetting someone else's needs the elevated scope.
    if claims.sub != identity_id.to_string()
        && !claims.scopes.contains(&IDENTITY_CREATE_SCOPE.to_string())
    {
        return Err(AppError::Forbidden(
            "Cannot reset another identity's password without elevated scope".into(),
        ));
    }
    let pool_id = resolve_pool(&state, tenant_id, claims.pool_id, pool_q.pool_id).await?;
    // 404 if the identity is not in this pool, before a token is minted.
    state
        .identity_service
        .get_identity(pool_id, identity_id)
        .await?;

    let (token, expires_at) = state
        .auth_service
        .request_password_reset(tenant_id, pool_id, identity_id, &config)
        .await?;
    let reset_url = build_reset_url(&config, &issuer, &token);

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::PasswordResetRequested,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("identity", identity_id.to_string())
        .with_details(json!({"via": "admin"})),
    );

    Ok((
        StatusCode::OK,
        Json(ResetLinkResponse {
            reset_url,
            expires_at,
        }),
    ))
}

// ── MFA break-glass (admin-initiated) ────────────────────────────────────────

/// `DELETE /api/identity/{identity_id}/mfa` — clear an identity's MFA
/// enrolment. For a user locked out of their second factor with no backup codes
/// left; distinct from the self-service removal under `/api/mfa/*`, and audited
/// as `mfa.reset` with the admin as actor. Deliberately separate from a
/// password reset so recovering an account never silently strips MFA.
#[instrument(
    name = "knox.identity.reset_mfa",
    skip_all,
    fields(knox.operation = "identity_reset_mfa", knox.tenant_id = %tenant_id, knox.identity_id = %identity_id)
)]
pub async fn admin_reset_mfa(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(IdentityPath { identity_id }): Path<IdentityPath>,
    Query(pool_q): Query<PoolQuery>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(IDENTITY_UPDATE_SCOPE)?;
    if claims.sub != identity_id.to_string()
        && !claims.scopes.contains(&IDENTITY_CREATE_SCOPE.to_string())
    {
        return Err(AppError::Forbidden(
            "Cannot reset another identity's MFA without elevated scope".into(),
        ));
    }
    let pool_id = resolve_pool(&state, tenant_id, claims.pool_id, pool_q.pool_id).await?;
    // 404 if the identity is not in this pool.
    state
        .identity_service
        .get_identity(pool_id, identity_id)
        .await?;

    state.mfa_service.remove_all(tenant_id, identity_id).await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::MfaReset,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("identity", identity_id.to_string()),
    );

    Ok((
        StatusCode::OK,
        Json(GenericResponse {
            message: "MFA enrolment cleared".into(),
            detail: None,
        }),
    ))
}

pub fn identity_routes() -> Router<SharedState> {
    Router::new()
        .route("/", post(create_identity))
        .route("/", get(list_identities))
        // Self-service password change. Above `/{identity_id}` is not required —
        // axum matches the static segment first — but it keeps the self routes
        // grouped.
        .route("/me/password", post(change_own_password))
        .route("/{identity_id}", get(get_identity))
        .route("/{identity_id}", patch(update_identity))
        .route("/{identity_id}", delete(delete_identity))
        .route(
            "/{identity_id}/password/reset",
            post(admin_create_reset_link),
        )
        .route("/{identity_id}/mfa", delete(admin_reset_mfa))
        .route(
            "/{identity_id}/roles",
            get(list_identity_roles).post(assign_identity_role),
        )
        .route("/{identity_id}/roles/{role}", delete(revoke_identity_role))
}
