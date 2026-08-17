use crate::handlers::{GenericResponse, self_identity_id};
use crate::{
    error::AppError, middleware::audit_context::AuditCtx, middleware::auth::RequireAuth,
    middleware::tenant_host::TenantConfig, middleware::tenant_host::TenantId, state::SharedState,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use knox_common::audit::{AuditActor, AuditEvent, AuditEventType, AuditOutcome};
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct MethodPath {
    pub method_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmTotpDto {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
}

#[instrument(
    name = "knox.mfa.totp.enroll",
    skip_all,
    fields(
        knox.operation = "mfa_totp_enroll",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn start_totp_enrollment(
    TenantId {
        id: tenant_id,
        slug,
        ..
    }: TenantId,
    TenantConfig(config): TenantConfig,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    let identity_id = self_identity_id(&claims)?;

    let identity = state
        .identity_service
        .get_identity(claims.pool_id, identity_id)
        .await?;

    let issuer = config
        .authentication_configuration
        .totp_issuer
        .clone()
        .unwrap_or(slug);

    debug!("Starting TOTP enrollment for identity {}", identity_id);
    let response = state
        .mfa_service
        .start_totp_enrollment(tenant_id, identity_id, &issuer, &identity.username)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::MfaEnrollStarted,
            AuditActor::Identity(identity_id),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("mfa_method", response.method_id.to_string())
        .with_details(serde_json::json!({"method": "totp"})),
    );

    Ok((StatusCode::OK, Json(response)))
}

#[instrument(
    name = "knox.mfa.totp.confirm",
    skip_all,
    fields(
        knox.operation = "mfa_totp_confirm",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn confirm_totp_enrollment(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    Json(payload): Json<ConfirmTotpDto>,
) -> Result<impl IntoResponse, AppError> {
    let identity_id = self_identity_id(&claims)?;

    let backup_codes = state
        .mfa_service
        .confirm_totp_enrollment(tenant_id, identity_id, &payload.code)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::MfaEnrolled,
            AuditActor::Identity(identity_id),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_details(serde_json::json!({"method": "totp"})),
    );

    Ok((StatusCode::OK, Json(BackupCodesResponse { backup_codes })))
}

#[instrument(
    name = "knox.mfa.methods.list",
    skip_all,
    fields(
        knox.operation = "mfa_methods_list",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn list_methods(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
) -> Result<impl IntoResponse, AppError> {
    let identity_id = self_identity_id(&claims)?;

    let methods = state
        .mfa_service
        .list_methods(tenant_id, identity_id)
        .await?;

    Ok((StatusCode::OK, Json(methods)))
}

#[instrument(
    name = "knox.mfa.methods.remove",
    skip_all,
    fields(
        knox.operation = "mfa_method_remove",
        knox.tenant_id = %tenant_id,
        knox.method_id = %method_id
    )
)]
pub async fn remove_method(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(MethodPath { method_id }): Path<MethodPath>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    let identity_id = self_identity_id(&claims)?;

    state
        .mfa_service
        .remove_method(tenant_id, identity_id, method_id)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::MfaRemoved,
            AuditActor::Identity(identity_id),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("mfa_method", method_id.to_string()),
    );

    Ok((
        StatusCode::OK,
        Json(GenericResponse {
            message: "MFA method removed".into(),
            detail: None,
        }),
    ))
}

#[instrument(
    name = "knox.mfa.backup_codes.regenerate",
    skip_all,
    fields(
        knox.operation = "mfa_backup_codes_regenerate",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn regenerate_backup_codes(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    let identity_id = self_identity_id(&claims)?;

    let backup_codes = state
        .mfa_service
        .regenerate_backup_codes(tenant_id, identity_id)
        .await?;

    state.audit_service.record(AuditEvent::new(
        tenant_id,
        AuditEventType::MfaBackupCodesRegenerated,
        AuditActor::Identity(identity_id),
        AuditOutcome::Success,
        audit_ctx,
    ));

    Ok((StatusCode::OK, Json(BackupCodesResponse { backup_codes })))
}

pub fn mfa_routes() -> Router<SharedState> {
    Router::new()
        .route("/totp/enroll", post(start_totp_enrollment))
        .route("/totp/confirm", post(confirm_totp_enrollment))
        .route("/methods", get(list_methods))
        .route("/methods/{method_id}", delete(remove_method))
        .route("/backup-codes/regenerate", post(regenerate_backup_codes))
}
