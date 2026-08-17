//! Identity pool management.
//!
//! A pool is the directory an identity lives in, and the thing a client
//! authenticates against. Every tenant is provisioned exactly one `staff` pool
//! with the tenant itself — that is the one the console binds to — and may
//! create any number of `customer` pools for its own applications' end users.
//!
//! There is deliberately no way to create a second staff pool, and no way to
//! change a pool's kind: both are baked into every token minted through clients
//! bound to the pool.

use crate::{
    error::AppError,
    middleware::audit_context::{AuditCtx, actor_from_claims},
    middleware::auth::{ClaimsExt, RequireAuth},
    middleware::tenant_host::TenantId,
    state::SharedState,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use knox_common::audit::{AuditEvent, AuditEventType, AuditOutcome};
use knox_core::roles::{TENANT_READ_SCOPE, TENANT_UPDATE_SCOPE};
use serde::Deserialize;
use tracing::{info, instrument};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreatePoolDto {
    /// DNS-label-shaped, unique within the tenant, immutable once set.
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
}

#[instrument(
    name = "knox.pool.list",
    skip(state, claims),
    fields(knox.operation = "pool_list", knox.tenant_id = %tenant_id)
)]
pub async fn list_pools(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(TENANT_READ_SCOPE)?;
    let pools = state.tenant_service.list_pools(tenant_id).await?;
    Ok((StatusCode::OK, Json(pools)))
}

#[instrument(
    name = "knox.pool.get",
    skip(state, claims),
    fields(knox.operation = "pool_get", knox.tenant_id = %tenant_id, knox.pool_id = %pool_id)
)]
pub async fn get_pool(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(pool_id): Path<Uuid>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(TENANT_READ_SCOPE)?;
    let pool = state.tenant_service.get_pool(tenant_id, pool_id).await?;
    Ok((StatusCode::OK, Json(pool)))
}

/// Creates an end-user pool. Staff pools are provisioned with the tenant and
/// capped at one by a partial unique index, so this can only ever make a
/// `customer` pool.
#[instrument(
    name = "knox.pool.create",
    skip(state, claims, payload),
    fields(knox.operation = "pool_create", knox.tenant_id = %tenant_id)
)]
pub async fn create_pool(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    Json(payload): Json<CreatePoolDto>,
) -> Result<impl IntoResponse, AppError> {
    // Creating a directory decides who can authenticate to this tenant's apps,
    // so it is a tenant-configuration change, not an identity operation.
    claims.require_scope(TENANT_UPDATE_SCOPE)?;

    info!(
        "Creating customer pool '{}' for tenant {}",
        payload.slug, tenant_id
    );
    let pool = state
        .tenant_service
        .create_customer_pool(tenant_id, &payload.slug, &payload.name, payload.description)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::PoolCreated,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("pool", pool.id.to_string()),
    );

    Ok((StatusCode::CREATED, Json(pool)))
}

pub fn pool_routes() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_pools).post(create_pool))
        .route("/{pool_id}", get(get_pool))
}
