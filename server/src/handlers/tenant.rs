use crate::{
    error::AppError,
    handlers::GenericResponse,
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
    routing::{get, post},
};
use knox_common::audit::{AuditEvent, AuditEventType, AuditOutcome};
use knox_core::roles::{
    PLATFORM_TENANT_CREATE_SCOPE, PLATFORM_TENANT_DELETE_SCOPE, PLATFORM_TENANT_LIST_SCOPE,
    PLATFORM_TENANT_READ_SCOPE, TENANT_READ_SCOPE,
};
use knox_core::tenant::{AdminUserRequest, CreateTenantRequest, TenantSearchRequest};
use serde::Deserialize;
use tracing::{info, instrument};

#[derive(Debug, Deserialize)]
pub struct AdminUserDto {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantDto {
    pub name: String,
    /// URL-safe identifier: lowercase alphanumeric and hyphens (e.g. "acme-corp").
    /// Immutable after creation.
    pub slug: String,
    pub description: Option<String>,
    pub management_redirect_uris: Option<Vec<String>>,
    pub admin_user: Option<AdminUserDto>,
}

#[instrument(
    name = "knox.tenant.create",
    skip(state, payload, claims),
    fields(
        knox.operation = "tenant_create",
        knox.tenant_name = %payload.name
    )
)]
pub async fn create_tenant(
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    Json(payload): Json<CreateTenantDto>,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(PLATFORM_TENANT_CREATE_SCOPE)?;

    info!("Creating new tenant: {}", payload.name);
    info!(
        "Management redirect URIs: {:?}",
        payload.management_redirect_uris
    );
    info!("Admin user present: {}", payload.admin_user.is_some());

    let obj = CreateTenantRequest {
        name: payload.name.clone(),
        slug: payload.slug.clone(),
        description: payload.description,
        management_redirect_uris: payload.management_redirect_uris,
        admin_user: payload.admin_user.map(|u| AdminUserRequest {
            email: u.email,
            password: u.password,
            first_name: u.first_name,
            last_name: u.last_name,
        }),
        // Never settable over the API — the platform tenant is a bootstrap concern.
        is_platform: false,
    };

    let response = state.tenant_service.create_tenant(obj).await?;

    info!(
        "Tenant created successfully. Admin identity returned: {}",
        response.admin_identity.is_some()
    );

    Ok((StatusCode::CREATED, Json(response)))
}

#[instrument(
    name = "knox.tenant.get",
    skip(state, claims),
    fields(
        knox.operation = "tenant_get",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn get_tenant(
    TenantId {
        id: tenant_id,
        slug: host_slug,
        ..
    }: TenantId,
    Path(tenant_slug): Path<String>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(TENANT_READ_SCOPE)?;

    // The route has always declared `{tenant_slug}` but previously ignored it,
    // resolving the tenant from the Host header instead — so it promised a
    // cross-tenant lookup it did not perform. Honour the parameter, and gate the
    // cross-tenant case on platform authority.
    if tenant_slug != host_slug {
        claims.require_scope(PLATFORM_TENANT_READ_SCOPE)?;
        info!("Platform read of tenant: {}", tenant_slug);
        let tenant = state
            .tenant_service
            .get_tenant_by_slug(&tenant_slug)
            .await?;
        return Ok((StatusCode::OK, Json(tenant)));
    }

    info!("Fetching tenant: {}", tenant_id);
    let tenant = state.tenant_service.get_tenant(tenant_id).await?;
    Ok((StatusCode::OK, Json(tenant)))
}

#[instrument(
    name = "knox.tenant.delete",
    skip(state, claims),
    fields(knox.operation = "tenant_delete", knox.tenant_slug = %tenant_slug)
)]
pub async fn delete_tenant(
    Path(tenant_slug): Path<String>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(PLATFORM_TENANT_DELETE_SCOPE)?;

    let tenant = state
        .tenant_service
        .get_tenant_by_slug(&tenant_slug)
        .await?;

    // Deleting the platform tenant would take the deployment's root of trust
    // with it — the only PlatformAdmin role, the only client that can create
    // tenants, and every operator account. There is no path back short of
    // re-running bootstrap against an otherwise-populated database.
    if tenant.is_platform {
        return Err(AppError::Forbidden(
            "The platform tenant cannot be deleted".into(),
        ));
    }

    info!("Deleting tenant {} ({})", tenant.slug, tenant.id);
    state.tenant_service.delete_tenant(tenant.id).await?;

    // Recorded against the *caller's* tenant, not the deleted one: audit rows
    // cascade with the tenant, so an event written against the target would be
    // removed by the very delete it documents.
    state.audit_service.record(
        AuditEvent::new(
            claims.tenant_id,
            AuditEventType::TenantDeleted,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("tenant", tenant.id.to_string())
        .with_details(serde_json::json!({
            "slug": tenant.slug,
            "name": tenant.name,
        })),
    );

    Ok((
        StatusCode::OK,
        Json(GenericResponse {
            message: format!("Tenant '{}' deleted", tenant.slug),
            detail: Some("All identities, clients, pools and keys were removed.".into()),
        }),
    ))
}

#[instrument(
    name = "knox.tenant.list",
    skip(state, claims),
    fields(knox.operation = "tenant_list")
)]
pub async fn list_tenants(
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
) -> Result<impl IntoResponse, AppError> {
    // "List the tenants you can see." Only the platform tenant sees the whole
    // platform; everyone else sees themselves. This used to require nothing but
    // TenantRead — held by the default TenantReader role in *every* tenant — and
    // then query with no filter at all, so any tenant's reader enumerated every
    // tenant on the deployment.
    if claims
        .scopes
        .contains(&PLATFORM_TENANT_LIST_SCOPE.to_string())
    {
        info!("Listing all tenants (platform caller)");

        // TODO: Take pagination params from query string
        let search = TenantSearchRequest {
            page: 1,
            page_size: 100,
        };

        let tenants = state.tenant_service.list_tenants(search).await?;
        return Ok((StatusCode::OK, Json(tenants)));
    }

    // A one-element list rather than a 403: the console calls this on every
    // dashboard load, and "you can see one tenant" is a normal condition, not an
    // error the client should have to special-case.
    claims.require_scope(TENANT_READ_SCOPE)?;
    info!("Listing own tenant only: {}", claims.tenant_id);
    let tenant = state.tenant_service.get_tenant(claims.tenant_id).await?;
    Ok((StatusCode::OK, Json((vec![tenant], 1u64))))
}

pub fn tenant_routes() -> Router<SharedState> {
    Router::new()
        .route("/", post(create_tenant).get(list_tenants))
        .route("/{tenant_slug}", get(get_tenant).delete(delete_tenant))
}
