use crate::handlers::GenericResponse;
use crate::middleware::tenant_host::TenantConfig;
use crate::{
    error::AppError,
    middleware::audit_context::{AuditCtx, actor_from_claims},
    middleware::auth::{ClaimsExt, RequireAuth},
    middleware::tenant_host::TenantId,
    state::SharedState,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use knox_common::audit::{AuditEvent, AuditEventType, AuditOutcome};
use knox_common::client::{Client, ClientFilter, ClientType};
use knox_common::identity::Status;
use knox_core::client::{CreateClientRequest, CreateClientResponse, UpdateClientRequest};
use knox_core::roles::{
    CLIENT_CREATE_SCOPE, CLIENT_DELETE_SCOPE, CLIENT_READ_SCOPE, CLIENT_UPDATE_SCOPE,
};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};
use uuid::Uuid;

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateClientDto {
    pub name: String,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub client_type: ClientType,
    pub token_endpoint_auth_method: Option<String>,
    pub allow_refresh_tokens: Option<bool>,
    pub grant_types: Vec<String>,
    pub response_types: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Vec<String>,
    pub access_token_ttl: Option<u32>,
    pub refresh_token_ttl: Option<u32>,
    pub id_token_ttl: Option<u32>,
    pub auth_code_ttl: Option<u32>,
    /// The identity pool this client authenticates against. Defaults to the
    /// caller's own pool.
    pub pool_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientDto {
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub allow_refresh_tokens: Option<bool>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub require_pkce: Option<bool>,
    pub access_token_ttl: Option<u32>,
    pub refresh_token_ttl: Option<u32>,
    pub id_token_ttl: Option<u32>,
    pub auth_code_ttl: Option<u32>,
    pub status: Option<Status>,
}

#[derive(Debug, Deserialize)]
pub struct ListClientsQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub status: Option<Status>,
}

/// The public-facing client view — strips the secret hash which must never leave the server.
#[derive(Debug, Serialize)]
pub struct ClientView {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Which identity pool this client authenticates against — i.e. whose
    /// credentials are even checkable at it. Surfaced because it is the
    /// security-relevant property of a client, not an implementation detail.
    pub pool_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub client_type: ClientType,
    pub token_endpoint_auth_method: String,
    pub allow_refresh_tokens: bool,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub require_pkce: bool,
    pub access_token_ttl: i32,
    pub refresh_token_ttl: i32,
    pub id_token_ttl: i32,
    pub auth_code_ttl: i32,
    pub token_version: i32,
    pub status: Status,
    pub metadata: serde_json::Value,
    pub custom_attributes: serde_json::Value,
    #[serde(with = "time::serde::iso8601")]
    pub created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    pub updated_at: time::OffsetDateTime,
}

impl From<Client> for ClientView {
    fn from(c: Client) -> Self {
        Self {
            id: c.id,
            tenant_id: c.tenant_id,
            pool_id: c.pool_id,
            name: c.name,
            description: c.description,
            logo_uri: c.logo_uri,
            client_type: c.client_type,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            allow_refresh_tokens: c.allow_refresh_tokens,
            grant_types: c.grant_types,
            response_types: c.response_types,
            redirect_uris: c.redirect_uris,
            post_logout_redirect_uris: c.post_logout_redirect_uris,
            allowed_scopes: c.allowed_scopes,
            require_pkce: c.require_pkce,
            access_token_ttl: c.access_token_ttl,
            refresh_token_ttl: c.refresh_token_ttl,
            id_token_ttl: c.id_token_ttl,
            auth_code_ttl: c.auth_code_ttl,
            token_version: c.token_version,
            status: c.status,
            metadata: c.metadata,
            custom_attributes: c.custom_attributes,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

/// Returned only from create / rotate-secret — the plaintext secret is shown exactly once.
#[derive(Debug, Serialize)]
pub struct ClientCreatedResponse {
    pub client: ClientView,
    /// Present only on create and secret rotation. Store it immediately — it will not be shown again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl From<CreateClientResponse> for ClientCreatedResponse {
    fn from(r: CreateClientResponse) -> Self {
        Self {
            client: r.client.into(),
            client_secret: r.client_secret,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ListClientsResponse {
    pub items: Vec<ClientView>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[instrument(
    name = "knox.client.create",
    skip(state, payload, claims),
    fields(
        knox.operation = "client_create",
        knox.tenant_id = %tenant_id,
        knox.client_name = %payload.name
    )
)]
pub async fn create_client(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    Json(payload): Json<CreateClientDto>,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(CLIENT_CREATE_SCOPE)?;

    info!(
        "Creating client '{}' for tenant {}",
        payload.name, tenant_id
    );

    let client_name = payload.name.clone();
    let req = CreateClientRequest {
        tenant_id,
        // Defaults to the creator's own pool. A client for a tenant's end-user
        // app must name its pool explicitly, which keeps "who can log in here"
        // an intentional decision rather than an inherited default.
        pool_id: payload.pool_id.unwrap_or(claims.pool_id),
        name: payload.name,
        description: payload.description,
        logo_uri: payload.logo_uri,
        client_type: payload.client_type,
        token_endpoint_auth_method: payload
            .token_endpoint_auth_method
            .unwrap_or_else(|| "client_secret_basic".into()),
        allow_refresh_tokens: payload.allow_refresh_tokens.unwrap_or(false),
        grant_types: payload.grant_types,
        response_types: payload.response_types.unwrap_or_default(),
        redirect_uris: payload.redirect_uris.unwrap_or_default(),
        post_logout_redirect_uris: payload.post_logout_redirect_uris.unwrap_or_default(),
        allowed_scopes: payload.allowed_scopes,
        access_token_ttl: payload.access_token_ttl,
        refresh_token_ttl: payload.refresh_token_ttl,
        id_token_ttl: payload.id_token_ttl,
        auth_code_ttl: payload.auth_code_ttl,
        token_version: None,
    };

    let response = state.client_service.create_client(req).await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::ClientCreated,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("client", client_name),
    );

    Ok((
        StatusCode::CREATED,
        Json(ClientCreatedResponse::from(response)),
    ))
}

#[instrument(
    name = "knox.client.get",
    skip(state, claims),
    fields(
        knox.operation = "client_get",
        knox.tenant_id = %tenant_id,
        knox.client_id = %client_id
    )
)]
pub async fn get_client(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(client_id): Path<Uuid>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(CLIENT_READ_SCOPE)?;

    let client = state
        .client_service
        .get_client(tenant_id, client_id)
        .await?;

    Ok((StatusCode::OK, Json(ClientView::from(client))))
}

#[instrument(
    name = "knox.client.list",
    skip(state, claims),
    fields(
        knox.operation = "client_list",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn list_clients(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    Query(query): Query<ListClientsQuery>,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(CLIENT_READ_SCOPE)?;

    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20).min(100);

    let filter = ClientFilter {
        tenant_id,
        page,
        page_size,
        status: query.status,
    };

    let (clients, total) = state.client_service.list_clients(&filter).await?;

    Ok((
        StatusCode::OK,
        Json(ListClientsResponse {
            items: clients.into_iter().map(ClientView::from).collect(),
            total,
            page,
            page_size,
        }),
    ))
}

#[instrument(
    name = "knox.client.update",
    skip(state, payload, claims),
    fields(
        knox.operation = "client_update",
        knox.tenant_id = %tenant_id,
        knox.client_id = %client_id
    )
)]
pub async fn update_client(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(client_id): Path<Uuid>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
    Json(payload): Json<UpdateClientDto>,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(CLIENT_UPDATE_SCOPE)?;

    // Fetch first: validates existence and provides the name for the audit trail.
    let client_name = state
        .client_service
        .get_client(tenant_id, client_id)
        .await?
        .name;

    let req = UpdateClientRequest {
        description: payload.description,
        logo_uri: payload.logo_uri,
        token_endpoint_auth_method: payload.token_endpoint_auth_method,
        allow_refresh_tokens: payload.allow_refresh_tokens,
        grant_types: payload.grant_types,
        response_types: payload.response_types,
        redirect_uris: payload.redirect_uris,
        post_logout_redirect_uris: payload.post_logout_redirect_uris,
        allowed_scopes: payload.allowed_scopes,
        require_pkce: payload.require_pkce,
        access_token_ttl: payload.access_token_ttl,
        refresh_token_ttl: payload.refresh_token_ttl,
        id_token_ttl: payload.id_token_ttl,
        auth_code_ttl: payload.auth_code_ttl,
        status: payload.status,
    };

    let updated = state
        .client_service
        .update_client(tenant_id, client_id, req)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::ClientUpdated,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("client", client_name),
    );

    Ok((StatusCode::OK, Json(ClientView::from(updated))))
}

#[instrument(
    name = "knox.client.delete",
    skip(state, claims),
    fields(
        knox.operation = "client_delete",
        knox.tenant_id = %tenant_id,
        knox.client_id = %client_id
    )
)]
pub async fn delete_client(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(client_id): Path<Uuid>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(CLIENT_DELETE_SCOPE)?;

    // Fetch first: 404s on unknown ids (repo delete is a silent no-op) and
    // provides the name for the audit trail.
    let client_name = state
        .client_service
        .get_client(tenant_id, client_id)
        .await?
        .name;

    state
        .client_service
        .delete_client(tenant_id, client_id)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::ClientDeleted,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("client", client_name),
    );

    Ok((
        StatusCode::OK,
        Json(GenericResponse {
            message: "Client deleted".into(),
            detail: None,
        }),
    ))
}

#[instrument(
    name = "knox.client.rotate_secret",
    skip(state, claims),
    fields(
        knox.operation = "client_rotate_secret",
        knox.tenant_id = %tenant_id,
        knox.client_id = %client_id
    )
)]
pub async fn rotate_client_secret(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(client_id): Path<Uuid>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(CLIENT_UPDATE_SCOPE)?;

    let client_name = state
        .client_service
        .get_client(tenant_id, client_id)
        .await?
        .name;

    info!(
        "Rotating secret for client {} in tenant {}",
        client_id, tenant_id
    );

    let response = state
        .client_service
        .rotate_client_secret(tenant_id, client_id)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::ClientUpdated,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("client", client_name)
        .with_details(serde_json::json!({"action": "rotate_secret"})),
    );

    Ok((StatusCode::OK, Json(ClientCreatedResponse::from(response))))
}

#[instrument(
    name = "knox.client.rotate_token_version",
    skip(state, claims),
    fields(
        knox.operation = "client_rotate_token_version",
        knox.tenant_id = %tenant_id,
        knox.client_id = %client_id
    )
)]
pub async fn rotate_token_version(
    TenantId { id: tenant_id, .. }: TenantId,
    Path(client_id): Path<Uuid>,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    TenantConfig(_config): TenantConfig,
    AuditCtx(audit_ctx): AuditCtx,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(CLIENT_UPDATE_SCOPE)?;

    let client_name = state
        .client_service
        .get_client(tenant_id, client_id)
        .await?
        .name;

    info!(
        "Rotating token version for client {} in tenant {}",
        client_id, tenant_id
    );

    let updated = state
        .client_service
        .rotate_token_version(tenant_id, client_id)
        .await?;

    state.audit_service.record(
        AuditEvent::new(
            tenant_id,
            AuditEventType::ClientUpdated,
            actor_from_claims(&claims),
            AuditOutcome::Success,
            audit_ctx,
        )
        .with_target("client", client_name)
        .with_details(serde_json::json!({"action": "rotate_token_version"})),
    );

    Ok((StatusCode::OK, Json(ClientView::from(updated))))
}

// ── Routes ────────────────────────────────────────────────────────────────────

pub fn client_routes() -> Router<SharedState> {
    Router::new()
        // Collection
        .route("/", get(list_clients).post(create_client))
        // Resource
        .route(
            "/{client_id}",
            get(get_client).patch(update_client).delete(delete_client),
        )
        // Actions
        .route("/{client_id}/rotate-secret", post(rotate_client_secret))
        .route(
            "/{client_id}/rotate-token-version",
            post(rotate_token_version),
        )
}
