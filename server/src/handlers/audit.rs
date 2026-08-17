use crate::{
    error::AppError,
    middleware::auth::{ClaimsExt, RequireAuth},
    middleware::tenant_host::TenantId,
    state::SharedState,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use knox_common::audit::{AuditEventFilter, AuditRepository, StoredAuditEvent};
use knox_common::error::ServiceError;
use knox_core::roles::AUDIT_READ_SCOPE;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::instrument;
use uuid::Uuid;

const DEFAULT_PAGE_LIMIT: u32 = 50;
const MAX_PAGE_LIMIT: u32 = 200;

#[derive(Debug, Deserialize)]
pub struct AuditEventsQuery {
    /// RFC 3339 lower bound (inclusive).
    pub from: Option<String>,
    /// RFC 3339 upper bound (inclusive).
    pub to: Option<String>,
    pub event_type: Option<String>,
    pub actor_id: Option<Uuid>,
    pub outcome: Option<String>,
    pub limit: Option<u32>,
    /// Opaque cursor from a previous response's `next_cursor`.
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditEventsResponse {
    pub items: Vec<StoredAuditEvent>,
    /// Present when there may be older events; pass back as `cursor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

fn parse_rfc3339(value: &str, field: &str) -> Result<OffsetDateTime, AppError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| AppError::BadRequest(format!("'{}' must be an RFC 3339 timestamp", field)))
}

fn encode_cursor(occurred_at: OffsetDateTime, id: Uuid) -> Option<String> {
    let at = occurred_at.format(&Rfc3339).ok()?;
    Some(URL_SAFE_NO_PAD.encode(format!("{}|{}", at, id)))
}

fn decode_cursor(cursor: &str) -> Result<(OffsetDateTime, Uuid), AppError> {
    let invalid = || AppError::BadRequest("Invalid cursor".into());
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
    let raw = String::from_utf8(bytes).map_err(|_| invalid())?;
    let (at, id) = raw.split_once('|').ok_or_else(invalid)?;
    Ok((
        OffsetDateTime::parse(at, &Rfc3339).map_err(|_| invalid())?,
        Uuid::parse_str(id).map_err(|_| invalid())?,
    ))
}

#[instrument(
    name = "knox.audit.events.list",
    skip_all,
    fields(
        knox.operation = "audit_events_list",
        knox.tenant_id = %tenant_id
    )
)]
pub async fn list_audit_events(
    TenantId { id: tenant_id, .. }: TenantId,
    State(state): State<SharedState>,
    RequireAuth(claims): RequireAuth,
    Query(query): Query<AuditEventsQuery>,
) -> Result<impl IntoResponse, AppError> {
    claims.require_scope(AUDIT_READ_SCOPE)?;

    let limit = query
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT);

    let filter = AuditEventFilter {
        tenant_id,
        from: query
            .from
            .as_deref()
            .map(|v| parse_rfc3339(v, "from"))
            .transpose()?,
        to: query
            .to
            .as_deref()
            .map(|v| parse_rfc3339(v, "to"))
            .transpose()?,
        event_type: query.event_type,
        actor_id: query.actor_id,
        outcome: query.outcome,
        limit,
        cursor: query.cursor.as_deref().map(decode_cursor).transpose()?,
    };

    let items = state
        .audit_repo
        .list(&filter)
        .await
        .map_err(ServiceError::Repository)
        .map_err(AppError::from)?;

    let next_cursor = if items.len() == limit as usize {
        items
            .last()
            .and_then(|e| encode_cursor(e.occurred_at, e.id))
    } else {
        None
    };

    Ok((
        StatusCode::OK,
        Json(AuditEventsResponse { items, next_cursor }),
    ))
}

pub fn audit_routes() -> Router<SharedState> {
    Router::new().route("/events", get(list_audit_events))
}
