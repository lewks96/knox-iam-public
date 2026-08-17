use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use knox_common::audit::{AuditActor, AuditContext};
use knox_core::token::JwtClaims;
use opentelemetry::trace::TraceContextExt;
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuditCtx(pub AuditContext);

impl<S> FromRequestParts<S> for AuditCtx
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Proxy headers first (first hop in x-forwarded-for), then the socket.
        let ip = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .or_else(|| {
                parts
                    .headers
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            })
            .or_else(|| {
                parts
                    .extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ci| ci.0.ip().to_string())
            });

        let user_agent = parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        // Same trace id that inject_correlation_id echoes as x-correlation-id.
        let trace_id = tracing::Span::current()
            .context()
            .span()
            .span_context()
            .trace_id()
            .to_string();
        let correlation_id = (trace_id != "00000000000000000000000000000000").then_some(trace_id);

        Ok(AuditCtx(AuditContext {
            ip,
            user_agent,
            correlation_id,
        }))
    }
}

/// Maps verified JWT claims to an audit actor. Human/user tokens carry the
/// identity UUID in `sub`; machine (client_credentials) tokens carry the
/// client name in `sub`, so fall back to the client UUID in `aud`.
pub fn actor_from_claims(claims: &JwtClaims) -> AuditActor {
    if let Ok(id) = Uuid::parse_str(&claims.sub) {
        AuditActor::Identity(id)
    } else if let Ok(client_id) = Uuid::parse_str(&claims.aud) {
        AuditActor::Client(client_id)
    } else {
        AuditActor::Anonymous
    }
}
