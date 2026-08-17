use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use knox_common::error::{OIDCError, RepositoryError, ServiceError};
use opentelemetry::trace::TraceContextExt;
use serde_json::json;
use tracing::{debug, error};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub enum AppError {
    NotFound,
    InternalServerError,
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    ServiceError {
        error: ServiceError,
        trace_id: String,
    },
}

impl From<ServiceError> for AppError {
    fn from(error: ServiceError) -> Self {
        let trace_id = tracing::Span::current()
            .context()
            .span()
            .span_context()
            .trace_id()
            .to_string();

        AppError::ServiceError { error, trace_id }
    }
}

/// The HTTP status a `ServiceError` deserves.
///
/// Deliberately exhaustive — no `_` arm. The 500s this function replaced were
/// not decisions, they were a fallthrough: every variant added to `ServiceError`
/// silently became a server error, so a wrong password, a missing row and a
/// half-built feature all reported "the server broke". Listing every variant
/// turns the next addition into a compile error here instead.
///
/// The rule: 5xx means *Knox* is at fault and the caller can only retry. Anything
/// the caller could fix by sending a different request is a 4xx.
fn status_for(error: &ServiceError) -> StatusCode {
    match error {
        // ── Authentication failed ──────────────────────────────────────────
        // A rejected password is an answer, not an outage.
        ServiceError::InvalidCredentials
        | ServiceError::InvalidMfaCode
        | ServiceError::InvalidMfaToken
        // Bearer-style credentials the caller presented and Knox refused.
        | ServiceError::InvalidSsoToken
        | ServiceError::SsoTokenExpired
        | ServiceError::InvalidResetToken
        | ServiceError::InvalidAuthCode => StatusCode::UNAUTHORIZED,

        // Reachable only off the happy path: `/authenticate` intercepts this
        // variant and answers 200 with the challenge, because a required second
        // factor is a step in the flow rather than a failure. If it surfaces
        // anywhere else, the caller is unauthenticated and has no way to be
        // handed the challenge, so 401 is the honest answer.
        ServiceError::MfaRequired(_) => StatusCode::UNAUTHORIZED,

        // ── Authorisation denied ───────────────────────────────────────────
        // An identity asking for scopes it does not hold is a denial,
        // not a server fault. Without this the token endpoint reports
        // 500 for an ordinary authorisation decision.
        ServiceError::Forbidden => StatusCode::FORBIDDEN,

        ServiceError::MfaTooManyAttempts
        | ServiceError::TooManyAuthenticationAttempts => StatusCode::TOO_MANY_REQUESTS,

        // ── Conflicts with existing state ──────────────────────────────────
        ServiceError::MfaAlreadyEnrolled | ServiceError::DuplicateIdentity => StatusCode::CONFLICT,

        // ── Malformed or inapplicable request ──────────────────────────────
        ServiceError::MfaNotEnrolled => StatusCode::BAD_REQUEST,
        // Also what `MfaService::verify` returns for the `webauthn`/`sms`
        // options it does not implement yet. 400 is right for both readings:
        // the request names something Knox will not act on.
        ServiceError::Validation(_) => StatusCode::BAD_REQUEST,
        // Never a redirect: the URI failed validation, so it is exactly the
        // URI Knox must not send the user to.
        ServiceError::RedirectUriMismatch => StatusCode::BAD_REQUEST,

        // ── Storage ────────────────────────────────────────────────────────
        // "No such row" is the caller naming a resource that does not exist —
        // e.g. DELETE /api/mfa/methods/{id} for an id that is already gone.
        ServiceError::Repository(RepositoryError::NotFound) => StatusCode::NOT_FOUND,
        // A unique-constraint violation the caller can resolve by not
        // re-creating what already exists.
        ServiceError::Repository(RepositoryError::Duplicate(_)) => StatusCode::CONFLICT,
        // A genuine database fault. The caller cannot do anything about it.
        ServiceError::Repository(RepositoryError::Database(_)) => StatusCode::INTERNAL_SERVER_ERROR,

        ServiceError::OIDC(e) => oidc_status(e),

        ServiceError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Statuses follow RFC 6749 §5.2, which is stricter than intuition: only
/// `invalid_client` is a 401, while `invalid_grant` and `unauthorized_client`
/// are 400s.
///
/// This maps the status only. The bodies are still Knox-shaped
/// (`{"error": "OIDC error: …"}`) rather than the `{"error": "invalid_grant"}`
/// the spec wants — a separate fix, since the response shape is what clients
/// parse and the UI renders.
fn oidc_status(error: &OIDCError) -> StatusCode {
    match error {
        OIDCError::InvalidClientSecret => StatusCode::UNAUTHORIZED,
        OIDCError::AccessDenied => StatusCode::FORBIDDEN,
        OIDCError::InvalidRequest(_)
        | OIDCError::InvalidGrant
        | OIDCError::UnauthorizedClient
        | OIDCError::UnsupportedResponseType
        | OIDCError::InvalidScope => StatusCode::BAD_REQUEST,
        OIDCError::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use knox_common::identity::MfaRequiredDetails;

    /// The regressions this pass fixed. Each of these answered 500 before.
    #[test]
    fn client_errors_are_not_server_errors() {
        let cases = [
            (ServiceError::InvalidCredentials, StatusCode::UNAUTHORIZED),
            (ServiceError::InvalidSsoToken, StatusCode::UNAUTHORIZED),
            (ServiceError::SsoTokenExpired, StatusCode::UNAUTHORIZED),
            (ServiceError::InvalidAuthCode, StatusCode::UNAUTHORIZED),
            (ServiceError::DuplicateIdentity, StatusCode::CONFLICT),
            (
                ServiceError::Validation("unsupported method".into()),
                StatusCode::BAD_REQUEST,
            ),
            (ServiceError::RedirectUriMismatch, StatusCode::BAD_REQUEST),
            (
                ServiceError::Repository(RepositoryError::NotFound),
                StatusCode::NOT_FOUND,
            ),
            (
                ServiceError::Repository(RepositoryError::Duplicate("uq_mfa".into())),
                StatusCode::CONFLICT,
            ),
            (
                ServiceError::OIDC(OIDCError::InvalidClientSecret),
                StatusCode::UNAUTHORIZED,
            ),
            (
                ServiceError::OIDC(OIDCError::InvalidGrant),
                StatusCode::BAD_REQUEST,
            ),
            (
                ServiceError::OIDC(OIDCError::AccessDenied),
                StatusCode::FORBIDDEN,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(status_for(&error), expected, "wrong status for {error:?}");
        }
    }

    /// The mappings that already existed, so this pass cannot quietly undo them.
    #[test]
    fn existing_mappings_are_preserved() {
        assert_eq!(
            status_for(&ServiceError::InvalidMfaCode),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_for(&ServiceError::InvalidMfaToken),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_for(&ServiceError::MfaTooManyAttempts),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_for(&ServiceError::TooManyAuthenticationAttempts),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_for(&ServiceError::MfaAlreadyEnrolled),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status_for(&ServiceError::MfaNotEnrolled),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(status_for(&ServiceError::Forbidden), StatusCode::FORBIDDEN);
    }

    /// Only an actual Knox fault may be a 5xx.
    #[test]
    fn server_faults_remain_server_errors() {
        assert!(status_for(&ServiceError::Internal("boom".into())).is_server_error());
        assert!(
            status_for(&ServiceError::Repository(RepositoryError::Database(
                "connection reset".into()
            )))
            .is_server_error()
        );
        assert!(
            status_for(&ServiceError::OIDC(OIDCError::ServerError("boom".into())))
                .is_server_error()
        );
    }

    /// `/authenticate` answers 200 with the challenge before this is reached;
    /// the mapping only covers the paths that cannot.
    #[test]
    fn mfa_required_is_unauthorized_off_the_authenticate_path() {
        let details = MfaRequiredDetails {
            token: "tok".into(),
            user_id: uuid::Uuid::nil(),
            options: vec![],
        };
        assert_eq!(
            status_for(&ServiceError::MfaRequired(details)),
            StatusCode::UNAUTHORIZED
        );
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let trace_id = tracing::Span::current()
            .context()
            .span()
            .span_context()
            .trace_id()
            .to_string();

        // 2. Map the error to an HTTP response
        match self {
            AppError::NotFound => {
                let body = json!({ "error": "Not Found", "correlation_id": trace_id });
                let mut resp = (StatusCode::NOT_FOUND, Json(body)).into_response();
                resp.headers_mut()
                    .insert("X-Correlation-ID", trace_id.parse().unwrap());
                resp
            }
            AppError::InternalServerError => {
                let body = json!({ "error": "Internal Server Error", "correlation_id": trace_id });
                let mut resp = (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response();
                resp.headers_mut()
                    .insert("X-Correlation-ID", trace_id.parse().unwrap());
                resp
            }
            AppError::BadRequest(msg) => {
                let body = json!({ "error": "Bad Request", "message": msg });
                (StatusCode::BAD_REQUEST, Json(body)).into_response()
            }
            AppError::Unauthorized(msg) => {
                let body = json!({ "error": "Unauthorized", "message": msg });
                (StatusCode::UNAUTHORIZED, Json(body)).into_response()
            }
            AppError::Forbidden(msg) => {
                let body = json!({ "error": "Forbidden", "message": msg });
                (StatusCode::FORBIDDEN, Json(body)).into_response()
            }
            AppError::ServiceError { error, trace_id } => {
                let status = status_for(&error);

                // Log at the level the status implies. Every one of these used to
                // be ERROR, which was defensible only while every one of them was
                // a 500. Now that a wrong password is a 401, logging it at ERROR
                // would mean routine credential stuffing fills the error stream.
                if status.is_server_error() {
                    error!("Service error: {:?}", error);
                } else {
                    debug!(status = %status.as_u16(), "Service error: {:?}", error);
                }

                let error_message = json!({
                    "error": error.to_string(),
                    "correlation_id": trace_id
                });
                let mut resp = (status, Json(error_message)).into_response();
                resp.headers_mut()
                    .insert("X-Correlation-ID", trace_id.parse().unwrap());
                resp
            }
        }
    }
}
