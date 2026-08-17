use crate::{error::AppError, state::SharedState};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use knox_common::tenant::{Tenant, TenantConfiguration};
use knox_core::tenant::{is_reserved_slug, is_valid_slug};
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ResolvedTenant {
    pub id: Uuid,
    pub slug: String,
    /// The tenant's canonical OIDC issuer. Load-bearing: it is what `verify_jwt`
    /// pins and what the discovery document advertises.
    pub issuer: String,
    pub config: TenantConfiguration,
    /// Owns cross-tenant operations. Read here so the token endpoint can refuse
    /// to mint platform scopes for anyone else.
    pub is_platform: bool,
    pub from_request: bool,
}

impl ResolvedTenant {
    fn new(tenant: Tenant, from_request: bool) -> Self {
        Self {
            id: tenant.id,
            is_platform: tenant.is_platform,
            slug: tenant.slug,
            issuer: tenant.issuer,
            config: tenant.config,
            from_request,
        }
    }
}

fn base_domain() -> &'static str {
    static BASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BASE.get_or_init(|| std::env::var("KNOX_BASE_DOMAIN").unwrap_or_else(|_| "localhost".into()))
}

fn trust_forwarded_host() -> bool {
    static TRUST: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRUST.get_or_init(|| {
        matches!(
            std::env::var("KNOX_TRUST_FORWARDED_HOST").as_deref(),
            Ok("true" | "1")
        )
    })
}

pub fn tenant_slug_from_host(host: &str, base_domain: &str) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default().to_string(),
        None => host.split(':').next().unwrap_or_default().to_string(),
    };
    let host = host.trim_end_matches('.');

    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    let base = base_domain.trim().to_ascii_lowercase();
    let base = base
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');

    let label = host.strip_suffix(base)?.strip_suffix('.')?;

    // Exactly one label. `a.b.example.com` must not resolve tenant "a.b": a
    // wildcard certificate covers one level, and multi-level hosts are a classic
    // way to slip past host-matching rules.
    if label.is_empty() || label.contains('.') {
        return None;
    }

    if !is_valid_slug(label) || is_reserved_slug(label) {
        return None;
    }

    Some(label.to_string())
}

pub async fn resolve_tenant_opt(
    parts: &mut Parts,
    state: &SharedState,
) -> Result<Option<Arc<ResolvedTenant>>, AppError> {
    if let Some(cached) = parts.extensions.get::<Arc<ResolvedTenant>>() {
        return Ok(Some(cached.clone()));
    }

    let host = if trust_forwarded_host() {
        parts
            .headers
            .get("x-forwarded-host")
            .or_else(|| parts.headers.get(axum::http::header::HOST))
    } else {
        parts.headers.get(axum::http::header::HOST)
    };

    let Some(host) = host.and_then(|h| h.to_str().ok()) else {
        return Ok(None);
    };

    let Some(slug) = tenant_slug_from_host(host, base_domain()) else {
        debug!(%host, "Host does not identify a tenant");
        return Ok(None);
    };

    debug!(%slug, "Resolving tenant");
    let tenant = state
        .tenant_service
        .get_tenant_by_slug(&slug)
        .await
        .map_err(|_| AppError::NotFound)?;

    let resolved = Arc::new(ResolvedTenant::new(tenant, true));
    parts.extensions.insert(resolved.clone());
    Ok(Some(resolved))
}

pub async fn resolve_tenant(
    parts: &mut Parts,
    state: &SharedState,
) -> Result<Arc<ResolvedTenant>, AppError> {
    resolve_tenant_opt(parts, state)
        .await?
        .ok_or_else(|| AppError::BadRequest("Request does not identify a tenant".into()))
}

pub async fn resolve_tenant_by_id(
    parts: &mut Parts,
    state: &SharedState,
    tenant_id: Uuid,
) -> Result<Arc<ResolvedTenant>, AppError> {
    if let Some(cached) = parts.extensions.get::<Arc<ResolvedTenant>>() {
        return Ok(cached.clone());
    }

    let tenant = state
        .tenant_service
        .get_tenant(tenant_id)
        .await
        .map_err(|_| AppError::Unauthorized("Tenant not found".into()))?;

    let resolved = Arc::new(ResolvedTenant::new(tenant, false));
    parts.extensions.insert(resolved.clone());
    Ok(resolved)
}

/// Resolves the tenant for handlers that need its UUID.
#[derive(Debug, Clone)]
pub struct TenantId {
    pub id: Uuid,
    pub slug: String,
    pub issuer: String,
    pub is_platform: bool,
}

impl FromRequestParts<SharedState> for TenantId {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let tenant = resolve_tenant(parts, state).await?;
        Ok(TenantId {
            id: tenant.id,
            slug: tenant.slug.clone(),
            issuer: tenant.issuer.clone(),
            is_platform: tenant.is_platform,
        })
    }
}

/// Resolves the tenant's configuration.
#[derive(Debug, Clone)]
pub struct TenantConfig(pub TenantConfiguration);

impl FromRequestParts<SharedState> for TenantConfig {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let tenant = resolve_tenant(parts, state)
            .await
            .map_err(|_| AppError::Unauthorized("Tenant not found".into()))?;
        Ok(TenantConfig(tenant.config.clone()))
    }
}

#[cfg(test)]
mod host_tests {
    use super::tenant_slug_from_host as slug;

    const BASE: &str = "example.com";

    #[test]
    fn resolves_a_single_label_subdomain() {
        assert_eq!(slug("acme.example.com", BASE).as_deref(), Some("acme"));
        assert_eq!(slug("ACME.Example.COM", BASE).as_deref(), Some("acme"));
        // Trailing dot is a valid FQDN form.
        assert_eq!(slug("acme.example.com.", BASE).as_deref(), Some("acme"));
    }

    #[test]
    fn strips_the_port() {
        assert_eq!(slug("acme.lvh.me:3000", "lvh.me").as_deref(), Some("acme"));
    }

    #[test]
    fn rejects_multi_level_subdomains() {
        // Would otherwise resolve tenant "a.b" — outside wildcard-cert scope and
        // a standard host-matching bypass.
        assert_eq!(slug("a.b.example.com", BASE), None);
    }

    #[test]
    fn rejects_ip_literals() {
        // Health probes reach pods by IP; they must resolve no tenant.
        assert_eq!(slug("10.224.0.5", BASE), None);
        assert_eq!(slug("10.224.0.5:8080", BASE), None);
        assert_eq!(slug("[::1]:8080", BASE), None);
    }

    #[test]
    fn rejects_reserved_and_malformed_labels() {
        assert_eq!(slug("www.example.com", BASE), None);
        assert_eq!(slug("api.example.com", BASE), None);
        assert_eq!(slug("xn--80ak6aa92e.example.com", BASE), None);
        assert_eq!(slug("-bad.example.com", BASE), None);
    }

    #[test]
    fn rejects_the_apex_and_foreign_domains() {
        assert_eq!(slug("example.com", BASE), None);
        assert_eq!(slug("acme.evil.example", BASE), None);
        // Suffix must be on a label boundary, not a bare string match.
        assert_eq!(slug("notexample.com", BASE), None);
    }
}
