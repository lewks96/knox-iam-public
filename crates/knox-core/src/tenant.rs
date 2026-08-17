use knox_common::authorization::{AuthorizationRepository, Role, RoleKind};
use knox_common::client::{ClientRepository, ClientType};
use knox_common::error::ServiceError;
use knox_common::identity::{IdentityRepository, PublicIdentity, Status};
use knox_common::key::{KeyAlgorithm, KeyEncryptionProvider, KeyRepository};
use knox_common::pool::{CreatePool, IdentityPool, PoolKind, PoolRepository};
use knox_common::tenant::{Tenant, TenantConfiguration, TenantRepository, TenantUpdates};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, instrument};
use uuid::Uuid;
use validator::Validate;

use crate::client::{ClientService, CreateClientRequest};
use crate::identity::{CreateIdentityRequest, IdentityService};
use crate::key::{CreateKeyRequest, KeyService};
use crate::roles::{
    KnoxRole, TENANT_CREATE_SCOPE, admin_tenant_role, audit_viewer_role, basic_user_role,
    client_admin_role, default_tenant_role, identity_admin_role, identity_create_role,
    identity_viewer_role, platform_admin_role, tenant_creator_role,
};
// =========================================================================
//  DTOs
// =========================================================================

/// Credentials for the initial admin user created alongside the tenant.
#[derive(Debug, Deserialize)]
pub struct AdminUserRequest {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Default, Validate, Deserialize)]
pub struct CreateTenantRequest {
    #[validate(length(
        min = 3,
        max = 100,
        message = "Tenant name must be between 3 and 100 characters"
    ))]
    pub name: String,

    #[validate(length(
        min = 3,
        max = 63,
        message = "Slug must be between 3 and 63 characters"
    ))]
    pub slug: String,

    #[validate(length(max = 500))]
    pub description: Option<String>,

    /// Redirect URIs for the management client's authorization_code flow.
    /// Required if a web admin UI will use this tenant's management client.
    #[serde(default)]
    pub management_redirect_uris: Option<Vec<String>>,

    /// If provided, an admin identity is created and assigned all admin roles.
    pub admin_user: Option<AdminUserRequest>,

    /// Makes this the platform tenant: it additionally receives the
    /// `PlatformAdmin` role and its management client is allowed the platform
    /// scopes. Only bootstrap sets this — there is deliberately no way to
    /// request it over the API, and a partial unique index caps it at one.
    #[serde(skip_deserializing)]
    pub is_platform: bool,
}

#[derive(Debug, Validate, Deserialize)]
pub struct UpdateTenantRequest {
    #[validate(length(min = 3, max = 100))]
    pub name: Option<String>,

    #[validate(length(max = 500))]
    pub description: Option<String>,

    pub status: Option<Status>,
}

#[derive(Debug, Deserialize)]
pub struct TenantSearchRequest {
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Serialize)]
pub struct CreateTenantResponse {
    pub tenant: Tenant,
    pub admin_client_id: String,
    pub admin_client_secret: Option<String>,
    /// Present only when `admin_user` was supplied in the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_identity: Option<PublicIdentity>,
}

// =========================================================================
//  The Service
// =========================================================================

#[derive(Clone)]
pub struct TenantService<
    R: TenantRepository,
    A: AuthorizationRepository,
    K: KeyRepository,
    P: KeyEncryptionProvider,
    C: ClientRepository,
    I: IdentityRepository,
    PL: PoolRepository,
> {
    tenant_repo: R,
    pool_repo: PL,
    auth_repo: A,
    key_service: KeyService<K, P>,
    client_service: ClientService<C>,
    identity_service: IdentityService<I, A>,
    /// Only consulted when minting a new tenant's issuer.
    issuer_config: IssuerConfig,
}

impl<
    R: TenantRepository,
    A: AuthorizationRepository,
    K: KeyRepository,
    P: KeyEncryptionProvider,
    C: ClientRepository,
    I: IdentityRepository,
    PL: PoolRepository,
> TenantService<R, A, K, P, C, I, PL>
{
    pub fn new(
        tenant_repo: R,
        pool_repo: PL,
        auth_repo: A,
        key_service: KeyService<K, P>,
        client_service: ClientService<C>,
        identity_service: IdentityService<I, A>,
        issuer_config: IssuerConfig,
    ) -> Self {
        Self {
            tenant_repo,
            pool_repo,
            auth_repo,
            key_service,
            client_service,
            identity_service,
            issuer_config,
        }
    }

    #[instrument(skip(self))]
    async fn create_internal_role(
        &self,
        tenant_id: Uuid,
        role: &KnoxRole,
    ) -> Result<Role, ServiceError> {
        let (role_name, perms) = role.parts();
        self.auth_repo
            .create_role(tenant_id, role_name, &perms, RoleKind::System)
            .await
            .map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn create_tenant(
        &self,
        req: CreateTenantRequest,
    ) -> Result<CreateTenantResponse, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        if !is_valid_slug(&req.slug) {
            return Err(ServiceError::Validation(
                "Slug must be lowercase alphanumeric and hyphens only, cannot start or end with a hyphen, and cannot contain consecutive hyphens".into(),
            ));
        }

        // Reserving the slug (a hostname) is what matters — the previous check
        // reserved `name`, which is display text and carries no such risk.
        if is_reserved_slug(&req.slug) {
            return Err(ServiceError::Validation(format!(
                "'{}' is a reserved subdomain and cannot be used as a tenant slug",
                req.slug
            )));
        }

        // Derived once, here, and persisted — see IssuerConfig.
        let issuer = self.issuer_config.issuer_for_slug(&req.slug);
        debug!("Creating tenant '{}' with issuer {}", req.name, issuer);
        let tenant = self
            .tenant_repo
            .create(
                &req.name,
                &req.slug,
                &issuer,
                req.description,
                req.is_platform,
            )
            .await
            .map_err(ServiceError::Repository)?;

        // The staff pool must exist before the management client and admin
        // identity, since both bind to it. A tenant without one has no console
        // access at all, so failing to create it rolls the tenant back.
        let staff_pool = match self
            .pool_repo
            .create(&CreatePool {
                tenant_id: tenant.id,
                slug: "staff".into(),
                name: "Staff".into(),
                kind: PoolKind::Staff,
                description: Some("Administrative and console identities".into()),
            })
            .await
        {
            Ok(p) => p,
            Err(e) => {
                error!(
                    "Failed to create staff pool for tenant {}, rolling back: {:?}",
                    tenant.id, e
                );
                let _ = self.tenant_repo.delete(tenant.id).await;
                return Err(ServiceError::Internal(
                    "Failed to create staff pool for tenant".into(),
                ));
            }
        };

        debug!(
            "Tenant created with ID: {}, staff pool {}, creating internal roles",
            tenant.id, staff_pool.id
        );
        let basic_role_desc = basic_user_role();
        let viewer_role_desc = identity_viewer_role();
        let create_role_desc = identity_create_role();
        let admin_role_desc = identity_admin_role();
        let default_role_desc = default_tenant_role();
        let tenant_admin_role_desc = admin_tenant_role();
        let client_admin_role_desc = client_admin_role();
        let audit_viewer_role_desc = audit_viewer_role();

        let mut role_descs = vec![
            &basic_role_desc,
            &viewer_role_desc,
            &create_role_desc,
            &admin_role_desc,
            &default_role_desc,
            &tenant_admin_role_desc,
            &client_admin_role_desc,
            &audit_viewer_role_desc,
        ];

        // Cross-tenant roles exist only in the platform tenant. An ordinary
        // tenant has no role carrying TenantCreate or any Platform* scope, so
        // `permitted_scopes` cannot mint one into a customer's token however the
        // client is configured.
        let tenant_creator_role_desc = tenant_creator_role();
        let platform_admin_role_desc = platform_admin_role();
        if req.is_platform {
            role_descs.push(&tenant_creator_role_desc);
            role_descs.push(&platform_admin_role_desc);
        }

        for role_desc in &role_descs {
            if let Err(e) = self.create_internal_role(tenant.id, role_desc).await {
                error!(
                    "Failed to create internal role '{}' for tenant {}, rolling back: {:?}",
                    role_desc.name(),
                    tenant.id,
                    e
                );
                let _ = self.tenant_repo.delete(tenant.id).await;
                return Err(ServiceError::Internal(
                    "Failed to create internal roles for tenant".into(),
                ));
            }
        }

        let params = CreateKeyRequest {
            kid: None,
            algorithm: Some(KeyAlgorithm::RS256),
            validity_days: Some(365),
        };

        debug!("Creating default signing key for tenant {}", tenant.id);
        self.key_service.create_key(tenant.id, params).await?;

        // Create the admin M2M client for management API access
        debug!("Creating admin M2M client for tenant {}", tenant.id);

        // Two different questions, answered in two different places:
        //
        //   allowed_scopes  — what this client may ever *request*
        //   permitted_scopes — what this identity is actually *granted*
        //
        // The console is one build serving every tenant, so it requests the same
        // scope list everywhere; the authorize endpoint rejects the whole request
        // if any requested scope is not allowed by the client. Hence the platform
        // scopes appear here for every tenant.
        //
        // That is safe precisely because of the second line: the roles carrying
        // Platform* permissions exist only in the platform tenant, so for anyone
        // else `permitted_scopes` narrows them away and the minted token simply
        // does not contain them. Advertising a scope is not granting it.
        let mut scopes: Vec<String> = role_descs
            .iter()
            .flat_map(|r| r.scopes().iter().cloned())
            .chain(platform_admin_role().scopes().iter().cloned())
            .chain(std::iter::once(TENANT_CREATE_SCOPE.to_string()))
            .collect();
        scopes.sort();
        scopes.dedup();

        let redirect_uris = req.management_redirect_uris.clone().unwrap_or_default();
        let supports_auth_code = !redirect_uris.is_empty();

        debug!(
            "Management redirect URIs: {:?}, supports_auth_code: {}",
            redirect_uris, supports_auth_code
        );

        let mut grant_types = vec!["client_credentials".to_string()];
        let mut response_types = vec![];
        let mut allow_refresh_tokens = false;
        if supports_auth_code {
            grant_types.push("authorization_code".into());
            grant_types.push("refresh_token".into());
            response_types.push("code".into());
            allow_refresh_tokens = true;
        }

        debug!(
            "Management client grant_types: {:?}, allow_refresh_tokens: {}",
            grant_types, allow_refresh_tokens
        );

        let admin_client_req = CreateClientRequest {
            tenant_id: tenant.id,
            // Binding the console's client to the staff pool is what makes end
            // users structurally unable to log into it.
            pool_id: staff_pool.id,
            name: "management".into(),
            description: Some("Auto-provisioned M2M client for management API access".into()),
            logo_uri: None,
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: "client_secret_basic".into(),
            allow_refresh_tokens,
            grant_types,
            response_types,
            redirect_uris,
            post_logout_redirect_uris: vec![],
            allowed_scopes: scopes,
            access_token_ttl: Some(3600),
            refresh_token_ttl: if allow_refresh_tokens {
                Some(86400)
            } else {
                None
            },
            id_token_ttl: None,
            auth_code_ttl: if supports_auth_code { Some(600) } else { None },
            token_version: Some(1),
        };

        let admin_client_response = self
            .client_service
            .create_client(admin_client_req)
            .await
            .map_err(|e| {
                error!(
                    "Failed to create admin client for tenant {}: {:?}",
                    tenant.id, e
                );
                // Note: We don't rollback the tenant here as it's still usable,
                // just without the admin client. Caller can manually create one.
                e
            })?;

        debug!(
            "Admin M2M client created with ID: {} for tenant {}",
            admin_client_response.client.id, tenant.id
        );

        // If admin user data was provided, create the admin identity and assign admin roles
        let admin_identity = if let Some(admin_user_req) = req.admin_user {
            debug!(
                "Admin user request present, email: {}",
                admin_user_req.email
            );

            let mut admin_roles = vec![
                admin_role_desc.name().to_string(),
                tenant_admin_role_desc.name().to_string(),
                client_admin_role_desc.name().to_string(),
            ];

            // Only the platform tenant's admin gets cross-tenant authority.
            if req.is_platform {
                admin_roles.push(tenant_creator_role_desc.name().to_string());
                admin_roles.push(platform_admin_role_desc.name().to_string());
            }

            debug!("Admin roles to assign: {:?}", admin_roles);

            let identity_req = CreateIdentityRequest {
                tenant_id: tenant.id,
                pool_id: staff_pool.id,
                email: admin_user_req.email.clone(),
                username: admin_user_req.email,
                password: admin_user_req.password,
                first_name: admin_user_req.first_name,
                last_name: admin_user_req.last_name,
                initial_roles: Some(admin_roles),
            };

            debug!("Creating admin identity for tenant {}", tenant.id);
            let identity = self
                .identity_service
                .create_user(identity_req)
                .await
                .map_err(|e| {
                    error!(
                        "Failed to create admin identity for tenant {}: {:?}",
                        tenant.id, e
                    );
                    e
                })?;

            debug!(
                "Admin identity created with ID: {} for tenant {}",
                identity.id, tenant.id
            );
            Some(identity.into())
        } else {
            debug!("No admin user request provided in CreateTenantRequest");
            None
        };

        Ok(CreateTenantResponse {
            tenant,
            admin_client_id: "management".to_string(),
            admin_client_secret: admin_client_response.client_secret,
            admin_identity,
        })
    }

    /// The tenant's staff pool — the directory the console authenticates against.
    #[instrument(skip(self))]
    pub async fn get_staff_pool(&self, tenant_id: Uuid) -> Result<IdentityPool, ServiceError> {
        self.pool_repo
            .get_staff_pool(tenant_id)
            .await
            .map_err(ServiceError::Repository)?
            .ok_or_else(|| ServiceError::Internal("Tenant has no staff pool".into()))
    }

    #[instrument(skip(self))]
    pub async fn get_pool(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
    ) -> Result<IdentityPool, ServiceError> {
        self.pool_repo
            .get_in_tenant(tenant_id, pool_id)
            .await
            .map_err(ServiceError::Repository)?
            .ok_or_else(|| ServiceError::Validation("Pool not found".into()))
    }

    #[instrument(skip(self))]
    pub async fn list_pools(&self, tenant_id: Uuid) -> Result<Vec<IdentityPool>, ServiceError> {
        self.pool_repo
            .list(tenant_id)
            .await
            .map_err(ServiceError::Repository)
    }

    /// Creates an end-user pool. Staff pools are provisioned with the tenant and
    /// capped at one, so this deliberately cannot mint another.
    #[instrument(skip(self))]
    pub async fn create_customer_pool(
        &self,
        tenant_id: Uuid,
        slug: &str,
        name: &str,
        description: Option<String>,
    ) -> Result<IdentityPool, ServiceError> {
        if !is_valid_slug(slug) {
            return Err(ServiceError::Validation(
                "Pool slug must be lowercase alphanumeric and hyphens only".into(),
            ));
        }

        self.pool_repo
            .create(&CreatePool {
                tenant_id,
                slug: slug.to_string(),
                name: name.to_string(),
                kind: PoolKind::Customer,
                description,
            })
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn get_tenant(&self, id: Uuid) -> Result<Tenant, ServiceError> {
        self.tenant_repo
            .get(id)
            .await
            .map_err(ServiceError::Repository)?
            .ok_or_else(|| ServiceError::Validation("Tenant not found".into()))
    }

    #[instrument(skip(self, req))]
    pub async fn update_tenant(
        &self,
        id: Uuid,
        req: UpdateTenantRequest,
    ) -> Result<Tenant, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        let updates = TenantUpdates {
            name: req.name,
            description: req.description,
            status: req.status,
            config: None,
        };

        self.tenant_repo
            .update(id, &updates)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn delete_tenant(&self, id: Uuid) -> Result<(), ServiceError> {
        // Critical: Deleting a tenant usually cascades to ALL data (users, roles, etc.)
        // This should be a highly privileged operation.
        self.tenant_repo
            .delete(id)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self, req))]
    pub async fn list_tenants(
        &self,
        req: TenantSearchRequest,
    ) -> Result<(Vec<Tenant>, u64), ServiceError> {
        // Admin-only operation usually
        self.tenant_repo
            .list(req.page, req.page_size)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn get_tenant_config(&self, id: Uuid) -> Result<TenantConfiguration, ServiceError> {
        match self.tenant_repo.get(id).await? {
            Some(tenant) => Ok(tenant.config),
            None => Err(ServiceError::Validation("Tenant not found".into())),
        }
    }

    #[instrument(skip(self))]
    pub async fn get_tenant_by_slug(&self, slug: &str) -> Result<Tenant, ServiceError> {
        self.tenant_repo
            .get_by_slug(slug)
            .await
            .map_err(ServiceError::Repository)?
            .ok_or_else(|| ServiceError::Validation("Tenant not found".into()))
    }

    #[instrument(skip(self, config))]
    pub async fn save_tenant_config(
        &self,
        id: Uuid,
        config: TenantConfiguration,
    ) -> Result<(), ServiceError> {
        let updates = TenantUpdates {
            name: None,
            description: None,
            status: None,
            config: Some(config),
        };

        let _ = self
            .tenant_repo
            .update(id, &updates)
            .await
            .map_err(ServiceError::Repository)?;

        Ok(())
    }
}

/// How a new tenant's canonical issuer is derived from deployment config.
///
/// Used **only** when creating a tenant: the result is written to the tenant row
/// and read verbatim from then on. Nothing at request time consults this, which
/// is what stops a config change from silently re-identifying every tenant.
#[derive(Debug, Clone)]
pub struct IssuerConfig {
    pub scheme: String,
    pub base_domain: String,
    pub port: Option<u16>,
}

impl IssuerConfig {
    pub fn from_env() -> Self {
        Self {
            scheme: std::env::var("KNOX_SCHEME").unwrap_or_else(|_| "https".into()),
            base_domain: std::env::var("KNOX_BASE_DOMAIN").unwrap_or_else(|_| "localhost".into()),
            port: std::env::var("KNOX_PUBLIC_PORT")
                .ok()
                .and_then(|p| p.parse().ok()),
        }
    }

    /// `{scheme}://{slug}.{base_domain}[:{port}]` — the tenant's subdomain.
    pub fn issuer_for_slug(&self, slug: &str) -> String {
        match self.port {
            Some(port) => format!("{}://{}.{}:{}", self.scheme, slug, self.base_domain, port),
            None => format!("{}://{}.{}", self.scheme, slug, self.base_domain),
        }
    }
}

/// Validates that a slug is lowercase alphanumeric + hyphens, does not start/end
/// with a hyphen, and contains no consecutive hyphens.
///
/// The slug is a DNS label: it becomes the tenant's subdomain and therefore part
/// of its permanent OIDC issuer. It is immutable once set — there is deliberately
/// no slug field on `UpdateTenantRequest` or `TenantUpdates`, because renaming one
/// would change the issuer and break every relying party trusting that tenant.
pub fn is_valid_slug(slug: &str) -> bool {
    let len = slug.len();
    if len < 3 || len > 63 {
        return false;
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return false;
    }
    if slug.contains("--") {
        return false;
    }
    // `xn--` is the punycode prefix; allowing it invites homograph confusion with
    // reserved names once the slug is rendered as a hostname.
    if slug.starts_with("xn-") {
        return false;
    }
    // All-numeric labels are ambiguous with IP-literal hosts in some resolvers.
    if slug.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    slug.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Subdomains that must never be handed to a tenant. A tenant owning one of these
/// would shadow platform infrastructure on the shared base domain — which is a
/// phishing primitive as much as an outage.
///
/// `sandbox` is intentionally absent: it is a normal example tenant.
pub const RESERVED_SUBDOMAINS: &[&str] = &[
    // platform + product
    "knox",
    "root",
    "system",
    "sys",
    "platform",
    "tenant",
    "tenants",
    "localhost",
    // web / console
    "www",
    "api",
    "app",
    "admin",
    "console",
    "dashboard",
    "portal",
    // auth surfaces
    "login",
    "logout",
    "auth",
    "authn",
    "authz",
    "sso",
    "oauth",
    "oauth2",
    "idp",
    "id",
    // mail + DNS (owning these enables mail spoofing / domain validation abuse)
    "mail",
    "smtp",
    "imap",
    "pop",
    "mx",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "autodiscover",
    "autoconfig",
    "dmarc",
    "dkim",
    "spf",
    // assets + delivery
    "cdn",
    "static",
    "assets",
    "img",
    "media",
    "files",
    "download",
    // ops + docs
    "docs",
    "doc",
    "help",
    "support",
    "status",
    "health",
    "metrics",
    "grafana",
    "prometheus",
    "observe",
    "aspire",
    // environments
    "dev",
    "develop",
    "staging",
    "stage",
    "test",
    "testing",
    "demo",
    "preview",
    // internal
    "internal",
    "intranet",
    "vpn",
    "git",
    "ci",
    "build",
    "deploy",
    "registry",
    // content
    "blog",
    "news",
    "about",
    "legal",
    "privacy",
    "terms",
];

/// Deployment-specific additions from `KNOX_EXTRA_RESERVED_SUBDOMAINS`
/// (comma-separated). Read once.
fn extra_reserved_subdomains() -> &'static [String] {
    static EXTRA: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    EXTRA.get_or_init(|| {
        std::env::var("KNOX_EXTRA_RESERVED_SUBDOMAINS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Checked at tenant creation *and* at host resolution, so adding a name here
/// immediately stops serving it even if a row already exists.
pub fn is_reserved_slug(slug: &str) -> bool {
    let slug = slug.to_ascii_lowercase();
    RESERVED_SUBDOMAINS.contains(&slug.as_str())
        || extra_reserved_subdomains().iter().any(|s| *s == slug)
}

#[cfg(test)]
mod slug_tests {
    use super::*;

    #[test]
    fn accepts_valid_dns_labels() {
        for slug in [
            "acme",
            "knox-root",
            "sandbox",
            "a1b",
            "user1-example-com",
        ] {
            assert!(is_valid_slug(slug), "expected {slug} to be valid");
        }
    }

    #[test]
    fn rejects_shapes_that_are_not_dns_labels() {
        for slug in [
            "ab",            // too short
            &"a".repeat(64), // too long (63 max)
            "-acme",         // leading hyphen
            "acme-",         // trailing hyphen
            "ac--me",        // consecutive hyphens
            "Acme",          // uppercase
            "ac me",         // space
            "ac.me",         // dot — would create a multi-level host
            "ac_me",         // underscore is not a DNS label char
        ] {
            assert!(!is_valid_slug(slug), "expected {slug} to be rejected");
        }
    }

    #[test]
    fn rejects_punycode_prefix_and_all_numeric() {
        // Homograph confusion against reserved names once rendered as a host.
        assert!(!is_valid_slug("xn--80ak6aa92e"));
        // Ambiguous with IP-literal hosts.
        assert!(!is_valid_slug("12345"));
        // Digits are fine as long as the label is not entirely numeric.
        assert!(is_valid_slug("1password"));
    }

    #[test]
    fn reserves_platform_subdomains() {
        for slug in ["www", "api", "admin", "login", "mail", "knox", "status"] {
            assert!(is_reserved_slug(slug), "expected {slug} to be reserved");
        }
    }

    #[test]
    fn does_not_reserve_ordinary_tenant_slugs() {
        // `sandbox` is an example tenant and must stay available; ordinary
        // tenant slugs must remain creatable.
        for slug in ["sandbox", "acme", "knox-root", "user1-example-com"] {
            assert!(!is_reserved_slug(slug), "expected {slug} to be available");
        }
    }

    #[test]
    fn reserved_check_is_case_insensitive() {
        assert!(is_reserved_slug("ADMIN"));
    }
}
