// Role name constants (DB-level grouping only, never checked in handlers)
pub(crate) const IDENTITY_SELF_ROLE_NAME: &str = "IdentitySelf";
const IDENTITY_VIEWER_ROLE: &str = "IdentityViewer";
const IDENTITY_CREATOR_ROLE: &str = "IdentityCreator";
const IDENTITY_ADMIN_ROLE: &str = "IdentityAdmin";
const TENANT_READER_ROLE: &str = "TenantReader";
const TENANT_ADMIN_ROLE: &str = "TenantAdmin";
const TENANT_CREATOR_ROLE: &str = "TenantCreator";
const CLIENT_ADMIN_ROLE: &str = "ClientAdmin";
const AUDIT_VIEWER_ROLE: &str = "AuditViewer";
const PLATFORM_ADMIN_ROLE: &str = "PlatformAdmin";

// Identity scopes
pub const IDENTITY_CREATE_SCOPE: &str = "IdentityCreate";
pub const IDENTITY_READ_SCOPE: &str = "IdentityRead";
pub const IDENTITY_UPDATE_SCOPE: &str = "IdentityUpdate";
pub const IDENTITY_DELETE_SCOPE: &str = "IdentityDelete";

// Tenant scopes
pub const TENANT_CREATE_SCOPE: &str = "TenantCreate";
pub const TENANT_READ_SCOPE: &str = "TenantRead";
pub const TENANT_UPDATE_SCOPE: &str = "TenantUpdate";
pub const TENANT_DELETE_SCOPE: &str = "TenantDelete";

// Client scopes
pub const CLIENT_CREATE_SCOPE: &str = "ClientCreate";
pub const CLIENT_READ_SCOPE: &str = "ClientRead";
pub const CLIENT_UPDATE_SCOPE: &str = "ClientUpdate";
pub const CLIENT_DELETE_SCOPE: &str = "ClientDelete";

// Audit scopes
pub const AUDIT_READ_SCOPE: &str = "AuditRead";

// Platform scopes.
//
// These act *across* tenants and are held only by identities in the platform
// tenant (`tenants.is_platform`). The tenant-scoped scopes above are deliberately
// not a subset relationship: TenantRead means "read my own tenant", whereas
// PlatformTenantRead means "read any tenant". Keeping them distinct is what stops
// a tenant admin's ordinary TenantRead from reaching across the platform, which
// is exactly how `list_tenants` leaked every tenant before this.
//
// Keys must match those seeded in migrations/20260303120000_platform_permissions.up.sql.
pub const PLATFORM_TENANT_CREATE_SCOPE: &str = "PlatformTenantCreate";
pub const PLATFORM_TENANT_READ_SCOPE: &str = "PlatformTenantRead";
pub const PLATFORM_TENANT_UPDATE_SCOPE: &str = "PlatformTenantUpdate";
pub const PLATFORM_TENANT_DELETE_SCOPE: &str = "PlatformTenantDelete";
pub const PLATFORM_TENANT_LIST_SCOPE: &str = "PlatformTenantList";

pub const PLATFORM_IDENTITY_CREATE_SCOPE: &str = "PlatformIdentityCreate";
pub const PLATFORM_IDENTITY_READ_SCOPE: &str = "PlatformIdentityRead";
pub const PLATFORM_IDENTITY_UPDATE_SCOPE: &str = "PlatformIdentityUpdate";
pub const PLATFORM_IDENTITY_DELETE_SCOPE: &str = "PlatformIdentityDelete";
pub const PLATFORM_IDENTITY_LIST_SCOPE: &str = "PlatformIdentityList";

pub const PLATFORM_CLIENT_CREATE_SCOPE: &str = "PlatformClientCreate";
pub const PLATFORM_CLIENT_READ_SCOPE: &str = "PlatformClientRead";
pub const PLATFORM_CLIENT_UPDATE_SCOPE: &str = "PlatformClientUpdate";
pub const PLATFORM_CLIENT_DELETE_SCOPE: &str = "PlatformClientDelete";
pub const PLATFORM_CLIENT_LIST_SCOPE: &str = "PlatformClientList";

pub const PLATFORM_ROLE_CREATE_SCOPE: &str = "PlatformRoleCreate";
pub const PLATFORM_ROLE_READ_SCOPE: &str = "PlatformRoleRead";
pub const PLATFORM_ROLE_UPDATE_SCOPE: &str = "PlatformRoleUpdate";
pub const PLATFORM_ROLE_DELETE_SCOPE: &str = "PlatformRoleDelete";
pub const PLATFORM_ROLE_LIST_SCOPE: &str = "PlatformRoleList";

pub const PLATFORM_CONFIG_READ_SCOPE: &str = "PlatformConfigRead";
pub const PLATFORM_CONFIG_WRITE_SCOPE: &str = "PlatformConfigWrite";
pub const PLATFORM_METRICS_READ_SCOPE: &str = "PlatformMetricsRead";
pub const PLATFORM_AUDIT_READ_SCOPE: &str = "PlatformAuditRead";

/// Scopes that act across tenants and therefore belong only to the platform
/// tenant.
///
/// `permitted_scopes` already keeps these out of identity-bearing tokens, since
/// no non-platform tenant has a role granting them. But `client_credentials` has
/// no identity and so no RBAC narrowing — it only checks `client.allowed_scopes`,
/// which every management client sets wide so the single console build can
/// request the same scopes on every tenant. Without this predicate, any tenant's
/// management client could mint platform authority as a machine token.
pub fn is_platform_scope(scope: &str) -> bool {
    scope.starts_with("Platform") || scope == TENANT_CREATE_SCOPE
}

//TODO: Try to avoid this allocation at some point
#[derive(Debug, Clone)]
pub struct KnoxRole {
    name: &'static str,
    scopes: Vec<String>,
}

impl KnoxRole {
    pub fn new(name: &'static str, scopes: Vec<&'static str>) -> Self {
        let v: Vec<String> = scopes.into_iter().map(|s| s.to_string()).collect();
        KnoxRole { name, scopes: v }
    }
    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn scopes(&self) -> &Vec<String> {
        &self.scopes
    }

    pub fn parts(&self) -> (&str, Vec<String>) {
        let v: Vec<String> = self.scopes.iter().map(|s| s.to_string()).collect();
        (self.name, v)
    }
}

/// What an identity may do to *itself* — the floor that remains when a token is
/// narrowed for want of MFA (`require_admin_mfa`).
///
/// Deliberately the same list `basic_user_role` grants, so the two cannot
/// drift: anything outside this set is, by definition, authority over someone
/// or something else and is what the second factor is protecting.
///
/// `IdentityUpdate` is load-bearing here. Every `/api/mfa/*` route gates on it
/// (see `self_identity_id`), so an identity narrowed below it could not enroll
/// and would have no way back — which is why narrowing withholds scopes rather
/// than refusing the login outright.
pub const SELF_SERVICE_SCOPES: &[&'static str] = &[
    IDENTITY_READ_SCOPE,
    IDENTITY_UPDATE_SCOPE,
    IDENTITY_DELETE_SCOPE,
];

pub fn is_self_service_scope(scope: &str) -> bool {
    SELF_SERVICE_SCOPES.contains(&scope)
}

/// Standard OpenID Connect / OAuth scopes.
///
/// These are not RBAC permissions — they select which claims a token carries and
/// whether a refresh token is issued, and they are authorised at
/// `/oauth2/authorize` against the client's `allowed_scopes`. They must be exempt
/// from `permitted_scopes`' intersection with the identity's held permissions:
/// an end user in a customer pool holds no `openid` permission, so without this a
/// plain CIAM login narrows to nothing and the token exchange fails closed with
/// `Forbidden`. For the same reason they are never withheld by the
/// `require_admin_mfa` narrowing — MFA gates authority over others, not the right
/// to prove who you are.
pub const OIDC_SCOPES: &[&'static str] = &[
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
];

pub fn is_oidc_scope(scope: &str) -> bool {
    OIDC_SCOPES.contains(&scope)
}

pub fn basic_user_role() -> KnoxRole {
    KnoxRole::new(IDENTITY_SELF_ROLE_NAME, SELF_SERVICE_SCOPES.to_vec())
}

pub fn identity_viewer_role() -> KnoxRole {
    KnoxRole::new(IDENTITY_VIEWER_ROLE, vec![IDENTITY_READ_SCOPE])
}

pub fn identity_create_role() -> KnoxRole {
    KnoxRole::new(IDENTITY_CREATOR_ROLE, vec![IDENTITY_CREATE_SCOPE])
}

pub fn identity_admin_role() -> KnoxRole {
    KnoxRole::new(
        IDENTITY_ADMIN_ROLE,
        vec![
            IDENTITY_CREATE_SCOPE,
            IDENTITY_READ_SCOPE,
            IDENTITY_UPDATE_SCOPE,
            IDENTITY_DELETE_SCOPE,
        ],
    )
}

pub fn default_tenant_role() -> KnoxRole {
    KnoxRole::new(TENANT_READER_ROLE, vec![TENANT_READ_SCOPE])
}

pub fn admin_tenant_role() -> KnoxRole {
    KnoxRole::new(
        TENANT_ADMIN_ROLE,
        vec![
            TENANT_READ_SCOPE,
            TENANT_UPDATE_SCOPE,
            TENANT_DELETE_SCOPE,
            AUDIT_READ_SCOPE,
        ],
    )
}

pub fn audit_viewer_role() -> KnoxRole {
    KnoxRole::new(AUDIT_VIEWER_ROLE, vec![AUDIT_READ_SCOPE])
}

/// Provisioned **only** in the platform tenant — see `create_tenant`.
///
/// Previously every tenant received this role and every tenant's admin was
/// assigned it, which made the TenantCreate gate on `create_tenant` satisfiable
/// by any tenant's admin.
pub fn tenant_creator_role() -> KnoxRole {
    KnoxRole::new(TENANT_CREATOR_ROLE, vec![TENANT_CREATE_SCOPE])
}

/// The cross-tenant role. Provisioned and assignable only within the platform
/// tenant; a non-platform tenant never has a role carrying any of these scopes,
/// so `permitted_scopes` cannot mint them into a customer's token.
pub fn platform_admin_role() -> KnoxRole {
    KnoxRole::new(
        PLATFORM_ADMIN_ROLE,
        vec![
            PLATFORM_TENANT_CREATE_SCOPE,
            PLATFORM_TENANT_READ_SCOPE,
            PLATFORM_TENANT_UPDATE_SCOPE,
            PLATFORM_TENANT_DELETE_SCOPE,
            PLATFORM_TENANT_LIST_SCOPE,
            PLATFORM_IDENTITY_CREATE_SCOPE,
            PLATFORM_IDENTITY_READ_SCOPE,
            PLATFORM_IDENTITY_UPDATE_SCOPE,
            PLATFORM_IDENTITY_DELETE_SCOPE,
            PLATFORM_IDENTITY_LIST_SCOPE,
            PLATFORM_CLIENT_CREATE_SCOPE,
            PLATFORM_CLIENT_READ_SCOPE,
            PLATFORM_CLIENT_UPDATE_SCOPE,
            PLATFORM_CLIENT_DELETE_SCOPE,
            PLATFORM_CLIENT_LIST_SCOPE,
            PLATFORM_ROLE_CREATE_SCOPE,
            PLATFORM_ROLE_READ_SCOPE,
            PLATFORM_ROLE_UPDATE_SCOPE,
            PLATFORM_ROLE_DELETE_SCOPE,
            PLATFORM_ROLE_LIST_SCOPE,
            PLATFORM_CONFIG_READ_SCOPE,
            PLATFORM_CONFIG_WRITE_SCOPE,
            PLATFORM_METRICS_READ_SCOPE,
            PLATFORM_AUDIT_READ_SCOPE,
        ],
    )
}

pub fn client_admin_role() -> KnoxRole {
    KnoxRole::new(
        CLIENT_ADMIN_ROLE,
        vec![
            CLIENT_CREATE_SCOPE,
            CLIENT_READ_SCOPE,
            CLIENT_UPDATE_SCOPE,
            CLIENT_DELETE_SCOPE,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_scopes_are_recognised_and_disjoint_from_permissions() {
        // The standard set is exempt from RBAC narrowing.
        assert!(is_oidc_scope("openid"));
        assert!(is_oidc_scope("offline_access"));
        assert!(is_oidc_scope("email"));

        // Permission scopes must never be treated as OIDC scopes, or the RBAC
        // narrowing they exist for would be bypassed.
        assert!(!is_oidc_scope(IDENTITY_READ_SCOPE));
        assert!(!is_oidc_scope(CLIENT_CREATE_SCOPE));
        assert!(!is_oidc_scope(PLATFORM_TENANT_LIST_SCOPE));

        // The two exemption sets are independent predicates.
        assert!(!is_self_service_scope("openid"));
        assert!(!is_oidc_scope(IDENTITY_UPDATE_SCOPE));
    }
}
