import { apiRequest } from "../api-client";

/**
 * Mirrors `AuthenticationConfiguration` in `knox-common`. Durations are
 * serialised by `time::Duration`, which is why the seconds fields are not plain
 * numbers — they arrive as `{ secs, nanos }`.
 */
export interface AuthenticationConfig {
  sso_cookie_name: string;
  sso_cookie_secure: boolean;
  sso_cookie_same_site_lax: boolean;
  sso_cookie_lifetime_seconds: unknown;
  sso_cookie_domain: string | null;
  sso_cookie_path: string | null;
  mfa_token_lifetime_seconds: unknown;
  /** Issuer shown in authenticator apps; falls back to the tenant slug. */
  totp_issuer: string | null;
  mfa_max_verification_attempts: number;
  login_max_attempts_per_account: number;
  login_max_attempts_per_tenant: number;
  login_max_attempts_per_ip: number;
  login_attempt_window_seconds: unknown;
  should_return_cookie_in_body: boolean;
  should_return_cookie_on_re_auth: boolean;
  password_reset_token_lifetime_seconds: unknown;
  password_reset_url_template: string | null;
  self_service_password_reset: boolean;
}

/** Mirrors `AuthorizationConfiguration` in `knox-common`. */
export interface AuthorizationConfig {
  allow_plain_pkce: boolean;
  auth_code_ttl_seconds: number;
  /**
   * Withhold every scope beyond self-service from an identity with no verified
   * MFA method. Governs what a token may carry, not who may sign in.
   */
  require_admin_mfa: boolean;
}

/** Mirrors `AuditConfiguration` in `knox-common`. */
export interface AuditConfig {
  retention_days: number;
}

export interface TenantConfig {
  authentication_configuration: AuthenticationConfig;
  authorization_configuration: AuthorizationConfig;
  audit_configuration: AuditConfig;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  /** Canonical OIDC issuer. Stored, not derived — it never shifts with deploy config. */
  issuer: string;
  description: string | null;
  /** Owns cross-tenant operations. Exactly one per deployment, and undeletable. */
  is_platform: boolean;
  status: string;
  config: TenantConfig;
  created_at: string;
  updated_at: string;
}

export interface AdminUser {
  id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  status: "active" | "inactive";
}

export interface CreateTenantRequest {
  name: string;
  /// URL-safe identifier: lowercase alphanumeric and hyphens. Immutable after creation.
  slug: string;
  description?: string;
  management_redirect_uris?: string[];
  admin_user?: {
    email: string;
    password: string;
    first_name?: string;
    last_name?: string;
  };
}

export interface CreateTenantResponse {
  tenant: Tenant;
  admin_client_id: string;
  admin_client_secret: string;
  admin_identity: AdminUser | null;
}

export async function listTenants(): Promise<Tenant[]> {
  const result = await apiRequest<[Tenant[], number]>("/tenant");
  return result[0];
}

export async function getTenant(tenantId: string): Promise<Tenant> {
  return apiRequest<Tenant>(`/tenant/${tenantId}`);
}

export async function createTenant(
  data: CreateTenantRequest
): Promise<CreateTenantResponse> {
  return apiRequest<CreateTenantResponse>("/tenant", {
    method: "POST",
    body: data,
  });
}

/**
 * Deletes a tenant and everything it owns — identities, pools, clients, signing
 * keys and audit history all cascade. Requires PlatformTenantDelete; the server
 * refuses for the platform tenant itself.
 */
export async function deleteTenant(
  slug: string
): Promise<{ message: string; detail?: string }> {
  return apiRequest<{ message: string; detail?: string }>(`/tenant/${slug}`, {
    method: "DELETE",
  });
}
