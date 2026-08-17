import {
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
} from "./pkce";

/// Scopes the console asks for.
///
/// The server intersects these with what the identity's roles actually grant
/// (`permitted_scopes`), and strips every cross-tenant scope for non-platform
/// tenants — so asking broadly here is safe and asking narrowly is not free:
/// a scope the console never requests is one the operator can never *grant*,
/// because you cannot assign a role carrying permissions you do not hold.
///
/// That is why the full platform set is listed. Without it an existing platform
/// admin could not create a second one, and `PlatformAdmin` would sit
/// permanently disabled in the role picker.
export const CONSOLE_SCOPES = [
  "IdentityCreate",
  "IdentityRead",
  "IdentityUpdate",
  "IdentityDelete",
  "ClientCreate",
  "ClientRead",
  "ClientUpdate",
  "ClientDelete",
  "TenantCreate",
  "TenantRead",
  "TenantUpdate",
  "TenantDelete",
  "AuditRead",
  // Granted only in the platform tenant; narrowed away for everyone else.
  "PlatformTenantCreate",
  "PlatformTenantRead",
  "PlatformTenantUpdate",
  "PlatformTenantDelete",
  "PlatformTenantList",
  "PlatformIdentityCreate",
  "PlatformIdentityRead",
  "PlatformIdentityUpdate",
  "PlatformIdentityDelete",
  "PlatformIdentityList",
  "PlatformClientCreate",
  "PlatformClientRead",
  "PlatformClientUpdate",
  "PlatformClientDelete",
  "PlatformClientList",
  "PlatformRoleCreate",
  "PlatformRoleRead",
  "PlatformRoleUpdate",
  "PlatformRoleDelete",
  "PlatformRoleList",
  "PlatformConfigRead",
  "PlatformConfigWrite",
  "PlatformMetricsRead",
  "PlatformAuditRead",
].join(" ");

/**
 * Starts the console's own PKCE authorization request and leaves via a browser
 * redirect.
 *
 * The SSO cookie is what makes this work without a password: `/oauth2/authorize`
 * mints a code for an existing session, and bounces to the login page when
 * there isn't one. That is why it serves two callers — the login form, right
 * after credentials are accepted, and MFA setup, which needs a *new* token
 * because the one it is holding had its administrative scopes withheld. A
 * refresh cannot recover those: the refresh token records the narrowed set, so
 * only a fresh authorization re-evaluates what the identity may now hold.
 */
export async function startAuthorization(tenantId: string): Promise<void> {
  const verifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);
  const state = generateState();

  // The callback is on this tenant's own host; the client must have this exact
  // URI registered.
  const redirectUri = `${window.location.origin}/callback`;
  const clientId = process.env.NEXT_PUBLIC_MANAGEMENT_CLIENT_ID!;

  // Persist PKCE and expected state before the redirect.
  sessionStorage.setItem("knox_pkce_verifier", verifier);
  sessionStorage.setItem("knox_pkce_state", state);
  sessionStorage.setItem("knox_pkce_tenant", tenantId);

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: CONSOLE_SCOPES,
    response_type: "code",
  });

  window.location.href = `/oauth2/authorize?${params}`;
}
