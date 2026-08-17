/// Scope that marks a session as platform-level.
///
/// Held only by identities in the tenant flagged `is_platform`, because that is
/// the only tenant in which the `PlatformAdmin` role is provisioned. Gating on
/// this rather than on a tenant slug means the client agrees with the server by
/// construction — the previous `knox-root` constant was a convention the UI had
/// no way to verify, and the server did not enforce.
export const PLATFORM_SCOPE = "PlatformTenantList";

/// Scopes that act on the signed-in identity itself. Mirrors
/// `SELF_SERVICE_SCOPES` in the server's roles.rs.
const SELF_SERVICE_SCOPES = ["IdentityRead", "IdentityUpdate", "IdentityDelete"];

/**
 * True when the session holds nothing beyond self-service.
 *
 * This is what a tenant with `require_admin_mfa` hands an administrator who has
 * not enrolled a second factor: the login succeeds and the session is real, but
 * every administrative scope is withheld until they enroll. Without detecting
 * it the console renders its usual navigation and every call 403s, which reads
 * as breakage rather than as policy.
 *
 * An identity that genuinely holds only `IdentitySelf` looks identical from
 * here, which is fine — the same screen is the right destination for both.
 */
export function isSelfServiceOnly(scopes: string[]): boolean {
  return scopes.length > 0 && scopes.every((s) => SELF_SERVICE_SCOPES.includes(s));
}
