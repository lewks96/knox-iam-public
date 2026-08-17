/**
 * The tenant is the subdomain of the host — `acme` in `acme.knox.example.com`.
 *
 * Mirrors `tenant_slug_from_host` in the server's tenant_host.rs. The server is
 * authoritative: this exists so the UI can label things and build URLs without a
 * round trip. Anything security-relevant is decided server-side from the same
 * Host header.
 */
const BASE_DOMAIN = process.env.NEXT_PUBLIC_BASE_DOMAIN ?? "lvh.me";

/** Extracts the tenant label from a host, or null if the host names no tenant. */
export function tenantFromHost(host: string | null | undefined): string | null {
  if (!host) return null;

  // Strip the port; bracketed IPv6 literals must not split on inner colons.
  const withoutPort = host.startsWith("[")
    ? (host.split("]")[0] ?? "").slice(1)
    : (host.split(":")[0] ?? "");
  const normalised = withoutPort.toLowerCase().replace(/\.$/, "");

  const base = BASE_DOMAIN.toLowerCase().split(":")[0]!.replace(/\.$/, "");
  if (!normalised.endsWith(`.${base}`)) return null;

  const label = normalised.slice(0, -(base.length + 1));
  // Exactly one label — `a.b.example.com` names no tenant.
  if (!label || label.includes(".")) return null;

  if (RESERVED.has(label)) return null;

  return label;
}

/**
 * A UX guard, not a security boundary — it stops us rendering a login form on
 * an infrastructure hostname. The authoritative list is RESERVED_SUBDOMAINS in
 * the server's tenant.rs, which rejects everything this misses; a name here need
 * only be a subset.
 */
const RESERVED = new Set([
  "www", "api", "app", "admin", "console", "login", "auth", "sso",
  "mail", "cdn", "static", "docs", "status", "knox",
]);

/** Client components: the tenant for the page currently being viewed. */
export function currentTenant(): string | null {
  if (typeof window === "undefined") return null;
  return tenantFromHost(window.location.hostname);
}
