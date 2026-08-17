import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { tenantFromHost } from "./tenant";

/**
 * Server components: the tenant for this request, from the Host header.
 *
 * Replaces the old `[tenant]` route param. A host that names no tenant is a
 * 404 — there is no sensible page to render without one, and the server would
 * reject the API calls anyway.
 */
export async function getTenant(): Promise<string> {
  const h = await headers();
  const tenant = tenantFromHost(h.get("x-forwarded-host") ?? h.get("host"));
  if (!tenant) notFound();
  return tenant;
}
