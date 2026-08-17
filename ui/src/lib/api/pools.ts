import { apiRequest } from "../api-client";

/**
 * What a pool is for. Immutable once set, and load-bearing rather than
 * descriptive: the console's management client is bound to the tenant's `staff`
 * pool, so an identity in a `customer` pool cannot hold a console session
 * however the tenant's other clients are configured.
 */
export type PoolKind = "staff" | "customer";

/**
 * A directory of identities inside a tenant. Identities are unique per pool,
 * not per tenant — the same email can be a tenant's administrator and an
 * unrelated end user of that tenant's application.
 */
export interface IdentityPool {
  id: string;
  tenant_id: string;
  slug: string;
  name: string;
  kind: PoolKind;
  description: string | null;
  config: Record<string, unknown>;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface CreatePoolRequest {
  /** DNS-label-shaped, unique within the tenant, immutable once set. */
  slug: string;
  name: string;
  description?: string;
}

/** Requires `TenantRead`. */
export async function listPools(): Promise<IdentityPool[]> {
  return apiRequest<IdentityPool[]>("/pools");
}

/**
 * Creates an end-user directory. There is deliberately no way to make a second
 * staff pool — the tenant's one is provisioned with the tenant — so this always
 * produces a `customer` pool. Requires `TenantUpdate`.
 */
export async function createPool(
  data: CreatePoolRequest
): Promise<IdentityPool> {
  return apiRequest<IdentityPool>("/pools", { method: "POST", body: data });
}

/** The tenant's single staff pool: the directory the console authenticates against. */
export function staffPool(pools: IdentityPool[]): IdentityPool | undefined {
  return pools.find((p) => p.kind === "staff");
}

/** End-user directories, in a stable presentation order. */
export function customerPools(pools: IdentityPool[]): IdentityPool[] {
  return pools
    .filter((p) => p.kind === "customer")
    .sort((a, b) => a.name.localeCompare(b.name));
}
