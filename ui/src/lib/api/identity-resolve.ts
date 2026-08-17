import { ApiError } from "../api-client";
import { getIdentity, type Identity } from "./identity";
import { customerPools, listPools, type IdentityPool } from "./pools";

/**
 * Fetches an identity when the directory it lives in is not known.
 *
 * An identity request without `pool_id` resolves against the caller's own pool
 * — the staff one, for a console session — which answers for administrators and
 * 404s for everyone else. Audit events name actors by id alone, and an actor
 * can just as easily be a customer signing in to a tenant's application, so a
 * 404 there means "look elsewhere" rather than "deleted".
 *
 * `loadPools` is passed in so callers can share their cached copy: a page of
 * audit events resolves several actors, and re-listing the directories for each
 * would be pure waste.
 */
export async function resolveIdentity(
  tenantId: string,
  identityId: string,
  poolId: string | undefined,
  loadPools: () => Promise<IdentityPool[]>
): Promise<Identity> {
  if (poolId) return getIdentity(tenantId, identityId, poolId);

  try {
    return await getIdentity(tenantId, identityId);
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 404)) throw err;

    let pools: IdentityPool[];
    try {
      pools = customerPools(await loadPools());
    } catch {
      // No TenantRead: there is nothing to widen the search with, so the
      // original 404 is the honest answer.
      throw err;
    }

    for (const pool of pools) {
      try {
        return await getIdentity(tenantId, identityId, pool.id);
      } catch (poolErr) {
        if (!(poolErr instanceof ApiError && poolErr.status === 404)) throw poolErr;
      }
    }
    throw err;
  }
}

/** The pools query every caller of {@link resolveIdentity} shares. */
export const poolsQuery = {
  queryKey: ["pools"] as const,
  queryFn: listPools,
  staleTime: 5 * 60 * 1000,
};
