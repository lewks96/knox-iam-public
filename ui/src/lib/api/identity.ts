import { apiRequest } from "../api-client";

export interface Identity {
  id: string;
  tenant_id: string;
  /** The directory this identity lives in; uniqueness is scoped to it. */
  pool_id: string;
  kind: "Human" | "Machine";
  username: string;
  email: string;
  email_verified: boolean;
  first_name: string | null;
  last_name: string | null;
  metadata: Record<string, unknown>;
  custom_attributes: Record<string, unknown>;
  status: string;
  created_at: string;
  updated_at: string;
}

/**
 * Which directory an operation acts on.
 *
 * Omitting it means the caller's own pool — for a console session, the tenant's
 * staff pool. That default is why administrator screens can leave it out and
 * customer screens must not: a request without it reads and writes the
 * administrator directory.
 */
export interface PoolScoped {
  poolId?: string;
}

export interface IdentityListParams extends PoolScoped {
  page?: number;
  page_size?: number;
  query?: string;
  status?: "active" | "inactive";
}

export interface IdentityListResponse {
  items: Identity[];
  total: number;
  page: number;
  page_size: number;
}

export interface CreateIdentityRequest {
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
  /** Roles granted at creation — how an administrator is made. */
  roles?: string[];
  /** Defaults server-side to the caller's own pool. */
  pool_id?: string;
}

export interface UpdateIdentityRequest {
  email?: string;
  username?: string;
  first_name?: string;
  last_name?: string;
  status?: "active" | "inactive";
  metadata?: Record<string, unknown>;
  custom_attributes?: Record<string, unknown>;
}

export interface GenericMessage {
  message: string;
}

export async function listIdentities(
  tenantId: string,
  params?: IdentityListParams
): Promise<IdentityListResponse> {
  return apiRequest<IdentityListResponse>(`/identity`, {
    params: {
      page: params?.page,
      page_size: params?.page_size ?? 20,
      query: params?.query,
      status: params?.status,
      pool_id: params?.poolId,
    },
  });
}

export async function getIdentity(
  tenantId: string,
  identityId: string,
  poolId?: string
): Promise<Identity> {
  return apiRequest<Identity>(`/identity/${identityId}`, {
    params: { pool_id: poolId },
  });
}

export async function createIdentity(
  tenantId: string,
  data: CreateIdentityRequest
): Promise<Identity> {
  return apiRequest<Identity>(`/identity`, {
    method: "POST",
    body: data,
  });
}

export async function updateIdentity(
  tenantId: string,
  identityId: string,
  data: UpdateIdentityRequest,
  poolId?: string
): Promise<Identity> {
  return apiRequest<Identity>(`/identity/${identityId}`, {
    method: "PATCH",
    body: data,
    params: { pool_id: poolId },
  });
}

export async function deleteIdentity(
  tenantId: string,
  identityId: string,
  poolId?: string
): Promise<GenericMessage> {
  return apiRequest<GenericMessage>(`/identity/${identityId}`, {
    method: "DELETE",
    params: { pool_id: poolId },
  });
}
