import { apiRequest } from "../api-client";

export type ClientType = "confidential" | "public";
export type GrantType =
  | "authorization_code"
  | "client_credentials"
  | "refresh_token";
export type ResponseType = "code";
export type TokenEndpointAuthMethod = "client_secret_basic" | "none";

export interface OAuthClient {
  id: string;
  tenant_id: string;
  /** The identity pool this client authenticates against — whose credentials
   * are even checkable at it. */
  pool_id: string;
  name: string;
  description: string | null;
  logo_uri: string | null;
  client_type: ClientType;
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  allow_refresh_tokens: boolean;
  grant_types: GrantType[];
  response_types: ResponseType[];
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  allowed_scopes: string[];
  require_pkce: boolean;
  access_token_ttl: number;
  refresh_token_ttl: number;
  id_token_ttl: number;
  auth_code_ttl: number;
  token_version: number;
  status: "active" | "inactive";
  metadata: Record<string, unknown>;
  custom_attributes: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ClientListResponse {
  items: OAuthClient[];
  total: number;
  page: number;
  page_size: number;
}

export interface CreateClientRequest {
  name: string;
  /** Which identity pool this client authenticates against. When omitted the
   * server binds the client to the creator's own pool (the staff pool). */
  pool_id?: string;
  description?: string | null;
  logo_uri?: string | null;
  client_type: ClientType;
  token_endpoint_auth_method?: TokenEndpointAuthMethod;
  allow_refresh_tokens?: boolean;
  grant_types: GrantType[];
  response_types?: ResponseType[];
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  allowed_scopes: string[];
  access_token_ttl?: number;
  refresh_token_ttl?: number;
  id_token_ttl?: number;
  auth_code_ttl?: number;
}

export interface UpdateClientRequest {
  description?: string | null;
  logo_uri?: string | null;
  token_endpoint_auth_method?: TokenEndpointAuthMethod;
  allow_refresh_tokens?: boolean;
  grant_types?: GrantType[];
  response_types?: ResponseType[];
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  allowed_scopes?: string[];
  require_pkce?: boolean;
  access_token_ttl?: number;
  refresh_token_ttl?: number;
  id_token_ttl?: number;
  auth_code_ttl?: number;
  status?: "active" | "inactive";
}

export interface CreateClientResponse {
  client: OAuthClient;
  client_secret: string | null;
}

export interface RotateSecretResponse {
  client: OAuthClient;
  client_secret: string;
}

export interface GenericMessage {
  message: string;
}

export async function listClients(
  tenantId: string,
  page = 1,
  pageSize = 20,
  status?: "active" | "inactive"
): Promise<ClientListResponse> {
  return apiRequest<ClientListResponse>(`/clients`, {
    params: { page, page_size: pageSize, ...(status ? { status } : {}) },
  });
}

export async function getClient(
  tenantId: string,
  clientId: string
): Promise<OAuthClient> {
  return apiRequest<OAuthClient>(`/clients/${clientId}`);
}

export async function createClient(
  tenantId: string,
  data: CreateClientRequest
): Promise<CreateClientResponse> {
  return apiRequest<CreateClientResponse>(`/clients`, {
    method: "POST",
    body: data,
  });
}

export async function updateClient(
  tenantId: string,
  clientId: string,
  data: UpdateClientRequest
): Promise<OAuthClient> {
  return apiRequest<OAuthClient>(`/clients/${clientId}`, {
    method: "PATCH",
    body: data,
  });
}

export async function deleteClient(
  tenantId: string,
  clientId: string
): Promise<GenericMessage> {
  return apiRequest<GenericMessage>(`/clients/${clientId}`, {
    method: "DELETE",
  });
}

export async function rotateClientSecret(
  tenantId: string,
  clientId: string
): Promise<RotateSecretResponse> {
  return apiRequest<RotateSecretResponse>(
    `/clients/${clientId}/rotate-secret`,
    { method: "POST" }
  );
}

export async function rotateTokenVersion(
  tenantId: string,
  clientId: string
): Promise<OAuthClient> {
  return apiRequest<OAuthClient>(
    `/clients/${clientId}/rotate-token-version`,
    { method: "POST" }
  );
}
