import { apiRequest } from "../api-client";

export interface Permission {
  id: string;
  key: string;
  description: string | null;
}

export interface Role {
  id: string;
  tenant_id: string;
  name: string;
  kind: "system" | "custom";
  description: string | null;
  permissions: Permission[];
  created_at: string;
  updated_at: string;
}

/**
 * Roles that together make an administrator, in the order they are presented.
 *
 * Mirrors what `create_tenant` grants its own admin identity — so "Administrator"
 * in the console means the same thing as the admin created alongside a tenant.
 */
export const ADMIN_ROLES = ["IdentityAdmin", "TenantAdmin", "ClientAdmin"] as const;

/** Granted to every identity at creation; never offered as a choice. */
export const IMPLICIT_ROLE = "IdentitySelf";

export async function listRoles(): Promise<Role[]> {
  return apiRequest<Role[]>("/roles");
}

export async function getIdentityRoles(identityId: string): Promise<string[]> {
  return apiRequest<string[]>(`/identity/${identityId}/roles`);
}

export async function assignRole(
  identityId: string,
  role: string
): Promise<{ message: string }> {
  return apiRequest<{ message: string }>(`/identity/${identityId}/roles`, {
    method: "POST",
    body: { role },
  });
}

export async function revokeRole(
  identityId: string,
  role: string
): Promise<{ message: string }> {
  return apiRequest<{ message: string }>(
    `/identity/${identityId}/roles/${encodeURIComponent(role)}`,
    { method: "DELETE" }
  );
}

/**
 * Whether the signed-in session could grant this role.
 *
 * The server enforces the same rule and is the authority — this only decides
 * whether to *offer* the role, so an admin isn't shown options that will fail.
 * You cannot grant a role carrying permissions you do not hold yourself.
 */
export function canGrant(role: Role, myScopes: string[]): boolean {
  return role.permissions.every((p) => myScopes.includes(p.key));
}

/** Permissions in `role` that the session is missing — used to explain a disabled option. */
export function missingFor(role: Role, myScopes: string[]): string[] {
  return role.permissions.map((p) => p.key).filter((k) => !myScopes.includes(k));
}
