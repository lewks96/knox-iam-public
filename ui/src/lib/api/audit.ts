import { apiRequest } from "../api-client";

export interface AuditEvent {
  id: string;
  tenant_id: string;
  occurred_at: string;
  event_type: string;
  actor_type: "identity" | "client" | "anonymous";
  actor_id: string | null;
  target_type: string | null;
  target_id: string | null;
  outcome: "success" | "failure" | "denied";
  ip: string | null;
  user_agent: string | null;
  correlation_id: string | null;
  details: Record<string, unknown>;
}

export interface AuditEventsResponse {
  items: AuditEvent[];
  next_cursor?: string;
}

export interface AuditEventsQuery {
  from?: string;
  to?: string;
  event_type?: string;
  outcome?: string;
  actor_id?: string;
  limit?: number;
  cursor?: string;
}

/**
 * List the tenant's audit events (newest first, keyset-paginated).
 * Requires the `AuditRead` scope.
 */
export async function listAuditEvents(
  tenantId: string,
  query: AuditEventsQuery = {}
): Promise<AuditEventsResponse> {
  return apiRequest<AuditEventsResponse>(`/audit/events`, {
    params: {
      from: query.from,
      to: query.to,
      event_type: query.event_type,
      outcome: query.outcome,
      actor_id: query.actor_id,
      limit: query.limit,
      cursor: query.cursor,
    },
  });
}

/** Known event types, grouped for the filter UI. The API treats this as an
 *  open set, so unknown types still render fine. */
export const AUDIT_EVENT_TYPES: { group: string; types: string[] }[] = [
  {
    group: "Authentication",
    types: [
      "auth.login",
      "auth.mfa_challenge",
      "auth.mfa_verify",
      "auth.mfa_lockout",
      "authz.cross_tenant_denied",
    ],
  },
  {
    group: "Tokens",
    types: ["token.issued", "token.refresh_reuse_detected"],
  },
  {
    group: "MFA enrollment",
    types: [
      "mfa.enroll_started",
      "mfa.enrolled",
      "mfa.removed",
      "mfa.backup_codes_regenerated",
    ],
  },
  {
    group: "Management",
    types: [
      "identity.created",
      "identity.updated",
      "identity.deleted",
      "client.created",
      "client.updated",
      "client.deleted",
    ],
  },
];
