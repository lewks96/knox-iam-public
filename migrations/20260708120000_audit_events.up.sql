-- Tenant-scoped audit events: append-only security event log.
-- Rows are written by a background writer; the same events are also emitted
-- as tracing events into the OTel pipeline. No updated_at / trigger: rows are
-- never updated.

CREATE TABLE audit_events
(
    id             UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Dotted taxonomy, e.g. 'auth.login', 'auth.mfa_verify', 'token.issued'.
    -- TEXT (not an enum) so new event types never need DDL.
    event_type     TEXT        NOT NULL,

    actor_type     TEXT        NOT NULL, -- 'identity' | 'client' | 'anonymous'
    actor_id       UUID,                 -- no FK: audit must outlive the actor

    target_type    TEXT,
    target_id      TEXT,

    outcome        TEXT        NOT NULL, -- 'success' | 'failure' | 'denied'

    ip             TEXT,
    user_agent     TEXT,
    -- OTel trace id (hex) of the request that produced the event; matches the
    -- x-correlation-id response header and the trace in the OTLP sink.
    correlation_id TEXT,

    -- Identifiers and small facts only - never secrets, credentials, or PII
    -- field values.
    details        JSONB       NOT NULL DEFAULT '{}'::jsonb
);

-- Newest-first keyset pagination per tenant.
CREATE INDEX idx_audit_events_tenant_time ON audit_events (tenant_id, occurred_at DESC, id DESC);
CREATE INDEX idx_audit_events_tenant_type ON audit_events (tenant_id, event_type, occurred_at DESC);
CREATE INDEX idx_audit_events_tenant_actor ON audit_events (tenant_id, actor_id, occurred_at DESC) WHERE actor_id IS NOT NULL;

-- ── Authorization seed ────────────────────────────────────────────────────────

INSERT INTO permissions (kind, key, description)
VALUES ('system', 'AuditRead', 'Can read the tenant audit event log')
ON CONFLICT (key) DO NOTHING;

-- Per-tenant AuditViewer role for existing tenants (new tenants get it from
-- TenantService role seeding).
INSERT INTO roles (id, tenant_id, name, description, kind)
SELECT gen_random_uuid(), t.id, 'AuditViewer', 'Can read the tenant audit event log', 'system'
FROM tenants t
ON CONFLICT (tenant_id, name) DO NOTHING;

-- AuditViewer and TenantAdmin both carry the AuditRead permission.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN permissions p ON p.key = 'AuditRead'
WHERE r.name IN ('AuditViewer', 'TenantAdmin')
  AND r.kind = 'system'
ON CONFLICT DO NOTHING;

-- Existing management clients may request the new scope.
UPDATE clients
SET allowed_scopes = array_append(allowed_scopes, 'AuditRead')
WHERE name = 'management'
  AND NOT ('AuditRead' = ANY (allowed_scopes));

-- ── Retention ────────────────────────────────────────────────────────────────
-- Daily prune honoring each tenant's audit_configuration.retention_days
-- (JSONB config), defaulting to 90 days. pg_cron extension is installed by
-- 20260424140000_refresh_token_cron.

SELECT cron.schedule(
               'prune-audit-events',
               '30 3 * * *',
               $$
        DELETE FROM audit_events a
        USING tenants t
        WHERE a.tenant_id = t.id
          AND a.occurred_at < now() - make_interval(
                days => COALESCE((t.config #>> '{audit_configuration,retention_days}')::int, 90))
    $$
       );
