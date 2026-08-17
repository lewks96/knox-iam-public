-- Marks the one tenant that owns platform-wide operations.
--
-- Until now "the platform tenant" was pure convention: the slug `knox-root`,
-- hardcoded in the UI and nowhere else. Nothing server-side enforced it, so the
-- Platform* permissions seeded in 20260303120000 had no subject to attach to
-- and every tenant's admin was handed TenantCreate instead.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_platform BOOLEAN NOT NULL DEFAULT false;

UPDATE tenants SET is_platform = true WHERE slug = 'knox-root';

-- A second platform tenant would be a second root of trust for the whole
-- deployment, so the cardinality is a constraint rather than a convention.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_single_platform
    ON tenants ((true)) WHERE is_platform;

-- NOTE: if a deployment's root tenant is not slugged `knox-root`, the UPDATE
-- above matches nothing and every platform-gated handler returns 403 until the
-- flag is set by hand. That is the correct direction to fail — the alternative
-- is guessing which tenant owns the platform.

-- `create_tenant` provisions the PlatformAdmin role, but only for tenants
-- created after this migration. Without the backfill below an existing
-- deployment migrates into a state where the platform gates are live and nobody
-- holds the scopes to pass them — i.e. the platform becomes unadministrable.
INSERT INTO roles (id, tenant_id, name, description, kind)
SELECT gen_random_uuid(), t.id, 'PlatformAdmin', 'Cross-tenant platform administration', 'system'
FROM tenants t
WHERE t.is_platform
ON CONFLICT (tenant_id, name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
         JOIN tenants t ON t.id = r.tenant_id AND t.is_platform
         JOIN permissions p ON p.key LIKE 'Platform%'
WHERE r.name = 'PlatformAdmin'
ON CONFLICT DO NOTHING;

-- Whoever could already create tenants is who this authority belonged to.
INSERT INTO identity_roles (identity_id, role_id)
SELECT ir.identity_id, plat.id
FROM identity_roles ir
         JOIN roles tc ON tc.id = ir.role_id AND tc.name = 'TenantCreator'
         JOIN tenants t ON t.id = tc.tenant_id AND t.is_platform
         JOIN roles plat ON plat.tenant_id = t.id AND plat.name = 'PlatformAdmin'
ON CONFLICT DO NOTHING;

-- TenantCreate is a cross-tenant power, so it now exists only in the platform
-- tenant. Every other tenant had it handed to its admin at creation, which is
-- what made the gate on create_tenant satisfiable by any tenant's admin.
DELETE FROM roles r
WHERE r.name = 'TenantCreator'
  AND r.tenant_id IN (SELECT id FROM tenants WHERE NOT is_platform);

-- allowed_scopes answers "what may this client request", not "what does this
-- identity get" — the latter is `permitted_scopes`, which intersects with the
-- caller's roles at issue time. The console is one build serving every tenant
-- and requests the same list everywhere, and the authorize endpoint rejects the
-- entire request if any requested scope is not allowed. So every management
-- client must allow the platform scopes; only the platform tenant has roles that
-- actually grant them.
UPDATE clients c
SET allowed_scopes = (
    SELECT array_agg(DISTINCT s ORDER BY s)
    FROM unnest(c.allowed_scopes || ARRAY(SELECT key FROM permissions WHERE key LIKE 'Platform%')
                                  || ARRAY['TenantCreate']) AS s
)
WHERE c.name = 'management';
