-- Identity pools: separate directories inside a tenant.
--
-- A tenant holds two very different populations — the handful of staff who
-- administer it through the console, and the tenant's own application end users.
-- `tenant_id` cannot tell them apart, so any end user could authenticate against
-- the auto-provisioned `management` client and obtain a console session. RBAC
-- narrowed what that token could do; nothing stopped it existing.
--
-- A client now binds to exactly one pool, and credential lookup happens within
-- that pool only. An end user presenting correct credentials to the management
-- client is not "denied" — their row is not visible to the query at all.

CREATE TYPE POOL_KIND AS ENUM ('staff', 'customer');

CREATE TABLE pools (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- Immutable, like tenants.slug: it identifies the directory a credential
    -- was checked against, and moving it would silently re-point live clients.
    slug        TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        POOL_KIND NOT NULL,
    description TEXT,
    -- Seam for per-pool policy (MFA requirement, password rules, token TTLs)
    -- overriding the tenant defaults. Deliberately empty for now — the column
    -- exists so adding policy is a value change, not a migration against a
    -- table with live foreign keys.
    config      JSONB NOT NULL DEFAULT '{}'::jsonb,
    status      STATUS NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, slug),
    -- Target for the composite foreign keys below. Without this, identities
    -- could carry a tenant_id that disagrees with their pool's tenant_id, and a
    -- tenant-scoped query would return another tenant's identity.
    UNIQUE (id, tenant_id)
);

CREATE INDEX idx_pools_tenant ON pools (tenant_id);

-- Exactly one staff pool per tenant: it is the pool the console binds to, so
-- "which one is it" must never be ambiguous.
CREATE UNIQUE INDEX idx_pools_one_staff_per_tenant
    ON pools (tenant_id) WHERE kind = 'staff';

CREATE TRIGGER update_pools_updated_at BEFORE UPDATE ON pools
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Every identity that exists today predates end users, so all of them are staff.
INSERT INTO pools (tenant_id, slug, name, kind, description)
SELECT id, 'staff', 'Staff', 'staff', 'Administrative and console identities'
FROM tenants;

ALTER TABLE identities ADD COLUMN pool_id UUID;
UPDATE identities i SET pool_id = p.id
    FROM pools p WHERE p.tenant_id = i.tenant_id AND p.kind = 'staff';
ALTER TABLE identities ALTER COLUMN pool_id SET NOT NULL;
ALTER TABLE identities ADD CONSTRAINT identities_pool_tenant_fk
    FOREIGN KEY (pool_id, tenant_id) REFERENCES pools (id, tenant_id);

ALTER TABLE clients ADD COLUMN pool_id UUID;
UPDATE clients c SET pool_id = p.id
    FROM pools p WHERE p.tenant_id = c.tenant_id AND p.kind = 'staff';
ALTER TABLE clients ALTER COLUMN pool_id SET NOT NULL;
ALTER TABLE clients ADD CONSTRAINT clients_pool_tenant_fk
    FOREIGN KEY (pool_id, tenant_id) REFERENCES pools (id, tenant_id);

CREATE INDEX idx_identities_pool_id ON identities (pool_id);
CREATE INDEX idx_clients_pool_id ON clients (pool_id);

-- Uniqueness moves from tenant scope to pool scope, so alice@acme.com can be
-- both a staff identity and an unrelated end user of the same tenant.
--
-- Built before the old indexes are dropped: with exactly one pool per tenant at
-- this point the two are equivalent over the current rows, so this cannot fail.
CREATE UNIQUE INDEX idx_identities_username_pool_unique
    ON identities (pool_id, LOWER(username));
CREATE UNIQUE INDEX idx_identities_email_pool_unique
    ON identities (pool_id, LOWER(email)) WHERE email IS NOT NULL;

DROP INDEX idx_identities_username_tenant_unique;
DROP INDEX idx_identities_email_tenant_unique;
