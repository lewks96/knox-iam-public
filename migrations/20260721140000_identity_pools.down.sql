-- NOTE: this only succeeds while each tenant has a single pool.
--
-- Once a second pool holds a username or email that collides with one in the
-- staff pool, recreating the tenant-scoped unique indexes below fails and this
-- migration aborts. That is intentional: the alternative is deleting identities
-- to make the index build. Treat the pool migration as one-way in practice.
CREATE UNIQUE INDEX idx_identities_username_tenant_unique
    ON identities (tenant_id, LOWER(username));
CREATE UNIQUE INDEX idx_identities_email_tenant_unique
    ON identities (tenant_id, LOWER(email)) WHERE email IS NOT NULL;

DROP INDEX idx_identities_username_pool_unique;
DROP INDEX idx_identities_email_pool_unique;

DROP INDEX idx_clients_pool_id;
DROP INDEX idx_identities_pool_id;

ALTER TABLE clients DROP CONSTRAINT clients_pool_tenant_fk;
ALTER TABLE clients DROP COLUMN pool_id;
ALTER TABLE identities DROP CONSTRAINT identities_pool_tenant_fk;
ALTER TABLE identities DROP COLUMN pool_id;

DROP TRIGGER IF EXISTS update_pools_updated_at ON pools;
DROP TABLE pools;
DROP TYPE POOL_KIND;
