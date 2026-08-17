-- Make deleting a tenant actually possible.
--
-- Every table owned by a tenant already cascaded — clients, roles, keys, audit
-- events, refresh tokens, MFA — except `identities`, whose FK was NO ACTION. So
-- `DELETE FROM tenants` failed on any tenant that had ever had a user, which is
-- every real one. `TenantService::delete_tenant` existed but had no route and no
-- caller; this is why.
ALTER TABLE identities DROP CONSTRAINT identities_tenant_id_fkey;
ALTER TABLE identities ADD CONSTRAINT identities_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE;

-- The composite keys added with pools were NO ACTION too, so once `pools`
-- cascaded away the rows pointing at them would block the delete. There are now
-- two cascade paths to `identities` (via tenant and via pool); Postgres is fine
-- with that, and both agree the row should go.
ALTER TABLE identities DROP CONSTRAINT identities_pool_tenant_fk;
ALTER TABLE identities ADD CONSTRAINT identities_pool_tenant_fk
    FOREIGN KEY (pool_id, tenant_id) REFERENCES pools (id, tenant_id) ON DELETE CASCADE;

ALTER TABLE clients DROP CONSTRAINT clients_pool_tenant_fk;
ALTER TABLE clients ADD CONSTRAINT clients_pool_tenant_fk
    FOREIGN KEY (pool_id, tenant_id) REFERENCES pools (id, tenant_id) ON DELETE CASCADE;
