ALTER TABLE clients DROP CONSTRAINT clients_pool_tenant_fk;
ALTER TABLE clients ADD CONSTRAINT clients_pool_tenant_fk
    FOREIGN KEY (pool_id, tenant_id) REFERENCES pools (id, tenant_id);

ALTER TABLE identities DROP CONSTRAINT identities_pool_tenant_fk;
ALTER TABLE identities ADD CONSTRAINT identities_pool_tenant_fk
    FOREIGN KEY (pool_id, tenant_id) REFERENCES pools (id, tenant_id);

ALTER TABLE identities DROP CONSTRAINT identities_tenant_id_fkey;
ALTER TABLE identities ADD CONSTRAINT identities_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);
