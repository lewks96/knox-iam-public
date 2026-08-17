DROP INDEX IF EXISTS idx_identity_roles_tenant_identity;

ALTER TABLE identity_roles
    DROP CONSTRAINT identity_roles_identity_tenant_fk,
    DROP CONSTRAINT identity_roles_role_tenant_fk;

ALTER TABLE identity_roles
    ADD CONSTRAINT identity_roles_identity_id_fkey
        FOREIGN KEY (identity_id) REFERENCES identities (id) ON DELETE CASCADE,
    ADD CONSTRAINT identity_roles_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE;

ALTER TABLE identity_roles DROP COLUMN tenant_id;
ALTER TABLE identities DROP CONSTRAINT identities_id_tenant_unique;
ALTER TABLE roles DROP CONSTRAINT roles_id_tenant_unique;
