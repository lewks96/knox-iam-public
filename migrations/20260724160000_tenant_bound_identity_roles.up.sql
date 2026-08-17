-- Make tenant ownership structural for role assignments.
--
-- Before this migration, identity_roles held two independent foreign keys. A
-- role from tenant A could therefore be attached to an identity from tenant B,
-- and the global permission query would grant that role's permission strings.

-- Remove any rows that already violate the invariant before constraining it.
-- Such rows could never be legitimate: roles are tenant-local by definition.
DELETE FROM identity_roles ir
USING identities i, roles r
WHERE ir.identity_id = i.id
  AND ir.role_id = r.id
  AND i.tenant_id <> r.tenant_id;

ALTER TABLE identities
    ADD CONSTRAINT identities_id_tenant_unique UNIQUE (id, tenant_id);
ALTER TABLE roles
    ADD CONSTRAINT roles_id_tenant_unique UNIQUE (id, tenant_id);

ALTER TABLE identity_roles ADD COLUMN tenant_id UUID;
UPDATE identity_roles ir
SET tenant_id = i.tenant_id
FROM identities i
WHERE ir.identity_id = i.id;
ALTER TABLE identity_roles ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE identity_roles
    DROP CONSTRAINT identity_roles_identity_id_fkey,
    DROP CONSTRAINT identity_roles_role_id_fkey;

ALTER TABLE identity_roles
    ADD CONSTRAINT identity_roles_identity_tenant_fk
        FOREIGN KEY (identity_id, tenant_id)
        REFERENCES identities (id, tenant_id) ON DELETE CASCADE,
    ADD CONSTRAINT identity_roles_role_tenant_fk
        FOREIGN KEY (role_id, tenant_id)
        REFERENCES roles (id, tenant_id) ON DELETE CASCADE;

CREATE INDEX idx_identity_roles_tenant_identity
    ON identity_roles (tenant_id, identity_id);
