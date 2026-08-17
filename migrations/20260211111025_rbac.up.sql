CREATE TYPE role_kind AS ENUM ('custom', 'system');

CREATE TABLE roles
(
    id          UUID PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT,
    kind        role_kind   NOT NULL DEFAULT 'custom',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE permissions
(
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    key         TEXT        NOT NULL UNIQUE, -- e.g., "users:read", "billing:update"
    description TEXT,
    kind        role_kind   NOT NULL DEFAULT 'custom',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions
(
    role_id       UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE identity_roles
(
    identity_id UUID        NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    role_id     UUID        NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (identity_id, role_id)
);

CREATE INDEX idx_roles_tenant ON roles (tenant_id);
CREATE INDEX idx_identity_roles_identity ON identity_roles (identity_id);

INSERT INTO permissions (kind, key, description)
VALUES ('system', 'IdentityCreate', 'Can create new identities'),
       ('system', 'IdentityRead', 'Can read identity information'),
       ('system', 'IdentityUpdate', 'Can update identity information'),
       ('system', 'IdentityDelete', 'Can delete an identity'),

       ('system', 'RoleCreate', 'Can create new roles'),
       ('system', 'RoleRead', 'Can read role information'),
       ('system', 'RoleUpdate', 'Can update role information'),
       ('system', 'RoleDelete', 'Can delete roles'),

       ('system', 'PermissionRead', 'Can read permissions'),

       ('system', 'TenantCreate', 'Can create new tenants'),
       ('system', 'TenantRead', 'Can read tenant information'),
       ('system', 'TenantUpdate', 'Can update tenant information'),
       ('system', 'TenantDelete', 'Can delete a tenant')
ON CONFLICT (key) DO NOTHING;
