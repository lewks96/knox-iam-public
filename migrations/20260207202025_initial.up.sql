CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TYPE STATUS AS ENUM ('active', 'disabled', 'inactive', 'suspended', 'pending');
CREATE TYPE IDENTITY_KIND AS ENUM ('human', 'machine', 'service_account');

CREATE TABLE tenants
(
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    description TEXT,
    status      STATUS      NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tenants_status ON tenants (status);
CREATE INDEX idx_tenants_name ON tenants (LOWER(name));
CREATE UNIQUE INDEX idx_tenants_name_unique ON tenants (LOWER(name));

CREATE TABLE identities
(
    id                UUID PRIMARY KEY       DEFAULT gen_random_uuid(),
    tenant_id         UUID          NOT NULL REFERENCES tenants (id),

    kind              IDENTITY_KIND NOT NULL DEFAULT 'human',

    username          TEXT          NOT NULL,
    email             TEXT,

    password_hash     TEXT,

    email_verified    BOOLEAN       NOT NULL DEFAULT FALSE,
    first_name        TEXT,
    last_name         TEXT,
    metadata          JSONB                  DEFAULT '{}'::jsonb,

    custom_attributes JSONB                  DEFAULT '{}'::jsonb,

    status            STATUS        NOT NULL DEFAULT 'inactive',

    created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX idx_identities_tenant_id ON identities (tenant_id);
CREATE INDEX idx_identities_status ON identities (status);

CREATE UNIQUE INDEX idx_identities_username_tenant_unique
    ON identities (tenant_id, LOWER(username));

CREATE UNIQUE INDEX idx_identities_email_tenant_unique
    ON identities (tenant_id, LOWER(email))
    WHERE email IS NOT NULL;

CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE
    ON tenants
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_identities_updated_at
    BEFORE UPDATE
    ON identities
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();