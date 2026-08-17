CREATE TYPE MFA_METHOD AS ENUM ('totp', 'webauthn', 'sms');

CREATE TABLE mfa_methods
(
    id             UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id      UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    identity_id    UUID        NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    method         MFA_METHOD  NOT NULL,

    -- AES-256-GCM blob (KeyEncryptionProvider versioned format).
    -- TOTP: base32 secret. SMS (later): phone number. WebAuthn (later): NULL.
    secret_enc     BYTEA,

    -- Non-secret method parameters.
    -- TOTP: {"algorithm":"SHA1","digits":6,"step":30}
    -- WebAuthn (later): {"credential_id":...,"public_key_cose":...,"sign_count":0}
    -- SMS (later): {"phone_masked":"+44*******12"}
    public_data    JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- TOTP replay guard: highest time-step already accepted (RFC 6238 §5.2).
    last_used_step BIGINT,

    verified_at    TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_mfa_methods_identity ON mfa_methods (tenant_id, identity_id);

-- Singleton per identity for totp/sms; multiple rows allowed for webauthn.
CREATE UNIQUE INDEX idx_mfa_methods_one_totp ON mfa_methods (tenant_id, identity_id) WHERE method = 'totp';
CREATE UNIQUE INDEX idx_mfa_methods_one_sms ON mfa_methods (tenant_id, identity_id) WHERE method = 'sms';

-- Login hot path: verified methods for an identity.
CREATE INDEX idx_mfa_methods_verified ON mfa_methods (tenant_id, identity_id) WHERE verified_at IS NOT NULL;

CREATE TRIGGER update_mfa_methods_updated_at
    BEFORE UPDATE
    ON mfa_methods
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Single-use recovery codes. High-entropy random codes, stored as SHA-256 hex
-- (same rationale as refresh token hashing - no KDF needed).
CREATE TABLE mfa_backup_codes
(
    id          UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    identity_id UUID        NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    code_hash   TEXT        NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, identity_id, code_hash)
);

CREATE INDEX idx_mfa_backup_codes_unused ON mfa_backup_codes (tenant_id, identity_id) WHERE used_at IS NULL;
