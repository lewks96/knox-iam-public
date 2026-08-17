--- Create an enum to manage the key lifecycle
CREATE TYPE key_state AS ENUM ('active', 'expired', 'revoked');

CREATE TABLE tenant_keys
(
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Ties the key to a specific tenant. Cascade ensures complete cryptographic wipe on tenant deletion.
    tenant_id             UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    
    -- The Key ID (kid) that gets injected into the JWT header so downstream apps know which key to verify with
    kid                   VARCHAR(255) NOT NULL,
    
    -- Cryptographic metadata (Standard JWK parameters)
    use_type              VARCHAR(10) NOT NULL DEFAULT 'sig',    -- 'sig' (signature) or 'enc' (encryption)
    kty                   VARCHAR(10) NOT NULL DEFAULT 'RSA',    -- Key Type (e.g., RSA, EC)
    alg                   VARCHAR(20) NOT NULL DEFAULT 'RS256',  -- Algorithm (e.g., RS256, ES256)
    
    -- The public key material (Safe to store in plaintext, served via public endpoints)
    public_key_pem        TEXT NOT NULL,                         -- Used for OIDC JWKS (/.well-known/jwks.json)
    x509_cert_pem         TEXT,                                  -- Used for SAML XML Metadata

    -- The private key material (MUST BE ENCRYPTED in memory via the Master KEK before insertion)
    encrypted_private_key BYTEA NOT NULL,                        -- AES-256-GCM encrypted blob
    
    -- Lifecycle management
    state                 key_state NOT NULL DEFAULT 'active',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL,                  -- When this key should automatically rotate out of 'active'
    
    -- A tenant cannot have duplicate key IDs
    UNIQUE (tenant_id, kid)
);

-- Index 1: Optimize for token creation. 
-- The TokenService needs to instantly find the ONE 'active' key to sign a new JWT.
CREATE INDEX idx_tenant_keys_active ON tenant_keys (tenant_id, state) WHERE state = 'active';

-- Index 2: Optimize for token verification (JWKS endpoint).
-- Downstream apps need to see both 'active' and 'expired' keys to verify tokens, but never 'revoked' keys.
CREATE INDEX idx_tenant_keys_jwks ON tenant_keys (tenant_id, state) WHERE state != 'revoked';

