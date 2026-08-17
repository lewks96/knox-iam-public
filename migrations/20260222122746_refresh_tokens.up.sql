CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    
    -- SECURITY: Hashed token string
    token_hash TEXT NOT NULL UNIQUE, 
    
    -- The specific scopes approved by the user
    scopes TEXT[] NOT NULL DEFAULT '{}',
    
    -- Lifecycle
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ, 
    
    -- Token Rotation Family (Mandatory for security)
    -- When a refresh token is used, we issue a new one with the SAME family_id.
    -- If a token is reused, we revoke ALL tokens with this family_id.
    family_id UUID NOT NULL,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_tenant_client ON refresh_tokens(tenant_id, client_id);
CREATE INDEX idx_refresh_tokens_identity ON refresh_tokens(identity_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
