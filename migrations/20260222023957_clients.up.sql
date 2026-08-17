CREATE TABLE clients (
    id UUID PRIMARY KEY, -- Functions as the `client_id` in OAuth flows
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    logo_uri TEXT,
    
    client_type TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
    
    client_secret_hash TEXT, 
    
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',

    grant_types TEXT[] NOT NULL DEFAULT '{"authorization_code"}',
    response_types TEXT[] NOT NULL DEFAULT '{"code"}',
    
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    
    allowed_scopes TEXT[] NOT NULL DEFAULT '{}',

    require_pkce BOOLEAN NOT NULL DEFAULT true, -- Highly recommended to default to true for ALL clients now
    require_auth_time BOOLEAN NOT NULL DEFAULT false, -- Enforces the 'auth_time' claim in OIDC
    
    access_token_ttl INTEGER NOT NULL DEFAULT 3600,       -- 1 Hour
    refresh_token_ttl INTEGER NOT NULL DEFAULT 2592000,   -- 30 Days
    id_token_ttl INTEGER NOT NULL DEFAULT 3600,           -- 1 Hour
    auth_code_ttl INTEGER NOT NULL DEFAULT 600,           -- 10 Minutes

    token_version INTEGER NOT NULL DEFAULT 1,

    jwks_uri TEXT,
    jwks JSONB,

    tls_client_auth_subject_dn TEXT,
    tls_client_auth_san_dns TEXT,
    tls_client_auth_san_uri TEXT,
    tls_client_auth_san_ip TEXT,
    tls_client_auth_san_email TEXT,

    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'disabled')),
    metadata JSONB NOT NULL DEFAULT '{}',
    custom_attributes JSONB NOT NULL DEFAULT '{}',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_clients_tenant_id ON clients(tenant_id);
CREATE INDEX idx_clients_status ON clients(status);
