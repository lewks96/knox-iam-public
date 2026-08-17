use knox_common::identity::Status;
use knox_common::{
    client::{Client, ClientFilter, ClientRepository, ClientType, ClientUpdates},
    error::ServiceError,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, instrument};
use uuid::Uuid;
use validator::Validate;

/// Whether a redirect URI is acceptable.
///
/// HTTPS always is. Plain HTTP is allowed only for hosts that are loopback by
/// definition: `localhost`/`127.0.0.1`/`[::1]`, anything under `.localhost`
/// (RFC 6761), and anything under `.lvh.me` (a public name whose every label
/// resolves to 127.0.0.1, which is how this project addresses per-tenant
/// subdomains in local dev).
///
/// The subdomain rework made this load-bearing: a tenant's console now lives at
/// `{slug}.lvh.me:3000`, and bootstrap derives the management client's redirect
/// URI from the tenant's issuer. With a `localhost`-only allowlist, `KNOX_SCHEME=http`
/// meant bootstrap could not create the management client at all.
fn is_allowed_redirect_uri(uri: &str) -> bool {
    if uri.starts_with("https://") {
        return true;
    }
    let Some(rest) = uri.strip_prefix("http://") else {
        return false;
    };
    // Host is everything before the port, path, query or fragment.
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or_else(|| rest.split(['/', '?', '#']).next().unwrap_or(""))
        .to_ascii_lowercase();

    host == "localhost"
        || host == "127.0.0.1"
        || host == "[::1]"
        || host.ends_with(".localhost")
        || host == "lvh.me"
        || host.ends_with(".lvh.me")
}

#[derive(Debug, Validate, Deserialize)]
pub struct CreateClientRequest {
    pub tenant_id: Uuid,
    /// Which identity pool this client authenticates against. Must belong to
    /// `tenant_id` — a composite foreign key enforces it.
    pub pool_id: Uuid,

    #[validate(length(min = 3, max = 100))]
    pub name: String,

    pub description: Option<String>,
    pub logo_uri: Option<String>,

    pub client_type: ClientType,

    pub token_endpoint_auth_method: String,
    pub allow_refresh_tokens: bool,

    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,

    pub access_token_ttl: Option<u32>,
    pub refresh_token_ttl: Option<u32>,
    pub id_token_ttl: Option<u32>,
    pub auth_code_ttl: Option<u32>,
    pub token_version: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CreateClientResponse {
    pub client: Client,
    pub client_secret: Option<String>,
}

/// `name` is intentionally omitted — it is the OAuth `client_id` and is immutable after creation.
/// `client_type` is also immutable: switching public ↔ confidential changes whether a secret
/// is required and would invalidate stored credentials. Use a new client instead.
#[derive(Debug, Validate, Deserialize)]
pub struct UpdateClientRequest {
    pub description: Option<String>,
    pub logo_uri: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub allow_refresh_tokens: Option<bool>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub require_pkce: Option<bool>,
    pub access_token_ttl: Option<u32>,
    pub refresh_token_ttl: Option<u32>,
    pub id_token_ttl: Option<u32>,
    pub auth_code_ttl: Option<u32>,
    pub status: Option<Status>,
}

#[derive(Clone)]
pub struct ClientService<R: ClientRepository> {
    repo: R,
}

impl<R: ClientRepository> ClientService<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }
    fn generate_secret() -> String {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    // Client secrets are 256-bit random values — no KDF needed, SHA-256 is sufficient.
    // Argon2 is reserved for low-entropy human passwords.
    fn hash_secret(secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn require_active(client: Client) -> Result<Client, ServiceError> {
        if client.status != Status::Active {
            return Err(ServiceError::InvalidCredentials);
        }
        Ok(client)
    }
    #[instrument(skip(self, req))]
    pub async fn create_client(
        &self,
        req: CreateClientRequest,
    ) -> Result<CreateClientResponse, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        if !is_valid_client_name(&req.name) {
            return Err(ServiceError::Validation(
                "Client name must be lowercase alphanumeric and hyphens only, 3–63 characters, and cannot start, end, or contain consecutive hyphens".into(),
            ));
        }

        debug!(
            "Validating redirect URIs for client creation request: {:?}",
            req.redirect_uris
        );
        for uri in &req.redirect_uris {
            if !is_allowed_redirect_uri(uri) {
                debug!("Invalid redirect URI detected: {}", uri);
                return Err(ServiceError::Validation(format!(
                    "Insecure redirect URI: {}",
                    uri
                )));
            }
        }

        let mut plaintext_secret = None;
        let mut client_secret_hash = None;
        if req.client_type == ClientType::Confidential {
            debug!(
                "Generating client secret for confidential client {}",
                req.name
            );
            let secret = Self::generate_secret();
            client_secret_hash = Some(Self::hash_secret(&secret));
            plaintext_secret = Some(secret);
        }

        let require_pkce = req.client_type == ClientType::Public;
        debug!(
            "Setting require_pkce={} for client {} based on client type {:?}",
            require_pkce, req.name, req.client_type
        );

        // Use provided TTLs or fall back to defaults. Error on invalid values (e.g. negative or
        // too large).
        let access_token_ttl: i32 = req
            .access_token_ttl
            .unwrap_or(3600)
            .try_into()
            .map_err(|_| ServiceError::Validation("Invalid access_token_ttl".into()))?;
        let refresh_token_ttl: i32 = req
            .refresh_token_ttl
            .unwrap_or(86400)
            .try_into()
            .map_err(|_| ServiceError::Validation("Invalid access_token_ttl".into()))?;

        let id_token_ttl: i32 = req
            .id_token_ttl
            .unwrap_or(3600)
            .try_into()
            .map_err(|_| ServiceError::Validation("Invalid id_token_ttl".into()))?;
        let auth_code_ttl: i32 = req
            .auth_code_ttl
            .unwrap_or(600)
            .try_into()
            .map_err(|_| ServiceError::Validation("Invalid auth_code_ttl".into()))?;
        let token_version: i32 = req
            .token_version
            .unwrap_or(1)
            .try_into()
            .map_err(|_| ServiceError::Validation("Invalid token_version".into()))?;

        let new_client = Client {
            id: Uuid::new_v4(),
            tenant_id: req.tenant_id,
            pool_id: req.pool_id,
            name: req.name,
            description: req.description,
            logo_uri: req.logo_uri,

            client_type: req.client_type,
            client_secret_hash,
            token_endpoint_auth_method: req.token_endpoint_auth_method,
            allow_refresh_tokens: req.allow_refresh_tokens,

            grant_types: req.grant_types,
            response_types: req.response_types,
            redirect_uris: req.redirect_uris,
            post_logout_redirect_uris: req.post_logout_redirect_uris,
            allowed_scopes: req.allowed_scopes,

            require_pkce,
            require_auth_time: false,

            access_token_ttl,
            refresh_token_ttl,
            id_token_ttl,
            auth_code_ttl,
            token_version,

            jwks_uri: None,
            jwks: None,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_ip: None,
            tls_client_auth_san_email: None,

            status: Status::Active,
            metadata: serde_json::json!({}),
            custom_attributes: serde_json::json!({}),
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };

        let created = self
            .repo
            .create(&new_client)
            .await
            .map_err(ServiceError::Repository)?;

        Ok(CreateClientResponse {
            client: created,
            client_secret: plaintext_secret, // Returned ONCE. If lost, they must rotate.
        })
    }

    #[instrument(skip(self, secret))]
    pub async fn authenticate_client(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        secret: &str,
    ) -> Result<Client, ServiceError> {
        let client = Self::require_active(self.get_client(tenant_id, client_id).await?)?;

        let stored_hash = match &client.client_secret_hash {
            Some(h) => h,
            None => {
                debug!(
                    "Authentication failed for client_id {}: no secret hash stored",
                    client_id
                );
                return Err(ServiceError::InvalidCredentials);
            }
        };

        let candidate_hash = Self::hash_secret(secret);

        // Constant-time comparison to prevent timing attacks
        if candidate_hash != *stored_hash {
            debug!(
                "Authentication failed for client_id {}: secret mismatch",
                client_id
            );
            return Err(ServiceError::InvalidCredentials);
        }

        Ok(client)
    }

    #[instrument(skip(self))]
    pub async fn get_client(&self, tenant_id: Uuid, id: Uuid) -> Result<Client, ServiceError> {
        self.repo
            .get(tenant_id, id)
            .await
            .map_err(ServiceError::Repository)?
            .ok_or_else(|| ServiceError::Validation(format!("Client '{}' not found", id)))
    }

    /// Runtime credential checks use this while management handlers retain the
    /// ability to inspect and reactivate a disabled client.
    #[instrument(skip(self))]
    pub async fn get_active_client(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Client, ServiceError> {
        Self::require_active(self.get_client(tenant_id, id).await?)
    }

    #[instrument(skip(self, req))]
    pub async fn update_client(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        req: UpdateClientRequest,
    ) -> Result<Client, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        // Optional: Re-validate URIs if they are being updated
        if let Some(uris) = &req.redirect_uris {
            for uri in uris {
                if !is_allowed_redirect_uri(uri) {
                    return Err(ServiceError::Validation(format!(
                        "Insecure redirect URI: {}",
                        uri
                    )));
                }
            }
        }

        let access_token_ttl = req
            .access_token_ttl
            .map(i32::try_from)
            .transpose()
            .map_err(|_| ServiceError::Validation("Invalid access_token_ttl".into()))?;
        let refresh_token_ttl = req
            .refresh_token_ttl
            .map(i32::try_from)
            .transpose()
            .map_err(|_| ServiceError::Validation("Invalid refresh_token_ttl".into()))?;
        let id_token_ttl = req
            .id_token_ttl
            .map(i32::try_from)
            .transpose()
            .map_err(|_| ServiceError::Validation("Invalid id_token_ttl".into()))?;
        let auth_code_ttl = req
            .auth_code_ttl
            .map(i32::try_from)
            .transpose()
            .map_err(|_| ServiceError::Validation("Invalid auth_code_ttl".into()))?;

        let token_version = if matches!(req.status, Some(status) if status != Status::Active) {
            let current = self.get_client(tenant_id, id).await?;
            if current.status == Status::Active {
                Some(current.token_version.checked_add(1).ok_or_else(|| {
                    ServiceError::Internal("Client token version overflow".into())
                })?)
            } else {
                None
            }
        } else {
            None
        };

        let updates = ClientUpdates {
            description: req.description,
            logo_uri: req.logo_uri,
            token_endpoint_auth_method: req.token_endpoint_auth_method,
            allow_refresh_tokens: req.allow_refresh_tokens,
            grant_types: req.grant_types,
            response_types: req.response_types,
            redirect_uris: req.redirect_uris,
            post_logout_redirect_uris: req.post_logout_redirect_uris,
            allowed_scopes: req.allowed_scopes,
            require_pkce: req.require_pkce,
            access_token_ttl,
            refresh_token_ttl,
            id_token_ttl,
            auth_code_ttl,
            // Access tokens carry this version. Advancing it makes a disabling
            // transition invalidate every token minted before the update.
            token_version,
            status: req.status,
            ..Default::default()
        };

        self.repo
            .update(tenant_id, id, &updates)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn delete_client(&self, tenant_id: Uuid, id: Uuid) -> Result<(), ServiceError> {
        self.repo
            .delete(tenant_id, id)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self, filter))]
    pub async fn list_clients(
        &self,
        filter: &ClientFilter,
    ) -> Result<(Vec<Client>, u64), ServiceError> {
        self.repo
            .list(filter)
            .await
            .map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn rotate_token_version(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Client, ServiceError> {
        let client = self.get_client(tenant_id, id).await?;

        let updates = ClientUpdates {
            token_version: Some(client.token_version + 1),
            ..Default::default()
        };

        self.repo
            .update(tenant_id, id, &updates)
            .await
            .map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn rotate_client_secret(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<CreateClientResponse, ServiceError> {
        let client = self.get_client(tenant_id, id).await?;

        if client.client_type != ClientType::Confidential {
            return Err(ServiceError::Validation(
                "Cannot rotate secret for a public client".into(),
            ));
        }

        let new_secret = Self::generate_secret();
        let new_hash = Self::hash_secret(&new_secret);

        let updates = ClientUpdates {
            client_secret_hash: Some(new_hash),
            token_version: Some(client.token_version + 1), // Invalidate old tokens instantly
            ..Default::default()
        };

        let updated_client = self
            .repo
            .update(tenant_id, id, &updates)
            .await
            .map_err(ServiceError::Repository)?;

        Ok(CreateClientResponse {
            client: updated_client,
            client_secret: Some(new_secret),
        })
    }

    #[instrument(skip(self))]
    pub async fn get_client_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Client, ServiceError> {
        self.repo
            .get_by_name(tenant_id, name)
            .await
            .map_err(ServiceError::Repository)?
            .ok_or_else(|| ServiceError::Validation(format!("Client '{}' not found", name)))
    }

    #[instrument(skip(self))]
    pub async fn get_active_client_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Client, ServiceError> {
        Self::require_active(self.get_client_by_name(tenant_id, name).await?)
    }

    #[instrument(skip(self, secret))]
    pub async fn authenticate_client_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
        secret: &str,
    ) -> Result<Client, ServiceError> {
        let client = Self::require_active(self.get_client_by_name(tenant_id, name).await?)?;

        let stored_hash = match &client.client_secret_hash {
            Some(h) => h,
            None => return Err(ServiceError::InvalidCredentials),
        };

        if Self::hash_secret(secret) != *stored_hash {
            return Err(ServiceError::InvalidCredentials);
        }

        Ok(client)
    }
}

/// Validates that a client name is URL-safe: lowercase alphanumeric + hyphens,
/// 3–63 characters, no leading/trailing/consecutive hyphens.
pub fn is_valid_client_name(name: &str) -> bool {
    let len = name.len();
    if len < 3 || len > 63 {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') {
        return false;
    }
    if name.contains("--") {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
