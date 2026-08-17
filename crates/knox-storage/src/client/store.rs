use async_trait::async_trait;
use knox_common::client::{Client, ClientFilter, ClientType, ClientUpdates};
use knox_common::error::RepositoryError;
use knox_common::identity::Status;
use sqlx::{PgPool, QueryBuilder};
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

// Internal DB Struct matching Postgres rows exactly
#[derive(sqlx::FromRow)]
struct DbClient {
    id: Uuid,
    tenant_id: Uuid,
    pool_id: Uuid,
    name: String,
    description: Option<String>,
    logo_uri: Option<String>,
    client_type: String,
    client_secret_hash: Option<String>,
    token_endpoint_auth_method: String,
    allow_refresh_tokens: bool,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    require_pkce: bool,
    require_auth_time: bool,
    access_token_ttl: i32,
    refresh_token_ttl: i32,
    id_token_ttl: i32,
    auth_code_ttl: i32,
    token_version: i32,
    jwks_uri: Option<String>,
    jwks: Option<serde_json::Value>,
    tls_client_auth_subject_dn: Option<String>,
    tls_client_auth_san_dns: Option<String>,
    tls_client_auth_san_uri: Option<String>,
    tls_client_auth_san_ip: Option<String>,
    tls_client_auth_san_email: Option<String>,
    status: String,
    metadata: serde_json::Value,
    custom_attributes: serde_json::Value,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl From<DbClient> for Client {
    fn from(db: DbClient) -> Self {
        Client {
            id: db.id,
            tenant_id: db.tenant_id,
            pool_id: db.pool_id,
            name: db.name,
            description: db.description,
            logo_uri: db.logo_uri,
            client_type: match db.client_type.as_str() {
                "confidential" => ClientType::Confidential,
                _ => ClientType::Public,
            },
            client_secret_hash: db.client_secret_hash,
            token_endpoint_auth_method: db.token_endpoint_auth_method,
            allow_refresh_tokens: db.allow_refresh_tokens,
            grant_types: db.grant_types,
            response_types: db.response_types,
            redirect_uris: db.redirect_uris,
            post_logout_redirect_uris: db.post_logout_redirect_uris,
            allowed_scopes: db.allowed_scopes,
            require_pkce: db.require_pkce,
            require_auth_time: db.require_auth_time,
            access_token_ttl: db.access_token_ttl,
            refresh_token_ttl: db.refresh_token_ttl,
            id_token_ttl: db.id_token_ttl,
            auth_code_ttl: db.auth_code_ttl,
            token_version: db.token_version,
            jwks_uri: db.jwks_uri,
            jwks: db.jwks,
            tls_client_auth_subject_dn: db.tls_client_auth_subject_dn,
            tls_client_auth_san_dns: db.tls_client_auth_san_dns,
            tls_client_auth_san_uri: db.tls_client_auth_san_uri,
            tls_client_auth_san_ip: db.tls_client_auth_san_ip,
            tls_client_auth_san_email: db.tls_client_auth_san_email,
            status: match db.status.as_str() {
                "suspended" => Status::Suspended,
                "disabled" => Status::Disabled,
                _ => Status::Active,
            },
            metadata: db.metadata,
            custom_attributes: db.custom_attributes,
            created_at: db.created_at,
            updated_at: db.updated_at,
        }
    }
}

#[async_trait]
pub trait ClientStore: Send + Sync {
    async fn create(&self, client: &Client) -> Result<Client, RepositoryError>;
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError>;
    async fn get_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Client>, RepositoryError>;
    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        updates: &ClientUpdates,
    ) -> Result<Client, RepositoryError>;
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
    async fn list(&self, filter: &ClientFilter) -> Result<(Vec<Client>, u64), RepositoryError>;
}

#[derive(Clone)]
pub struct PgClientStore {
    pool: PgPool,
}

impl PgClientStore {
    #[instrument(skip(pool))]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ClientStore for PgClientStore {
    #[instrument(skip(self, client))]
    async fn create(&self, client: &Client) -> Result<Client, RepositoryError> {
        let client_type_str = match client.client_type {
            ClientType::Public => "public",
            ClientType::Confidential => "confidential",
        };
        let status_str = match client.status {
            Status::Active => "active",
            Status::Inactive => "inactive",
            Status::Pending => "pending",
            Status::Disabled => "disabled",
            Status::Suspended => "suspended",
        };

        let rec = sqlx::query_as!(
            DbClient,
            r#"
            INSERT INTO clients (
                id, tenant_id, pool_id, name, description, logo_uri, client_type, client_secret_hash,
                token_endpoint_auth_method, grant_types, response_types, redirect_uris,
                post_logout_redirect_uris, allowed_scopes, require_pkce, require_auth_time,
                access_token_ttl, refresh_token_ttl, id_token_ttl, auth_code_ttl, token_version,
                jwks_uri, jwks, tls_client_auth_subject_dn, tls_client_auth_san_dns,
                tls_client_auth_san_uri, tls_client_auth_san_ip, tls_client_auth_san_email,
                status, metadata, custom_attributes, allow_refresh_tokens
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32
            )
            RETURNING *
            "#,
            client.id, client.tenant_id, client.pool_id, client.name, client.description, client.logo_uri,
            client_type_str, client.client_secret_hash, client.token_endpoint_auth_method,
            &client.grant_types, &client.response_types, &client.redirect_uris,
            &client.post_logout_redirect_uris, &client.allowed_scopes, client.require_pkce,
            client.require_auth_time, client.access_token_ttl, client.refresh_token_ttl,
            client.id_token_ttl, client.auth_code_ttl, client.token_version, client.jwks_uri,
            client.jwks, client.tls_client_auth_subject_dn, client.tls_client_auth_san_dns,
            client.tls_client_auth_san_uri, client.tls_client_auth_san_ip, client.tls_client_auth_san_email,
            status_str, client.metadata, client.custom_attributes, client.allow_refresh_tokens,
        )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbClient,
            "SELECT * FROM clients WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn get_by_name(
        &self,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Client>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbClient,
            "SELECT * FROM clients WHERE tenant_id = $1 AND name = $2",
            tenant_id,
            name
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self, updates))]
    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        updates: &ClientUpdates,
    ) -> Result<Client, RepositoryError> {
        let mut builder = QueryBuilder::new("UPDATE clients SET ");
        let mut separated = builder.separated(", ");

        if let Some(desc) = &updates.description {
            separated.push("description = ").push_bind_unseparated(desc);
        }
        if let Some(logo_uri) = &updates.logo_uri {
            separated
                .push("logo_uri = ")
                .push_bind_unseparated(logo_uri);
        }
        if let Some(client_secret_hash) = &updates.client_secret_hash {
            separated
                .push("client_secret_hash = ")
                .push_bind_unseparated(client_secret_hash);
        }
        if let Some(token_endpoint_auth_method) = &updates.token_endpoint_auth_method {
            separated
                .push("token_endpoint_auth_method = ")
                .push_bind_unseparated(token_endpoint_auth_method);
        }
        if let Some(allow_refresh_tokens) = updates.allow_refresh_tokens {
            separated
                .push("allow_refresh_tokens = ")
                .push_bind_unseparated(allow_refresh_tokens);
        }
        if let Some(grant_types) = &updates.grant_types {
            separated
                .push("grant_types = ")
                .push_bind_unseparated(grant_types);
        }
        if let Some(response_types) = &updates.response_types {
            separated
                .push("response_types = ")
                .push_bind_unseparated(response_types);
        }
        if let Some(redirect_uris) = &updates.redirect_uris {
            separated
                .push("redirect_uris = ")
                .push_bind_unseparated(redirect_uris);
        }
        if let Some(post_logout_redirect_uris) = &updates.post_logout_redirect_uris {
            separated
                .push("post_logout_redirect_uris = ")
                .push_bind_unseparated(post_logout_redirect_uris);
        }
        if let Some(allowed_scopes) = &updates.allowed_scopes {
            separated
                .push("allowed_scopes = ")
                .push_bind_unseparated(allowed_scopes);
        }
        if let Some(require_pkce) = updates.require_pkce {
            separated
                .push("require_pkce = ")
                .push_bind_unseparated(require_pkce);
        }
        if let Some(require_auth_time) = updates.require_auth_time {
            separated
                .push("require_auth_time = ")
                .push_bind_unseparated(require_auth_time);
        }
        if let Some(access_token_ttl) = updates.access_token_ttl {
            separated
                .push("access_token_ttl = ")
                .push_bind_unseparated(access_token_ttl);
        }
        if let Some(refresh_token_ttl) = updates.refresh_token_ttl {
            separated
                .push("refresh_token_ttl = ")
                .push_bind_unseparated(refresh_token_ttl);
        }
        if let Some(id_token_ttl) = updates.id_token_ttl {
            separated
                .push("id_token_ttl = ")
                .push_bind_unseparated(id_token_ttl);
        }
        if let Some(auth_code_ttl) = updates.auth_code_ttl {
            separated
                .push("auth_code_ttl = ")
                .push_bind_unseparated(auth_code_ttl);
        }
        if let Some(token_version) = updates.token_version {
            separated
                .push("token_version = ")
                .push_bind_unseparated(token_version);
        }
        if let Some(metadata) = &updates.metadata {
            separated
                .push("metadata = ")
                .push_bind_unseparated(metadata);
        }
        if let Some(custom_attributes) = &updates.custom_attributes {
            separated
                .push("custom_attributes = ")
                .push_bind_unseparated(custom_attributes);
        }
        if let Some(status) = updates.status {
            let status_str = match status {
                Status::Active => "active",
                Status::Suspended => "suspended",
                Status::Disabled => "disabled",
                Status::Pending => "pending",
                Status::Inactive => "inactive",
            };
            separated
                .push("status = ")
                .push_bind_unseparated(status_str);
        }

        separated.push("updated_at = now()");

        builder.push(" WHERE id = ").push_bind(id);
        builder.push(" AND tenant_id = ").push_bind(tenant_id);
        builder.push(" RETURNING *");

        let rec = builder
            .build_query_as::<DbClient>()
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError> {
        let res = sqlx::query!(
            "DELETE FROM clients WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        if res.rows_affected() == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list(&self, filter: &ClientFilter) -> Result<(Vec<Client>, u64), RepositoryError> {
        let limit = filter.page_size as i64;
        let offset = ((filter.page - 1) * filter.page_size) as i64;

        let clients = sqlx::query_as!(
            DbClient,
            "SELECT * FROM clients WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            filter.tenant_id,
            limit,
            offset
        )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?
            .into_iter()
            .map(|c| c.into())
            .collect();

        let total = sqlx::query!(
            "SELECT COUNT(*) as count FROM clients WHERE tenant_id = $1",
            filter.tenant_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?
        .count
        .unwrap_or(0);

        Ok((clients, total as u64))
    }
}
