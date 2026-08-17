use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::key::{CreateKeyParams, KeyState, TenantKey};
use sqlx::PgPool;
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct DbTenantKey {
    id: Uuid,
    tenant_id: Uuid,
    kid: String,
    use_type: String,
    kty: String,
    alg: String,
    public_key_pem: String,
    x509_cert_pem: Option<String>,
    encrypted_private_key: Vec<u8>,
    state: KeyState,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl From<DbTenantKey> for TenantKey {
    fn from(db: DbTenantKey) -> Self {
        TenantKey {
            id: db.id,
            tenant_id: db.tenant_id,
            kid: db.kid,
            use_type: db.use_type,
            kty: db.kty,
            alg: db.alg,
            public_key_pem: db.public_key_pem,
            x509_cert_pem: db.x509_cert_pem,
            encrypted_private_key: db.encrypted_private_key,
            state: db.state,
            created_at: db.created_at,
            expires_at: db.expires_at,
        }
    }
}

#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn create(&self, params: CreateKeyParams) -> Result<TenantKey, RepositoryError>;
    async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
    async fn get_by_kid(
        &self,
        tenant_id: Uuid,
        kid: &str,
    ) -> Result<Option<TenantKey>, RepositoryError>;
    async fn get_active_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantKey>, RepositoryError>;
    async fn list_for_jwks(&self, tenant_id: Uuid) -> Result<Vec<TenantKey>, RepositoryError>;
    async fn list(
        &self,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<TenantKey>, u64), RepositoryError>;
    async fn update_state(
        &self,
        id: Uuid,
        new_state: KeyState,
    ) -> Result<TenantKey, RepositoryError>;
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
    async fn revoke_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
}

#[derive(Clone)]
pub struct PgKeyStore {
    pool: PgPool,
}

impl PgKeyStore {
    #[instrument(skip(pool))]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KeyStore for PgKeyStore {
    #[instrument(skip(self, params))]
    async fn create(&self, params: CreateKeyParams) -> Result<TenantKey, RepositoryError> {
        let rec = sqlx::query_as!(
            DbTenantKey,
            r#"
            INSERT INTO tenant_keys (
                tenant_id, kid, use_type, kty, alg,
                public_key_pem, x509_cert_pem, encrypted_private_key,
                state, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9)
            RETURNING
                id, tenant_id, kid, use_type, kty, alg,
                public_key_pem, x509_cert_pem, encrypted_private_key,
                state as "state: KeyState",
                created_at, expires_at
            "#,
            params.tenant_id,
            params.kid,
            params.use_type,
            params.kty,
            params.alg,
            params.public_key_pem,
            params.x509_cert_pem,
            params.encrypted_private_key,
            params.expires_at
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("tenant_keys_tenant_id_kid_key") {
                    return RepositoryError::Duplicate(format!(
                        "Key with kid '{}' already exists for tenant",
                        params.kid
                    ));
                }
            }
            RepositoryError::Database(e.to_string())
        })?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbTenantKey,
            r#"
            SELECT
                id, tenant_id, kid, use_type, kty, alg,
                public_key_pem, x509_cert_pem, encrypted_private_key,
                state as "state: KeyState",
                created_at, expires_at
            FROM tenant_keys
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn get_by_kid(
        &self,
        tenant_id: Uuid,
        kid: &str,
    ) -> Result<Option<TenantKey>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbTenantKey,
            r#"
            SELECT
                id, tenant_id, kid, use_type, kty, alg,
                public_key_pem, x509_cert_pem, encrypted_private_key,
                state as "state: KeyState",
                created_at, expires_at
            FROM tenant_keys
            WHERE kid = $1 AND tenant_id = $2
            "#,
            kid,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        //let key = rec.map(|r| r.into());
        //if key.is_some() {
        //    error!("Found key by kid: tenant={}, kid={}", tenant_id, kid);
        //} else {
        //    error!("No key found by kid: tenant={}, kid={}", tenant_id, kid);
        //}
        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn get_active_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantKey>, RepositoryError> {
        // Uses the `idx_tenant_keys_active` partial index for optimal performance.
        // Returns the most recently created active key (for graceful rotation).
        let rec = sqlx::query_as!(
            DbTenantKey,
            r#"
            SELECT
                id, tenant_id, kid, use_type, kty, alg,
                public_key_pem, x509_cert_pem, encrypted_private_key,
                state as "state: KeyState",
                created_at, expires_at
            FROM tenant_keys
            WHERE tenant_id = $1 AND state = 'active'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            tenant_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn list_for_jwks(&self, tenant_id: Uuid) -> Result<Vec<TenantKey>, RepositoryError> {
        // Uses the `idx_tenant_keys_jwks` partial index.
        // Returns both 'active' and 'expired' keys (never 'revoked') for token verification.
        let recs = sqlx::query_as!(
            DbTenantKey,
            r#"
            SELECT
                id, tenant_id, kid, use_type, kty, alg,
                public_key_pem, x509_cert_pem, encrypted_private_key,
                state as "state: KeyState",
                created_at, expires_at
            FROM tenant_keys
            WHERE tenant_id = $1 AND state != 'revoked'
            ORDER BY created_at DESC
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(recs.into_iter().map(|r| r.into()).collect())
    }

    #[instrument(skip(self))]
    async fn list(
        &self,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<TenantKey>, u64), RepositoryError> {
        let limit = page_size as i64;
        let offset = ((page - 1) * page_size) as i64;

        let keys = sqlx::query_as!(
            DbTenantKey,
            r#"
            SELECT
                id, tenant_id, kid, use_type, kty, alg,
                public_key_pem, x509_cert_pem, encrypted_private_key,
                state as "state: KeyState",
                created_at, expires_at
            FROM tenant_keys
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            tenant_id,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?
        .into_iter()
        .map(|r| r.into())
        .collect();

        let count = sqlx::query!(
            "SELECT COUNT(*) as count FROM tenant_keys WHERE tenant_id = $1",
            tenant_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?
        .count
        .unwrap_or(0);

        Ok((keys, count as u64))
    }

    #[instrument(skip(self))]
    async fn update_state(
        &self,
        id: Uuid,
        new_state: KeyState,
    ) -> Result<TenantKey, RepositoryError> {
        let rec = sqlx::query_as!(
            DbTenantKey,
            r#"
            UPDATE tenant_keys
            SET state = $2
            WHERE id = $1
            RETURNING
                id, tenant_id, kid, use_type, kty, alg,
                public_key_pem, x509_cert_pem, encrypted_private_key,
                state as "state: KeyState",
                created_at, expires_at
            "#,
            id,
            new_state as KeyState
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?
        .ok_or(RepositoryError::NotFound)?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError> {
        let res = sqlx::query!("DELETE FROM tenant_keys WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| RepositoryError::Database(e.to_string()))?;

        if res.rows_affected() == 0 {
            return Err(RepositoryError::NotFound);
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn revoke_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError> {
        sqlx::query!(
            "UPDATE tenant_keys SET state = 'revoked' WHERE tenant_id = $1 AND state != 'revoked'",
            tenant_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| RepositoryError::Database(e.to_string()))?;

        Ok(())
    }
}
