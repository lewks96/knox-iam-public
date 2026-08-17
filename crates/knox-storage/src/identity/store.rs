use crate::identity::{DbIdentity, IdentityStore};
use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::identity::{Identity, IdentityFilter, IdentityKind, IdentityUpdates, Status};
use sqlx::{PgPool, QueryBuilder, Row};
use tracing::instrument;
use uuid::Uuid;

#[derive(Clone)]
pub struct PgIdentityStore {
    write_pool: PgPool,
    read_pool: PgPool,
}

impl PgIdentityStore {
    #[instrument(skip(write_pool, read_pool))]
    pub fn new(write_pool: PgPool, read_pool: PgPool) -> Self {
        Self {
            write_pool,
            read_pool,
        }
    }
}
#[async_trait]
impl IdentityStore for PgIdentityStore {
    #[instrument(skip(self, identity))]
    async fn create(&self, identity: &Identity) -> Result<Identity, RepositoryError> {
        let rec = sqlx::query_as!(
            DbIdentity,
            r#"
            INSERT INTO identities (
                id, tenant_id, pool_id, kind, username, email, password_hash,
                email_verified, first_name, last_name,
                metadata, custom_attributes, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING
                id, tenant_id, pool_id,
                kind as "kind: IdentityKind",
                username, email, password_hash, email_verified,
                first_name, last_name, metadata, custom_attributes,
                status as "status: Status",
                created_at, updated_at
            "#,
            identity.id,
            identity.tenant_id,
            identity.pool_id,
            identity.kind as IdentityKind,
            identity.username,
            identity.email,
            identity.password_hash,
            identity.email_verified,
            identity.first_name,
            identity.last_name,
            identity.metadata,
            identity.custom_attributes,
            identity.status as Status
        )
        .fetch_one(&self.write_pool)
        .await
        .map_err(map_sql_error)?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn get_by_id(
        &self,
        pool_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Identity>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbIdentity,
            r#"
            SELECT
                id, tenant_id, pool_id,
                kind as "kind: IdentityKind",
                username, email, password_hash, email_verified,
                first_name, last_name, metadata, custom_attributes,
                status as "status: Status",
                created_at, updated_at
            FROM identities
            WHERE id = $1 AND pool_id = $2
            "#,
            id,
            pool_id
        )
        .fetch_optional(&self.read_pool)
        .await
        .map_err(map_sql_error)?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn get_by_email(
        &self,
        pool_id: Uuid,
        email: &str,
    ) -> Result<Option<Identity>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbIdentity,
            r#"
            SELECT
                id, tenant_id, pool_id,
                kind as "kind: IdentityKind",
                username, email, password_hash, email_verified,
                first_name, last_name, metadata, custom_attributes,
                status as "status: Status",
                created_at, updated_at
            FROM identities
            WHERE pool_id = $1 AND lower(email) = lower($2)
            "#,
            pool_id,
            email
        )
        .fetch_optional(&self.read_pool)
        .await
        .map_err(map_sql_error)?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn get_by_username(
        &self,
        pool_id: Uuid,
        username: &str,
    ) -> Result<Option<Identity>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbIdentity,
            r#"
            SELECT
                id, tenant_id, pool_id,
                kind as "kind: IdentityKind",
                username, email, password_hash, email_verified,
                first_name, last_name, metadata, custom_attributes,
                status as "status: Status",
                created_at, updated_at
            FROM identities
            WHERE pool_id = $1 AND lower(username) = lower($2)
            "#,
            pool_id,
            username
        )
        .fetch_optional(&self.read_pool)
        .await
        .map_err(map_sql_error)?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        pool_id: Uuid,
        id: Uuid,
        updates: &IdentityUpdates,
    ) -> Result<Identity, RepositoryError> {
        let mut builder = QueryBuilder::new("UPDATE identities SET ");
        let mut separated = builder.separated(", ");

        if let Some(username) = &updates.username {
            separated.push("username = ");
            separated.push_bind_unseparated(username);
        }
        if let Some(email) = &updates.email {
            separated.push("email = ");
            separated.push_bind_unseparated(email);
        }
        if let Some(pwd) = &updates.password_hash {
            separated.push("password_hash = ");
            separated.push_bind_unseparated(pwd);
        }
        if let Some(verified) = updates.email_verified {
            separated.push("email_verified = ");
            separated.push_bind_unseparated(verified);
        }
        if let Some(fname) = &updates.first_name {
            separated.push("first_name = ");
            separated.push_bind_unseparated(fname);
        }
        if let Some(lname) = &updates.last_name {
            separated.push("last_name = ");
            separated.push_bind_unseparated(lname);
        }
        if let Some(meta) = &updates.metadata {
            separated.push("metadata = ");
            separated.push_bind_unseparated(meta);
        }
        if let Some(custom) = &updates.custom_attributes {
            separated.push("custom_attributes = ");
            separated.push_bind_unseparated(custom);
        }
        if let Some(status) = updates.status {
            separated.push("status = ");
            separated.push_bind_unseparated(status as Status);
        }

        separated.push("updated_at = now()");

        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" AND pool_id = ");
        builder.push_bind(pool_id);

        // IMPORTANT: Explicit columns in RETURNING for dynamic builder too
        builder.push(
            r#"
            RETURNING
                id, tenant_id, pool_id,
                kind,
                username, email, password_hash, email_verified,
                first_name, last_name, metadata, custom_attributes,
                status,
                created_at, updated_at
        "#,
        );

        let rec = builder
            .build_query_as::<DbIdentity>()
            .fetch_one(&self.write_pool)
            .await
            .map_err(map_sql_error)?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn delete(&self, pool_id: Uuid, id: Uuid) -> Result<(), RepositoryError> {
        let result = sqlx::query!(
            "DELETE FROM identities WHERE id = $1 AND pool_id = $2",
            id,
            pool_id
        )
        .execute(&self.write_pool)
        .await
        .map_err(map_sql_error)?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn list(&self, filter: &IdentityFilter) -> Result<(Vec<Identity>, u64), RepositoryError> {
        // Use explicit columns here too
        let mut builder = QueryBuilder::new(
            r#"
            SELECT
                id, tenant_id, pool_id,
                kind,
                username, email, password_hash, email_verified,
                first_name, last_name, metadata, custom_attributes,
                status,
                created_at, updated_at
            FROM identities
            WHERE tenant_id =
        "#,
        );

        builder.push_bind(filter.tenant_id);

        if let Some(pool_id) = filter.pool_id {
            builder.push(" AND pool_id = ");
            builder.push_bind(pool_id);
        }

        if let Some(status) = filter.status {
            builder.push(" AND status = ");
            builder.push_bind(status as Status);
        }

        if let Some(query) = &filter.query {
            builder.push(" AND (lower(email) LIKE ");
            builder.push_bind(format!("%{}%", query.to_lowercase()));
            builder.push(" OR lower(username) LIKE ");
            builder.push_bind(format!("%{}%", query.to_lowercase()));
            builder.push(")");
        }

        builder.push(" ORDER BY created_at DESC");

        let limit = filter.page_size;
        let offset = (filter.page - 1) * filter.page_size;

        builder.push(" LIMIT ");
        builder.push_bind(limit as i64);
        builder.push(" OFFSET ");
        builder.push_bind(offset as i64);

        let identities = builder
            .build_query_as::<DbIdentity>()
            .fetch_all(&self.read_pool)
            .await
            .map_err(map_sql_error)?
            .into_iter()
            .map(|d| d.into())
            .collect();

        // Count query stays simple
        let mut count_builder =
            QueryBuilder::new("SELECT COUNT(*) FROM identities WHERE tenant_id = ");
        count_builder.push_bind(filter.tenant_id);

        if let Some(pool_id) = filter.pool_id {
            count_builder.push(" AND pool_id = ");
            count_builder.push_bind(pool_id);
        }

        if let Some(status) = filter.status {
            count_builder.push(" AND status = ");
            count_builder.push_bind(status as Status);
        }

        if let Some(query) = &filter.query {
            count_builder.push(" AND (lower(email) LIKE ");
            count_builder.push_bind(format!("%{}%", query.to_lowercase()));
            count_builder.push(" OR lower(username) LIKE ");
            count_builder.push_bind(format!("%{}%", query.to_lowercase()));
            count_builder.push(")");
        }

        let count: i64 = count_builder
            .build()
            .fetch_one(&self.read_pool)
            .await
            .map_err(map_sql_error)?
            .get(0);

        Ok((identities, count as u64))
    }
}

#[instrument]
fn map_sql_error(e: sqlx::Error) -> RepositoryError {
    match e {
        sqlx::Error::RowNotFound => RepositoryError::NotFound,
        sqlx::Error::Database(db_err) => {
            if db_err.constraint().is_some() {
                RepositoryError::Duplicate(db_err.message().to_string())
            } else {
                RepositoryError::Database(db_err.message().to_string())
            }
        }
        _ => RepositoryError::Database(e.to_string()),
    }
}
