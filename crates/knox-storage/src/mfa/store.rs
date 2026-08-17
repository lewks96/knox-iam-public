use crate::mfa::{DbMfaMethod, MfaStore};
use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::mfa::{MfaMethod, MfaMethodKind, NewMfaMethod};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

#[derive(Clone)]
pub struct PgMfaStore {
    pool: PgPool,
}

impl PgMfaStore {
    #[instrument(skip(pool))]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MfaStore for PgMfaStore {
    #[instrument(skip(self, method))]
    async fn create_method(&self, method: &NewMfaMethod) -> Result<MfaMethod, RepositoryError> {
        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;

        // Singleton kinds: replace any unverified enrollment of the same kind
        // so a user can restart enrollment. A verified enrollment survives and
        // surfaces as a unique violation -> Duplicate.
        if matches!(method.method, MfaMethodKind::Totp | MfaMethodKind::Sms) {
            sqlx::query!(
                r#"
                DELETE FROM mfa_methods
                WHERE tenant_id = $1 AND identity_id = $2 AND method = $3 AND verified_at IS NULL
                "#,
                method.tenant_id,
                method.identity_id,
                method.method as MfaMethodKind,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sql_error)?;
        }

        let rec = sqlx::query_as!(
            DbMfaMethod,
            r#"
            INSERT INTO mfa_methods (tenant_id, identity_id, method, secret_enc, public_data)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id, tenant_id, identity_id,
                method as "method: MfaMethodKind",
                secret_enc, public_data, last_used_step,
                verified_at, last_used_at, created_at, updated_at
            "#,
            method.tenant_id,
            method.identity_id,
            method.method as MfaMethodKind,
            method.secret_enc.as_deref(),
            method.public_data,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sql_error)?;

        tx.commit().await.map_err(map_sql_error)?;

        Ok(rec.into())
    }

    #[instrument(skip(self))]
    async fn get_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<Option<MfaMethod>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbMfaMethod,
            r#"
            SELECT
                id, tenant_id, identity_id,
                method as "method: MfaMethodKind",
                secret_enc, public_data, last_used_step,
                verified_at, last_used_at, created_at, updated_at
            FROM mfa_methods
            WHERE tenant_id = $1 AND identity_id = $2 AND id = $3
            "#,
            tenant_id,
            identity_id,
            method_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn get_method_by_kind(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        kind: MfaMethodKind,
    ) -> Result<Option<MfaMethod>, RepositoryError> {
        let rec = sqlx::query_as!(
            DbMfaMethod,
            r#"
            SELECT
                id, tenant_id, identity_id,
                method as "method: MfaMethodKind",
                secret_enc, public_data, last_used_step,
                verified_at, last_used_at, created_at, updated_at
            FROM mfa_methods
            WHERE tenant_id = $1 AND identity_id = $2 AND method = $3
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            tenant_id,
            identity_id,
            kind as MfaMethodKind,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(rec.map(|r| r.into()))
    }

    #[instrument(skip(self))]
    async fn list_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethod>, RepositoryError> {
        let recs = sqlx::query_as!(
            DbMfaMethod,
            r#"
            SELECT
                id, tenant_id, identity_id,
                method as "method: MfaMethodKind",
                secret_enc, public_data, last_used_step,
                verified_at, last_used_at, created_at, updated_at
            FROM mfa_methods
            WHERE tenant_id = $1 AND identity_id = $2
            ORDER BY created_at ASC
            "#,
            tenant_id,
            identity_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(recs.into_iter().map(|r| r.into()).collect())
    }

    #[instrument(skip(self))]
    async fn list_verified_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethod>, RepositoryError> {
        let recs = sqlx::query_as!(
            DbMfaMethod,
            r#"
            SELECT
                id, tenant_id, identity_id,
                method as "method: MfaMethodKind",
                secret_enc, public_data, last_used_step,
                verified_at, last_used_at, created_at, updated_at
            FROM mfa_methods
            WHERE tenant_id = $1 AND identity_id = $2 AND verified_at IS NOT NULL
            ORDER BY created_at ASC
            "#,
            tenant_id,
            identity_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(recs.into_iter().map(|r| r.into()).collect())
    }

    #[instrument(skip(self))]
    async fn mark_verified(
        &self,
        tenant_id: Uuid,
        method_id: Uuid,
    ) -> Result<MfaMethod, RepositoryError> {
        let rec = sqlx::query_as!(
            DbMfaMethod,
            r#"
            UPDATE mfa_methods
            SET verified_at = now()
            WHERE tenant_id = $1 AND id = $2
            RETURNING
                id, tenant_id, identity_id,
                method as "method: MfaMethodKind",
                secret_enc, public_data, last_used_step,
                verified_at, last_used_at, created_at, updated_at
            "#,
            tenant_id,
            method_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?;

        rec.map(|r| r.into()).ok_or(RepositoryError::NotFound)
    }

    #[instrument(skip(self))]
    async fn delete_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<(), RepositoryError> {
        let result = sqlx::query!(
            "DELETE FROM mfa_methods WHERE tenant_id = $1 AND identity_id = $2 AND id = $3",
            tenant_id,
            identity_id,
            method_id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn claim_totp_step(
        &self,
        tenant_id: Uuid,
        method_id: Uuid,
        step: i64,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query!(
            r#"
            UPDATE mfa_methods
            SET last_used_step = $3, last_used_at = now()
            WHERE tenant_id = $1 AND id = $2
              AND (last_used_step IS NULL OR last_used_step < $3)
            "#,
            tenant_id,
            method_id,
            step,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self, code_hashes))]
    async fn replace_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code_hashes: &[String],
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;

        sqlx::query!(
            "DELETE FROM mfa_backup_codes WHERE tenant_id = $1 AND identity_id = $2",
            tenant_id,
            identity_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sql_error)?;

        sqlx::query!(
            r#"
            INSERT INTO mfa_backup_codes (tenant_id, identity_id, code_hash)
            SELECT $1, $2, unnest($3::text[])
            "#,
            tenant_id,
            identity_id,
            code_hashes,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sql_error)?;

        tx.commit().await.map_err(map_sql_error)?;

        Ok(())
    }

    #[instrument(skip(self, code_hash))]
    async fn consume_backup_code(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query!(
            r#"
            UPDATE mfa_backup_codes
            SET used_at = now()
            WHERE tenant_id = $1 AND identity_id = $2 AND code_hash = $3 AND used_at IS NULL
            "#,
            tenant_id,
            identity_id,
            code_hash,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self))]
    async fn count_unused_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<u64, RepositoryError> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM mfa_backup_codes
            WHERE tenant_id = $1 AND identity_id = $2 AND used_at IS NULL
            "#,
            tenant_id,
            identity_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(count as u64)
    }

    #[instrument(skip(self))]
    async fn delete_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), RepositoryError> {
        sqlx::query!(
            "DELETE FROM mfa_backup_codes WHERE tenant_id = $1 AND identity_id = $2",
            tenant_id,
            identity_id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(())
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
