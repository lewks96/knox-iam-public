use argon2::{
    Argon2, Params,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use knox_common::error::ServiceError;
use knox_common::{
    authorization::{AuthorizationRepository, Role},
    identity::{
        Identity, IdentityFilter, IdentityHandle, IdentityKind, IdentityRepository,
        IdentityUpdates, Status,
    },
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;
use validator::Validate;

/// Argon2id tuning parameters.
///
/// Production defaults match OWASP recommendations (m=19456, t=2, p=1).
/// Lower these in non-production environments via env vars to speed up tests:
///
///   ARGON2_M_COST=4096   # memory in KiB
///   ARGON2_T_COST=1      # iterations
///   ARGON2_P_COST=1      # parallelism
#[derive(Clone, Debug)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Params {
    /// Reads params from environment variables, falling back to OWASP-recommended defaults.
    pub fn from_env() -> Self {
        let m_cost = std::env::var("ARGON2_M_COST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(19456);
        let t_cost = std::env::var("ARGON2_T_COST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        let p_cost = std::env::var("ARGON2_P_COST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }

    fn build(&self) -> Result<Argon2<'static>, ServiceError> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, None)
            .map_err(|e| ServiceError::Internal(format!("Invalid Argon2 params: {}", e)))?;
        Ok(Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// Cap on concurrent argon2 hash/verify operations across the service.
///
/// Each operation allocates `m_cost` KiB (~19 MiB at OWASP defaults) and is
/// fully CPU-bound. With only `cpu limit` cores available, allowing dozens
/// or hundreds of concurrent ops just queues them on the blocking pool while
/// each request frame keeps holding its arguments, span data and DB pool
/// permit — that's the OOM path. Bounding the concurrent count to ~ the CPU
/// limit means waiting requests park at this single semaphore (tiny memory)
/// instead of accumulating per-request state.
///
/// Default = 2, override with `ARGON2_MAX_CONCURRENT`.
fn argon2_concurrency_limit() -> usize {
    std::env::var("ARGON2_MAX_CONCURRENT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(2)
}

#[derive(Debug, Validate, Deserialize, Default)]
pub struct CreateIdentityRequest {
    pub tenant_id: Uuid,
    /// The directory to create this identity in. Determines who can ever
    /// authenticate as them: only clients bound to this pool.
    pub pool_id: Uuid,
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 3, max = 50, message = "Username must be between 3 and 50 chars"))]
    pub username: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    pub initial_roles: Option<Vec<String>>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Validate, Deserialize)]
pub struct LoginRequest {
    pub tenant_id: Uuid,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1))]
    pub password: String,
}

#[derive(Debug, Default, Validate, Serialize, Deserialize, Clone)]
pub struct UpdateIdentityRequest {
    pub email: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub status: Option<Status>,
    pub metadata: Option<serde_json::Value>,
    pub custom_attributes: Option<serde_json::Value>,
}

#[derive(Debug, Validate, Deserialize)]
pub struct ChangePasswordRequest {
    pub pool_id: Uuid,
    pub identity_id: Uuid,
    pub current_password: String,
    #[validate(length(min = 8, message = "New password must be at least 8 characters"))]
    pub new_password: String,
}

#[derive(Debug, Validate, Deserialize)]
pub struct AdminResetPasswordRequest {
    pub pool_id: Uuid,
    pub identity_id: Uuid,
    #[validate(length(min = 8))]
    pub new_password: String,
}

#[derive(Debug, Validate, Deserialize)]
pub struct RoleAssignmentRequest {
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
    pub role_name: String,
}

#[derive(Debug, Deserialize)]
pub struct IdentitySearchRequest {
    pub tenant_id: Uuid,
    /// `None` lists every pool in the tenant.
    pub pool_id: Option<Uuid>,
    pub page: u32,
    pub page_size: u32,
    pub query: Option<String>,
    pub status: Option<Status>,
}

#[derive(Clone)]
pub struct IdentityService<I, A>
where
    I: IdentityRepository,
    A: AuthorizationRepository,
{
    identity_repo: I,
    auth_repo: A,
    argon2_params: Argon2Params,
    argon2_semaphore: Arc<Semaphore>,
    /// A real Argon2id hash used when no usable credential exists. Verifying it
    /// keeps unknown, passwordless, and inactive accounts on the same expensive
    /// path as an ordinary wrong password.
    dummy_password_hash: String,
}

impl<I, A> IdentityService<I, A>
where
    I: IdentityRepository,
    A: AuthorizationRepository,
{
    #[instrument(skip(identity_repo, auth_repo))]
    pub fn new(identity_repo: I, auth_repo: A) -> Self {
        let permits = argon2_concurrency_limit();
        info!(
            "Argon2 concurrency limit: {} (override with ARGON2_MAX_CONCURRENT)",
            permits
        );
        let argon2_params = Argon2Params::from_env();
        let dummy_password_hash = argon2_params
            .build()
            .expect("invalid Argon2 parameters")
            .hash_password(
                b"knox-dummy-password-not-a-user-credential",
                &SaltString::generate(&mut OsRng),
            )
            .expect("failed to create dummy password hash")
            .to_string();

        Self {
            identity_repo,
            auth_repo,
            argon2_params,
            argon2_semaphore: Arc::new(Semaphore::new(permits)),
            dummy_password_hash,
        }
    }

    /// Verifies the first factor (password). Whether a second factor is
    /// required is decided by `AuthenticationService`, which owns the MFA
    /// orchestration.
    ///
    /// Scoped to a single pool, and that is the whole point: the caller derives
    /// `pool_id` from the OAuth client being logged into, so an identity in a
    /// different pool of the same tenant is not merely refused — the lookup
    /// never sees it. An end user presenting correct credentials to the console's
    /// `management` client gets `InvalidCredentials`, indistinguishable from a
    /// wrong password.
    #[instrument(skip(self, password))]
    pub async fn authenticate(
        &self,
        pool_id: Uuid,
        handle: IdentityHandle,
        password: &str,
    ) -> Result<Identity, ServiceError> {
        let identity = self.identity_repo.get(pool_id, handle.clone()).await?;

        let has_password = identity
            .as_ref()
            .and_then(|user| user.password_hash.as_ref())
            .is_some();
        let hash_owned = identity
            .as_ref()
            .and_then(|user| user.password_hash.clone())
            .unwrap_or_else(|| self.dummy_password_hash.clone());
        PasswordHash::new(&hash_owned).map_err(|_| {
            ServiceError::Repository(knox_common::error::RepositoryError::Database(
                "Corrupt hash".into(),
            ))
        })?;

        // allocates m_cost KiB. spawn_blocking keeps it off the async runtime;
        // the semaphore caps how many run concurrently so waiting requests
        // park here (small) rather than queueing on the blocking pool while
        // each holds its full request frame.
        let argon2 = self.argon2_params.build()?;
        let password_owned = password.to_owned();
        let _permit = self
            .argon2_semaphore
            .acquire()
            .await
            .map_err(|_| ServiceError::Internal("Argon2 semaphore closed".into()))?;
        let password_matches =
            tokio::task::spawn_blocking(move || -> Result<bool, ServiceError> {
                let parsed = PasswordHash::new(&hash_owned)
                    .map_err(|_| ServiceError::Internal("Invalid verification hash".into()))?;
                Ok(argon2
                    .verify_password(password_owned.as_bytes(), &parsed)
                    .is_ok())
            })
            .await
            .map_err(|e| ServiceError::Internal(format!("Blocking task failed: {}", e)))??;

        let Some(user) = identity else {
            return Err(ServiceError::InvalidCredentials);
        };
        if !has_password || !password_matches || user.status != Status::Active {
            return Err(ServiceError::InvalidCredentials);
        }
        debug!("User {:?} authenticated successfully", handle);

        Ok(user)
    }
    #[instrument(skip(self, req))]
    pub async fn create_user(&self, req: CreateIdentityRequest) -> Result<Identity, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        debug!(
            "Creating user with email: {}, username: {}",
            req.email, req.username
        );

        // argon2 hash is CPU-bound — run on a blocking thread to avoid
        // starving the tokio runtime, and gate concurrency through the
        // service-wide semaphore so the blocking pool can't accumulate
        // queued ops (each holding its own m_cost-KiB working set).
        let argon2 = self.argon2_params.build()?;
        let password_owned = req.password.clone();
        let _permit = self
            .argon2_semaphore
            .acquire()
            .await
            .map_err(|_| ServiceError::Internal("Argon2 semaphore closed".into()))?;
        let password_hash = tokio::task::spawn_blocking(move || -> Result<String, ServiceError> {
            let salt = SaltString::generate(&mut OsRng);
            argon2
                .hash_password(password_owned.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|e| ServiceError::Validation(format!("Hashing failed: {}", e)))
        })
        .await
        .map_err(|e| ServiceError::Internal(format!("Blocking task failed: {}", e)))??;

        debug!("Password hashed successfully for user: {}", req.email);

        let new_id = Uuid::new_v4();
        let identity = Identity {
            id: new_id,
            tenant_id: req.tenant_id,
            pool_id: req.pool_id,
            kind: IdentityKind::Human,
            username: req.username,
            email: Some(req.email.clone()),
            password_hash: Some(password_hash),
            email_verified: false,
            first_name: req.first_name,
            last_name: req.last_name,
            metadata: serde_json::json!({}),
            custom_attributes: serde_json::json!({}),
            status: Status::Active,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };

        let created = self.identity_repo.create(&identity).await?;
        debug!("User created with ID: {}", created.id);

        let mut roles = vec![crate::roles::IDENTITY_SELF_ROLE_NAME.to_string()];

        if let Some(extra_roles) = req.initial_roles.as_ref() {
            info!(
                "Assigning initial roles to user {}: {:?}",
                req.email, extra_roles
            );
            roles.extend(extra_roles.iter().cloned());
        }

        for role in &roles {
            self.auth_repo
                .assign_role(req.tenant_id, created.id, role)
                .await?;
            debug!(
                "Assigned role '{}' to user {} (ID: {})",
                role, req.email, created.id
            );
        }

        Ok(created)
    }

    #[instrument(skip(self))]
    pub async fn get_identity(&self, pool_id: Uuid, id: Uuid) -> Result<Identity, ServiceError> {
        debug!("Fetching identity with ID: {} for pool: {}", id, pool_id);
        self.identity_repo
            .get(pool_id, IdentityHandle::Id(id))
            .await?
            .ok_or_else(|| ServiceError::Validation("User not found".into()))
    }

    /// Looks up an identity by handle within a pool. `None` when absent, rather
    /// than an error — for flows that must not reveal whether an account exists
    /// (self-service reset requests), the caller treats found and not-found the
    /// same way.
    #[instrument(skip(self))]
    pub async fn find_by_handle(
        &self,
        pool_id: Uuid,
        handle: IdentityHandle,
    ) -> Result<Option<Identity>, ServiceError> {
        self.identity_repo
            .get(pool_id, handle)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn list_identities(
        &self,
        req: IdentitySearchRequest,
    ) -> Result<(Vec<Identity>, u64), ServiceError> {
        debug!(
            "Listing identities for tenant: {}, page: {}, page_size: {}, query: {:?}, status: {:?}",
            req.tenant_id, req.page, req.page_size, req.query, req.status
        );

        let filter = IdentityFilter {
            tenant_id: req.tenant_id,
            pool_id: req.pool_id,
            page: req.page,
            page_size: req.page_size,
            status: req.status,
            query: req.query,
        };

        self.identity_repo
            .list(filter)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self, req))]
    pub async fn update_identity(
        &self,
        pool_id: Uuid,
        id: Uuid,
        req: UpdateIdentityRequest,
    ) -> Result<Identity, ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        debug!(
            "Updating identity with ID: {} for pool: {}. Updates - first_name: {:?}, last_name: {:?}, status: {:?}, metadata: {:?}",
            id, pool_id, req.first_name, req.last_name, req.status, req.metadata
        );

        let updates = IdentityUpdates {
            first_name: req.first_name,
            last_name: req.last_name,
            status: req.status,
            metadata: req.metadata,
            email: req.email,
            username: req.username,
            custom_attributes: req.custom_attributes,
            ..Default::default()
        };

        self.identity_repo
            .update(pool_id, IdentityHandle::Id(id), &updates)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn delete_identity(&self, pool_id: Uuid, id: Uuid) -> Result<(), ServiceError> {
        debug!("Deleting identity with ID: {} for pool: {}", id, pool_id);
        self.identity_repo
            .delete(pool_id, IdentityHandle::Id(id))
            .await
            .map_err(ServiceError::Repository)
    }
    /// Hashes `new_password` and writes it, replacing whatever hash was there.
    /// No authorization or current-password check — callers own that. Argon2 is
    /// CPU-bound, so it runs on the blocking pool under the service-wide
    /// semaphore, exactly as `create_user` does.
    ///
    /// Enforces the 8-character floor here, so every write path — the reset and
    /// change flows in `AuthenticationService` included — gets it without having
    /// to remember to validate first.
    ///
    /// `pub(crate)` so `AuthenticationService` can compose it into the reset and
    /// self-service flows; not exposed past the crate, where callers should use
    /// the fuller `change_password` / `admin_reset_password`.
    #[instrument(skip(self, new_password), fields(identity_id = %identity_id, pool_id = %pool_id))]
    pub(crate) async fn set_password(
        &self,
        pool_id: Uuid,
        identity_id: Uuid,
        new_password: &str,
    ) -> Result<(), ServiceError> {
        if new_password.chars().count() < 8 {
            return Err(ServiceError::Validation(
                "New password must be at least 8 characters".into(),
            ));
        }
        let argon2 = self.argon2_params.build()?;
        let password_owned = new_password.to_owned();
        let _permit = self
            .argon2_semaphore
            .acquire()
            .await
            .map_err(|_| ServiceError::Internal("Argon2 semaphore closed".into()))?;
        let new_hash = tokio::task::spawn_blocking(move || -> Result<String, ServiceError> {
            let salt = SaltString::generate(&mut OsRng);
            argon2
                .hash_password(password_owned.as_bytes(), &salt)
                .map(|h| h.to_string())
                .map_err(|e| ServiceError::Validation(e.to_string()))
        })
        .await
        .map_err(|e| ServiceError::Internal(format!("Blocking task failed: {}", e)))??;

        let updates = IdentityUpdates {
            password_hash: Some(new_hash),
            ..Default::default()
        };

        self.identity_repo
            .update(pool_id, IdentityHandle::Id(identity_id), &updates)
            .await?;

        Ok(())
    }

    #[instrument(skip(self, req))]
    pub async fn change_password(&self, req: ChangePasswordRequest) -> Result<(), ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        debug!(
            "Changing password for identity ID: {} in pool: {}",
            req.identity_id, req.pool_id
        );

        let user = self.get_identity(req.pool_id, req.identity_id).await?;

        let stored_hash = user.password_hash.ok_or(ServiceError::InvalidCredentials)?;

        debug!(
            "Verifying current password for identity ID: {} in pool: {}",
            req.identity_id, req.pool_id
        );

        let argon2_verify = self.argon2_params.build()?;
        // Verify current password on the blocking pool, guarded by semaphore.
        // The permit is scoped to this block so it is released before
        // `set_password` acquires its own — otherwise `ARGON2_MAX_CONCURRENT=1`
        // would deadlock, one hash waiting on a permit the same task still holds.
        let current_password = req.current_password.clone();
        let hash_for_verify = stored_hash.clone();
        {
            let _permit = self
                .argon2_semaphore
                .acquire()
                .await
                .map_err(|_| ServiceError::Internal("Argon2 semaphore closed".into()))?;
            tokio::task::spawn_blocking(move || -> Result<(), ServiceError> {
                let parsed = PasswordHash::new(&hash_for_verify)
                    .map_err(|_| ServiceError::InvalidCredentials)?;
                argon2_verify
                    .verify_password(current_password.as_bytes(), &parsed)
                    .map_err(|_| ServiceError::InvalidCredentials)
            })
            .await
            .map_err(|e| ServiceError::Internal(format!("Blocking task failed: {}", e)))??;
        }

        debug!(
            "Password change verified for identity ID: {}. Updating hash.",
            req.identity_id
        );

        self.set_password(req.pool_id, req.identity_id, &req.new_password)
            .await
    }

    #[instrument(skip(self, req))]
    pub async fn admin_reset_password(
        &self,
        req: AdminResetPasswordRequest,
    ) -> Result<(), ServiceError> {
        req.validate()
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        if !self
            .identity_repo
            .exists(req.pool_id, IdentityHandle::Id(req.identity_id))
            .await?
        {
            error!(
                "Admin password reset failed: identity ID {} not found in pool {}",
                req.identity_id, req.pool_id
            );
            return Err(ServiceError::Validation("User not found".into()));
        }

        debug!(
            "Admin resetting password for identity ID: {} in pool: {}",
            req.identity_id, req.pool_id
        );

        self.set_password(req.pool_id, req.identity_id, &req.new_password)
            .await
    }

    #[instrument(skip(self))]
    pub async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, ServiceError> {
        self.auth_repo
            .list_roles(tenant_id)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn get_identity_roles(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<String>, ServiceError> {
        self.auth_repo
            .get_identity_roles(tenant_id, identity_id)
            .await
            .map_err(ServiceError::Repository)
    }

    /// You cannot grant what you do not hold.
    ///
    /// Role assignment is a privilege operation reachable by anyone with
    /// `IdentityUpdate`, so without this an ordinary identity admin in the
    /// platform tenant could assign themselves `PlatformAdmin` — turning a
    /// tenant-level permission into deployment-level authority. Requiring the
    /// granter to already hold every permission the role confers makes
    /// assignment able to *spread* privilege but never to *create* it.
    ///
    /// `granter_scopes` comes from the caller's verified token, which
    /// `permitted_scopes` has already narrowed to what their own roles allow.
    pub async fn ensure_can_grant(
        &self,
        tenant_id: Uuid,
        role_name: &str,
        granter_scopes: &[String],
    ) -> Result<(), ServiceError> {
        let roles = self.list_roles(tenant_id).await?;
        let role = roles
            .iter()
            .find(|r| r.name == role_name)
            .ok_or_else(|| ServiceError::Validation(format!("Unknown role: {}", role_name)))?;

        let missing: Vec<&str> = role
            .permissions
            .iter()
            .map(|p| p.key.as_str())
            .filter(|key| !granter_scopes.iter().any(|s| s == key))
            .collect();

        if !missing.is_empty() {
            error!(
                "Refusing to assign role '{}': granter lacks {:?}",
                role_name, missing
            );
            return Err(ServiceError::Forbidden);
        }
        Ok(())
    }

    #[instrument(skip(self, req, granter_scopes))]
    pub async fn assign_role(
        &self,
        req: RoleAssignmentRequest,
        granter_scopes: &[String],
    ) -> Result<(), ServiceError> {
        debug!(
            "Assigning role '{}' to identity ID: {} in tenant: {}",
            req.role_name, req.identity_id, req.tenant_id
        );
        self.ensure_can_grant(req.tenant_id, &req.role_name, granter_scopes)
            .await?;
        self.auth_repo
            .assign_role(req.tenant_id, req.identity_id, &req.role_name)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self, req, granter_scopes))]
    pub async fn revoke_role(
        &self,
        req: RoleAssignmentRequest,
        granter_scopes: &[String],
    ) -> Result<(), ServiceError> {
        debug!(
            "Revoking role '{}' from identity ID: {} in tenant: {}",
            req.role_name, req.identity_id, req.tenant_id
        );
        if req.role_name == "IdentitySelf" {
            error!(
                "Attempt to revoke default role '{}' from identity ID: {} in tenant: {} - operation not allowed",
                req.role_name, req.identity_id, req.tenant_id
            );
            return Err(ServiceError::Validation(format!(
                "Cannot revoke default role: {}",
                req.role_name
            )));
        }
        // Symmetric with assignment: revoking a role you could not grant would
        // let a lesser-privileged admin strip authority from a greater one.
        self.ensure_can_grant(req.tenant_id, &req.role_name, granter_scopes)
            .await?;
        self.auth_repo
            .remove_role(req.tenant_id, req.identity_id, &req.role_name)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn get_permissions(&self, identity_id: Uuid) -> Result<Vec<String>, ServiceError> {
        debug!("Fetching permissions for identity ID: {}", identity_id);
        self.auth_repo
            .get_permissions(identity_id)
            .await
            .map_err(ServiceError::Repository)
    }
}
