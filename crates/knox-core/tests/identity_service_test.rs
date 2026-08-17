use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHasher};
use async_trait::async_trait;
use knox_common::authorization::{AuthorizationRepository, Permission, Role, RoleKind};
use knox_common::error::{RepositoryError, ServiceError};
use knox_common::identity::{
    Identity, IdentityFilter, IdentityHandle, IdentityKind, IdentityRepository, IdentityUpdates,
    Status,
};
use knox_core::identity::{
    AdminResetPasswordRequest, ChangePasswordRequest, CreateIdentityRequest, IdentitySearchRequest,
    IdentityService, LoginRequest, RoleAssignmentRequest, UpdateIdentityRequest,
};
use mockall::{mock, predicate::*};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub IdentityRepo {}
    #[async_trait]
    impl IdentityRepository for IdentityRepo {
        async fn create(&self, identity: &Identity) -> Result<Identity, RepositoryError>;
        async fn get(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<Option<Identity>, RepositoryError>;
        async fn exists(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<bool, RepositoryError>;
        async fn update(&self, pool_id: Uuid, handle: IdentityHandle, updates: &IdentityUpdates) -> Result<Identity, RepositoryError>;
        async fn delete(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<(), RepositoryError>;
        async fn list(&self, filter: IdentityFilter) -> Result<(Vec<Identity>, u64), RepositoryError>;
        async fn count(&self, tenant_id: Uuid, filter: Option<String>) -> Result<u64, RepositoryError>;
    }
}

mock! {
    pub AuthRepo {}
    #[async_trait]
    impl AuthorizationRepository for AuthRepo {
        async fn create_role(&self, tenant_id: Uuid, name: &str, permissions: &Vec<String>, kind: RoleKind) -> Result<Role, RepositoryError>;
        async fn get_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<Option<Role>, RepositoryError>;
        async fn delete_role(&self, tenant_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError>;
        async fn assign_role(&self, tenant_id: Uuid, identity_id: Uuid, role_name: &str) -> Result<(), RepositoryError>;
        async fn remove_role(&self, tenant_id: Uuid, identity_id: Uuid, role_name: &str) -> Result<(), RepositoryError>;
        async fn get_permissions(&self, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
        async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, RepositoryError>;
        async fn get_identity_roles(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

fn hash_pwd(pwd: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pwd.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn make_identity(tenant_id: Uuid, status: Status, password: &str) -> Identity {
    make_identity_in_pool(tenant_id, Uuid::new_v4(), status, password)
}

fn make_identity_in_pool(
    tenant_id: Uuid,
    pool_id: Uuid,
    status: Status,
    password: &str,
) -> Identity {
    Identity {
        id: Uuid::new_v4(),
        tenant_id,
        pool_id,
        kind: IdentityKind::Human,
        username: "testuser".into(),
        email: Some("test@knox.com".into()),
        password_hash: Some(hash_pwd(password)),
        email_verified: true,
        status,
        first_name: Some("Test".into()),
        last_name: Some("User".into()),
        metadata: serde_json::json!({}),
        custom_attributes: serde_json::json!({}),
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    }
}

fn dummy_identity() -> Identity {
    Identity {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        pool_id: Uuid::new_v4(),
        kind: IdentityKind::Human,
        username: "dummy".into(),
        email: None,
        password_hash: None,
        email_verified: false,
        status: Status::Active,
        first_name: None,
        last_name: None,
        metadata: serde_json::json!({}),
        custom_attributes: serde_json::json!({}),
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    }
}

// ---------------------------------------------------------------------------
// create_user tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_user_hashes_password_and_assigns_default_role() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();

    mock_i
        .expect_create()
        .times(1)
        .withf(|i: &Identity| {
            i.password_hash
                .as_ref()
                .map(|h| h.starts_with("$argon2"))
                .unwrap_or(false)
        })
        .returning(|i| Ok(i.clone()));

    let default_roles = vec!["IdentitySelf".to_string()];
    for role in default_roles {
        mock_a
            .expect_assign_role()
            .with(eq(tenant_id), always(), eq(role.to_string()))
            .times(1)
            .returning(|_, _, _| Ok(()));
    }

    let service = IdentityService::new(mock_i, mock_a);
    let req = CreateIdentityRequest {
        pool_id: Uuid::new_v4(),
        tenant_id,
        email: "new@user.com".to_string(),
        username: "newuser".to_string(),
        password: "securePassword123".to_string(),
        first_name: Some("New".to_string()),
        last_name: Some("User".to_string()),
        initial_roles: None,
    };

    let result = service.create_user(req).await;
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
}

#[tokio::test]
async fn test_create_user_with_custom_initial_roles() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();

    mock_i.expect_create().times(1).returning(|i| Ok(i.clone()));

    let mut roles = vec!["IdentitySelf".to_string()];
    roles.push("Admin".to_string()); // Custom role in addition to defaults  
    for role in roles {
        mock_a
            .expect_assign_role()
            .with(eq(tenant_id), always(), eq(role.to_string()))
            .times(1)
            .returning(|_, _, _| Ok(()));
    }

    let service = IdentityService::new(mock_i, mock_a);
    let req = CreateIdentityRequest {
        pool_id: Uuid::new_v4(),
        tenant_id,
        email: "admin@user.com".to_string(),
        username: "adminuser".to_string(),
        password: "securePassword123".to_string(),
        first_name: Some("New".to_string()),
        last_name: Some("User".to_string()),
        initial_roles: Some(vec!["Admin".to_string()]),
    };

    let result = service.create_user(req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_user_invalid_email_fails_validation() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    let service = IdentityService::new(mock_i, mock_a);
    let req = CreateIdentityRequest {
        pool_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        email: "not-an-email".to_string(),
        username: "validuser".to_string(),
        password: "securePassword123".to_string(),
        first_name: Some("New".to_string()),
        last_name: Some("User".to_string()),
        initial_roles: None,
    };

    let result = service.create_user(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_user_username_too_short_fails_validation() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    let service = IdentityService::new(mock_i, mock_a);
    let req = CreateIdentityRequest {
        pool_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        email: "valid@email.com".to_string(),
        username: "ab".to_string(), // too short (min 3)
        password: "securePassword123".to_string(),
        first_name: Some("New".to_string()),
        last_name: Some("User".to_string()),
        initial_roles: None,
    };

    let result = service.create_user(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_user_username_too_long_fails_validation() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    let service = IdentityService::new(mock_i, mock_a);
    let req = CreateIdentityRequest {
        pool_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        email: "valid@email.com".to_string(),
        username: "a".repeat(51), // too long (max 50)
        password: "securePassword123".to_string(),
        first_name: Some("New".to_string()),
        last_name: Some("User".to_string()),
        initial_roles: None,
    };

    let result = service.create_user(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_user_password_too_short_fails_validation() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    let service = IdentityService::new(mock_i, mock_a);
    let req = CreateIdentityRequest {
        pool_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        email: "valid@email.com".to_string(),
        username: "validuser".to_string(),
        password: "short".to_string(), // too short (min 8)
        first_name: Some("New".to_string()),
        last_name: Some("User".to_string()),
        initial_roles: None,
    };

    let result = service.create_user(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_user_password_exactly_8_chars_is_valid() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();

    mock_i.expect_create().times(1).returning(|i| Ok(i.clone()));
    let default_roles = vec!["IdentitySelf".to_string()];
    for role in default_roles {
        mock_a
            .expect_assign_role()
            .with(eq(tenant_id), always(), eq(role.to_string()))
            .times(1)
            .returning(|_, _, _| Ok(()));
    }

    let service = IdentityService::new(mock_i, mock_a);
    let req = CreateIdentityRequest {
        pool_id: Uuid::new_v4(),
        tenant_id,
        email: "valid@email.com".to_string(),
        username: "validuser".to_string(),
        password: "exactly8".to_string(), // exactly 8 characters
        first_name: Some("New".to_string()),
        last_name: Some("User".to_string()),
        initial_roles: None,
    };

    let result = service.create_user(req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_user_repo_error_propagates() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();

    mock_i
        .expect_create()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("DB down".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let req = CreateIdentityRequest {
        pool_id: Uuid::new_v4(),
        tenant_id,
        email: "new@user.com".to_string(),
        username: "newuser".to_string(),
        password: "securePassword123".to_string(),
        first_name: Some("New".to_string()),
        last_name: Some("User".to_string()),
        initial_roles: None,
    };

    let result = service.create_user(req).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

//#[tokio::test]
//async fn test_create_user_role_assignment_failure_does_not_fail_request() {
//    // The service uses eprintln! and continues on role assignment failure
//    init_tracing();
//    let mut mock_i = MockIdentityRepo::new();
//    let mut mock_a = MockAuthRepo::new();
//    let tenant_id = Uuid::new_v4();
//
//    mock_i.expect_create().times(1).returning(|i| Ok(i.clone()));
//
//    mock_a
//        .expect_assign_role()
//        .times(1)
//        .returning(|_, _, _| Err(RepositoryError::Database("Role service down".into())));
//
//    let service = IdentityService::new(mock_i, mock_a);
//    let req = CreateIdentityRequest {
//        tenant_id,
//        email: "new@user.com".to_string(),
//        username: "newuser".to_string(),
//        password: "securePassword123".to_string(),
//        first_name: Some("New".to_string()),
//        last_name: Some("User".to_string()),
//        initial_roles: None,
//    };
//
//    // Should still succeed even if role assignment fails
//    let result = service.create_user(req).await;
//    assert!(
//        result.is_ok(),
//        "User creation should succeed even if role assignment fails"
//    );
//}

// ---------------------------------------------------------------------------
// authenticate tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authenticate_success() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let password = "mySecretPassword";
    let user = make_identity(tenant_id, Status::Active, password);

    mock_i
        .expect_get()
        .with(
            eq(tenant_id),
            function(|h| matches!(h, IdentityHandle::Email(_))),
        )
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    let service = IdentityService::new(mock_i, mock_a);
    let req = LoginRequest {
        tenant_id,
        email: "test@knox.com".into(),
        password: password.into(),
    };

    let result = service
        .authenticate(
            req.tenant_id,
            IdentityHandle::Email(req.email),
            &req.password,
        )
        .await;
    assert!(
        result.is_ok(),
        "Expected successful auth, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_authenticate_in_wrong_pool_is_invalid_credentials_not_a_denial() {
    // The property this whole change exists for.
    //
    // An end user presents entirely correct credentials, but against the pool
    // the console's `management` client is bound to. The repository is queried
    // with the staff pool, so their row is not a candidate — they get
    // InvalidCredentials, indistinguishable from a wrong password.
    //
    // Note what is NOT happening: no "is this user allowed here" check that
    // could be forgotten at a new call site, and no Forbidden that would
    // confirm the account exists. The scope is part of the lookup.
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    let tenant_id = Uuid::new_v4();
    let staff_pool = Uuid::new_v4();
    let customer_pool = Uuid::new_v4();
    let password = "theEndUsersRealPassword";

    // The identity exists — in the customer pool.
    let _end_user = make_identity_in_pool(tenant_id, customer_pool, Status::Active, password);

    // Logging in via the console resolves the staff pool, where they do not exist.
    mock_i
        .expect_get()
        .with(
            eq(staff_pool),
            function(|h| matches!(h, IdentityHandle::Username(_))),
        )
        .times(1)
        .return_once(move |_, _| Ok(None));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service
        .authenticate(
            staff_pool,
            IdentityHandle::Username("test@knox.com".into()),
            password,
        )
        .await;

    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "End user authenticating against the staff pool must be indistinguishable \
         from a bad password, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_authenticate_succeeds_in_the_pool_the_identity_belongs_to() {
    // The other half: the same credentials work at their own pool's client.
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    let tenant_id = Uuid::new_v4();
    let customer_pool = Uuid::new_v4();
    let password = "theEndUsersRealPassword";
    let end_user = make_identity_in_pool(tenant_id, customer_pool, Status::Active, password);

    mock_i
        .expect_get()
        .with(
            eq(customer_pool),
            function(|h| matches!(h, IdentityHandle::Username(_))),
        )
        .times(1)
        .return_once(move |_, _| Ok(Some(end_user)));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service
        .authenticate(
            customer_pool,
            IdentityHandle::Username("testuser".into()),
            password,
        )
        .await;

    assert!(
        result.is_ok(),
        "Expected successful auth, got: {:?}",
        result
    );
    assert_eq!(result.unwrap().pool_id, customer_pool);
}

#[tokio::test]
async fn test_authenticate_wrong_password_returns_invalid_credentials() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user = make_identity(tenant_id, Status::Active, "CorrectPassword");

    mock_i
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    let service = IdentityService::new(mock_i, mock_a);
    let req = LoginRequest {
        tenant_id,
        email: "test@knox.com".into(),
        password: "WrongPassword".into(),
    };

    let result = service
        .authenticate(
            req.tenant_id,
            IdentityHandle::Email(req.email),
            &req.password,
        )
        .await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Expected InvalidCredentials, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_authenticate_user_not_found_returns_invalid_credentials() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();

    mock_i.expect_get().times(1).return_once(|_, _| Ok(None));

    let service = IdentityService::new(mock_i, mock_a);
    let req = LoginRequest {
        tenant_id,
        email: "ghost@knox.com".into(),
        password: "SomePassword123".into(),
    };

    let result = service
        .authenticate(
            req.tenant_id,
            IdentityHandle::Email(req.email),
            &req.password,
        )
        .await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Expected InvalidCredentials for missing user, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_authenticate_inactive_user_returns_uniform_invalid_credentials() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let password = "correctPassword";
    let user = make_identity(tenant_id, Status::Inactive, password);

    mock_i
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    let service = IdentityService::new(mock_i, mock_a);
    let req = LoginRequest {
        tenant_id,
        email: "test@knox.com".into(),
        password: password.into(),
    };

    let result = service
        .authenticate(
            req.tenant_id,
            IdentityHandle::Email(req.email),
            &req.password,
        )
        .await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Expected uniform InvalidCredentials for inactive user, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_authenticate_suspended_user_returns_uniform_invalid_credentials() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let password = "correctPassword";
    let user = make_identity(tenant_id, Status::Suspended, password);

    mock_i
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    let service = IdentityService::new(mock_i, mock_a);
    let req = LoginRequest {
        tenant_id,
        email: "test@knox.com".into(),
        password: password.into(),
    };

    let result = service
        .authenticate(
            req.tenant_id,
            IdentityHandle::Email(req.email),
            &req.password,
        )
        .await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Expected uniform InvalidCredentials for suspended user, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_authenticate_user_with_no_password_hash_returns_invalid_credentials() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();

    let mut user = make_identity(tenant_id, Status::Active, "anything");
    user.password_hash = None; // Simulate OAuth-only user

    mock_i
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    let service = IdentityService::new(mock_i, mock_a);
    let req = LoginRequest {
        tenant_id,
        email: "test@knox.com".into(),
        password: "anything".into(),
    };

    let result = service
        .authenticate(
            req.tenant_id,
            IdentityHandle::Email(req.email),
            &req.password,
        )
        .await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Expected InvalidCredentials for user with no password hash, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_authenticate_repo_error_propagates() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();

    mock_i
        .expect_get()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Connection lost".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let req = LoginRequest {
        tenant_id,
        email: "test@knox.com".into(),
        password: "password123".into(),
    };

    let result = service
        .authenticate(
            req.tenant_id,
            IdentityHandle::Email(req.email),
            &req.password,
        )
        .await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// get_identity tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_identity_found() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let mut user = make_identity(tenant_id, Status::Active, "pass");
    user.id = user_id;

    mock_i
        .expect_get()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service.get_identity(tenant_id, user_id).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, user_id);
}

#[tokio::test]
async fn test_get_identity_not_found_returns_validation_error() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    mock_i
        .expect_get()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .return_once(|_, _| Ok(None));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service.get_identity(tenant_id, user_id).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_get_identity_repo_error_propagates() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    mock_i
        .expect_get()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Timeout".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service.get_identity(Uuid::new_v4(), Uuid::new_v4()).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// list_identities tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_identities_returns_results() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();

    let users = vec![make_identity(tenant_id, Status::Active, "pass")];
    let total = 1u64;

    mock_i
        .expect_list()
        .times(1)
        .return_once(move |_| Ok((users, total)));

    let service = IdentityService::new(mock_i, mock_a);
    let req = IdentitySearchRequest {
        pool_id: None,
        tenant_id,
        page: 1,
        page_size: 10,
        query: None,
        status: None,
    };

    let result = service.list_identities(req).await;
    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_list_identities_empty_result() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    mock_i
        .expect_list()
        .times(1)
        .return_once(|_| Ok((vec![], 0)));

    let service = IdentityService::new(mock_i, mock_a);
    let req = IdentitySearchRequest {
        pool_id: None,
        tenant_id: Uuid::new_v4(),
        page: 1,
        page_size: 10,
        query: Some("nonexistent".to_string()),
        status: Some(Status::Active),
    };

    let result = service.list_identities(req).await;
    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert!(list.is_empty());
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_list_identities_repo_error_propagates() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    mock_i
        .expect_list()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("DB error".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let req = IdentitySearchRequest {
        pool_id: None,
        tenant_id: Uuid::new_v4(),
        page: 1,
        page_size: 10,
        query: None,
        status: None,
    };

    let result = service.list_identities(req).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// update_identity tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_identity_success() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let mut updated_user = make_identity(tenant_id, Status::Active, "pass");
    updated_user.first_name = Some("Updated".into());

    mock_i
        .expect_update()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)), always())
        .times(1)
        .return_once(move |_, _, _| Ok(updated_user));

    let service = IdentityService::new(mock_i, mock_a);
    let req = UpdateIdentityRequest {
        first_name: Some("Updated".to_string()),
        last_name: None,
        status: None,
        metadata: None,
        ..Default::default()
    };

    let result = service.update_identity(tenant_id, user_id, req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().first_name, Some("Updated".into()));
}

#[tokio::test]
async fn test_update_identity_status_change() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let mut updated_user = make_identity(tenant_id, Status::Inactive, "pass");
    updated_user.status = Status::Inactive;

    mock_i
        .expect_update()
        .times(1)
        .return_once(move |_, _, _| Ok(updated_user));

    let service = IdentityService::new(mock_i, mock_a);
    let req = UpdateIdentityRequest {
        first_name: None,
        last_name: None,
        status: Some(Status::Inactive),
        metadata: None,
        ..Default::default()
    };

    let result = service.update_identity(tenant_id, user_id, req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_update_identity_repo_error_propagates() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    mock_i
        .expect_update()
        .times(1)
        .return_once(|_, _, _| Err(RepositoryError::Database("Error".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let req = UpdateIdentityRequest {
        first_name: Some("Name".to_string()),
        last_name: None,
        status: None,
        metadata: None,
        ..Default::default()
    };

    let result = service
        .update_identity(Uuid::new_v4(), Uuid::new_v4(), req)
        .await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// delete_identity tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_identity_success() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    mock_i
        .expect_delete()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .returning(|_, _| Ok(()));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service.delete_identity(tenant_id, user_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_identity_repo_error_propagates() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    mock_i
        .expect_delete()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Not found".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service
        .delete_identity(Uuid::new_v4(), Uuid::new_v4())
        .await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// change_password tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_change_password_success() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let old_pwd = "OldPassword123";
    let mut user = make_identity(tenant_id, Status::Active, old_pwd);
    user.id = user_id;

    mock_i
        .expect_get()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    mock_i
        .expect_update()
        .times(1)
        .returning(|_, _, _| Ok(dummy_identity()));

    let service = IdentityService::new(mock_i, mock_a);
    let req = ChangePasswordRequest {
        pool_id: tenant_id,
        identity_id: user_id,
        current_password: old_pwd.to_string(),
        new_password: "NewPassword456".to_string(),
    };

    let result = service.change_password(req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_change_password_wrong_current_password() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let mut user = make_identity(tenant_id, Status::Active, "ActualPassword");
    user.id = user_id;

    mock_i
        .expect_get()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    // update should NOT be called
    mock_i.expect_update().times(0);

    let service = IdentityService::new(mock_i, mock_a);
    let req = ChangePasswordRequest {
        pool_id: tenant_id,
        identity_id: user_id,
        current_password: "WrongPassword".to_string(),
        new_password: "NewPassword456".to_string(),
    };

    let result = service.change_password(req).await;
    assert!(
        matches!(result, Err(ServiceError::InvalidCredentials)),
        "Expected InvalidCredentials, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_change_password_new_password_too_short() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    let service = IdentityService::new(mock_i, mock_a);
    let req = ChangePasswordRequest {
        pool_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        current_password: "OldPassword123".to_string(),
        new_password: "short".to_string(), // fails validation
    };

    let result = service.change_password(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_change_password_user_not_found() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    mock_i
        .expect_get()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .return_once(|_, _| Ok(None));

    let service = IdentityService::new(mock_i, mock_a);
    let req = ChangePasswordRequest {
        pool_id: tenant_id,
        identity_id: user_id,
        current_password: "OldPassword123".to_string(),
        new_password: "NewPassword456".to_string(),
    };

    let result = service.change_password(req).await;
    // get_identity returns Validation("User not found") when None
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_change_password_user_with_no_hash_returns_invalid_credentials() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let mut user = make_identity(tenant_id, Status::Active, "whatever");
    user.id = user_id;
    user.password_hash = None;

    mock_i
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    let service = IdentityService::new(mock_i, mock_a);
    let req = ChangePasswordRequest {
        pool_id: tenant_id,
        identity_id: user_id,
        current_password: "whatever".to_string(),
        new_password: "NewPassword456".to_string(),
    };

    let result = service.change_password(req).await;
    assert!(matches!(result, Err(ServiceError::InvalidCredentials)));
}

// ---------------------------------------------------------------------------
// admin_reset_password tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_reset_password_success() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    mock_i
        .expect_exists()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .returning(|_, _| Ok(true));

    mock_i
        .expect_update()
        .times(1)
        .returning(|_, _, _| Ok(dummy_identity()));

    let service = IdentityService::new(mock_i, mock_a);
    let req = AdminResetPasswordRequest {
        pool_id: tenant_id,
        identity_id: user_id,
        new_password: "BrandNewPassword1".to_string(),
    };

    let result = service.admin_reset_password(req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_admin_reset_password_user_not_found() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    mock_i
        .expect_exists()
        .with(eq(tenant_id), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .returning(|_, _| Ok(false));

    // update should NOT be called
    mock_i.expect_update().times(0);

    let service = IdentityService::new(mock_i, mock_a);
    let req = AdminResetPasswordRequest {
        pool_id: tenant_id,
        identity_id: user_id,
        new_password: "BrandNewPassword1".to_string(),
    };

    let result = service.admin_reset_password(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_admin_reset_password_new_password_too_short() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    let service = IdentityService::new(mock_i, mock_a);
    let req = AdminResetPasswordRequest {
        pool_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        new_password: "short".to_string(),
    };

    let result = service.admin_reset_password(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_admin_reset_password_exactly_8_chars_is_valid() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    mock_i.expect_exists().times(1).returning(|_, _| Ok(true));
    mock_i
        .expect_update()
        .times(1)
        .returning(|_, _, _| Ok(dummy_identity()));

    let service = IdentityService::new(mock_i, mock_a);
    let req = AdminResetPasswordRequest {
        pool_id: tenant_id,
        identity_id: user_id,
        new_password: "exactly8".to_string(),
    };

    let result = service.admin_reset_password(req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_admin_reset_password_repo_exists_error_propagates() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();

    mock_i
        .expect_exists()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Error".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let req = AdminResetPasswordRequest {
        pool_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        new_password: "ValidPassword1".to_string(),
    };

    let result = service.admin_reset_password(req).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------

/// A role definition for the mocked `list_roles`, which `ensure_can_grant`
/// consults to decide whether the granter already holds what it confers.
fn role_with(tenant_id: Uuid, name: &str, perms: &[&str]) -> Role {
    Role {
        id: Uuid::new_v4(),
        tenant_id,
        name: name.to_string(),
        kind: RoleKind::Custom,
        description: None,
        permissions: perms
            .iter()
            .map(|k| Permission {
                id: Uuid::new_v4(),
                key: k.to_string(),
                description: None,
            })
            .collect(),
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    }
}

fn scopes(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// assign_role / revoke_role tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_assign_role_success() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    mock_a
        .expect_list_roles()
        .returning(move |t| Ok(vec![role_with(t, "Manager", &["ManageStuff"])]));
    mock_a
        .expect_assign_role()
        .with(eq(tenant_id), eq(user_id), eq("Manager"))
        .times(1)
        .returning(|_, _, _| Ok(()));

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id,
        identity_id: user_id,
        role_name: "Manager".to_string(),
    };

    let result = service.assign_role(req, &scopes(&["ManageStuff"])).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_assign_role_repo_error_propagates() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a
        .expect_list_roles()
        .returning(move |t| Ok(vec![role_with(t, "Manager", &["ManageStuff"])]));
    mock_a
        .expect_assign_role()
        .times(1)
        .returning(|_, _, _| Err(RepositoryError::Database("Error".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        role_name: "Manager".to_string(),
    };

    let result = service.assign_role(req, &scopes(&["ManageStuff"])).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

#[tokio::test]
async fn test_revoke_role_success() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    mock_a
        .expect_list_roles()
        .returning(move |t| Ok(vec![role_with(t, "Admin", &["ManageStuff"])]));
    mock_a
        .expect_remove_role()
        .with(eq(tenant_id), eq(user_id), eq("Admin"))
        .times(1)
        .returning(|_, _, _| Ok(()));

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id,
        identity_id: user_id,
        role_name: "Admin".to_string(),
    };

    let result = service.revoke_role(req, &scopes(&["ManageStuff"])).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_role_repo_error_propagates() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a
        .expect_list_roles()
        .returning(move |t| Ok(vec![role_with(t, "Admin", &["ManageStuff"])]));
    mock_a
        .expect_remove_role()
        .times(1)
        .returning(|_, _, _| Err(RepositoryError::Database("Error".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        role_name: "Admin".to_string(),
    };

    let result = service.revoke_role(req, &scopes(&["ManageStuff"])).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// get_permissions tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_permissions_returns_list() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();
    let identity_id = Uuid::new_v4();

    mock_a
        .expect_get_permissions()
        .with(eq(identity_id))
        .times(1)
        .return_once(|_| Ok(vec!["read:users".to_string(), "write:users".to_string()]));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service.get_permissions(identity_id).await;
    assert!(result.is_ok());
    let perms = result.unwrap();
    assert_eq!(perms.len(), 2);
    assert!(perms.contains(&"read:users".to_string()));
}

#[tokio::test]
async fn test_get_permissions_empty() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a
        .expect_get_permissions()
        .times(1)
        .return_once(|_| Ok(vec![]));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service.get_permissions(Uuid::new_v4()).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_get_permissions_repo_error_propagates() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a
        .expect_get_permissions()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Error".into())));

    let service = IdentityService::new(mock_i, mock_a);
    let result = service.get_permissions(Uuid::new_v4()).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_identity_uses_correct_tenant_id() {
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Should only be called with tenant_a, not tenant_b
    mock_i
        .expect_get()
        .with(eq(tenant_a), eq(IdentityHandle::Id(user_id)))
        .times(1)
        .return_once(|_, _| Ok(None));

    let service = IdentityService::new(mock_i, mock_a);
    // Even if tenant_b exists, we're querying with tenant_a
    let _ = service.get_identity(tenant_a, user_id).await;
    let _ = tenant_b; // suppress warning
}

#[tokio::test]
async fn test_change_password_new_hash_is_argon2() {
    // Verify the new hash is actually stored as argon2
    init_tracing();
    let mut mock_i = MockIdentityRepo::new();
    let mock_a = MockAuthRepo::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let old_pwd = "OldPassword123";
    let mut user = make_identity(tenant_id, Status::Active, old_pwd);
    user.id = user_id;

    mock_i
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(user)));

    mock_i
        .expect_update()
        .withf(|_, _, updates: &IdentityUpdates| {
            updates
                .password_hash
                .as_ref()
                .map(|h| h.starts_with("$argon2"))
                .unwrap_or(false)
        })
        .times(1)
        .returning(|_, _, _| Ok(dummy_identity()));

    let service = IdentityService::new(mock_i, mock_a);
    let req = ChangePasswordRequest {
        pool_id: tenant_id,
        identity_id: user_id,
        current_password: old_pwd.to_string(),
        new_password: "NewPassword456".to_string(),
    };

    let result = service.change_password(req).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// no-escalation rule
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cannot_grant_a_role_conferring_permissions_you_lack() {
    // Role assignment is reachable by anyone holding IdentityUpdate. Without
    // this rule an ordinary identity admin in the platform tenant could assign
    // themselves PlatformAdmin, turning a tenant-level permission into
    // deployment-level authority.
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a.expect_list_roles().returning(move |t| {
        Ok(vec![role_with(
            t,
            "PlatformAdmin",
            &["PlatformTenantCreate", "PlatformTenantList"],
        )])
    });
    // The grant must never reach the repository.
    mock_a.expect_assign_role().times(0);

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        role_name: "PlatformAdmin".to_string(),
    };

    let result = service
        .assign_role(req, &scopes(&["IdentityCreate", "IdentityUpdate"]))
        .await;
    assert!(
        matches!(result, Err(ServiceError::Forbidden)),
        "expected Forbidden, got {:?}",
        result
    );
}

#[tokio::test]
async fn test_partial_overlap_is_still_refused() {
    // Holding *some* of what a role confers is not enough — the missing one is
    // exactly the privilege that would be created out of nothing.
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a.expect_list_roles().returning(move |t| {
        Ok(vec![role_with(
            t,
            "TenantAdmin",
            &["TenantRead", "TenantDelete"],
        )])
    });
    mock_a.expect_assign_role().times(0);

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        role_name: "TenantAdmin".to_string(),
    };

    // Holds TenantRead but not TenantDelete.
    let result = service.assign_role(req, &scopes(&["TenantRead"])).await;
    assert!(matches!(result, Err(ServiceError::Forbidden)));
}

#[tokio::test]
async fn test_granting_an_unknown_role_is_a_validation_error() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a.expect_list_roles().returning(|_| Ok(vec![]));
    mock_a.expect_assign_role().times(0);

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        role_name: "NoSuchRole".to_string(),
    };

    let result = service.assign_role(req, &scopes(&["IdentityCreate"])).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_revocation_obeys_the_same_rule() {
    // Otherwise a lesser-privileged admin could strip authority from a greater
    // one — denial of service by demotion.
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a
        .expect_list_roles()
        .returning(move |t| Ok(vec![role_with(t, "ClientAdmin", &["ClientDelete"])]));
    mock_a.expect_remove_role().times(0);

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        role_name: "ClientAdmin".to_string(),
    };

    let result = service.revoke_role(req, &scopes(&["ClientRead"])).await;
    assert!(matches!(result, Err(ServiceError::Forbidden)));
}

#[tokio::test]
async fn test_a_role_conferring_nothing_is_always_grantable() {
    init_tracing();
    let mock_i = MockIdentityRepo::new();
    let mut mock_a = MockAuthRepo::new();

    mock_a
        .expect_list_roles()
        .returning(move |t| Ok(vec![role_with(t, "Empty", &[])]));
    mock_a
        .expect_assign_role()
        .times(1)
        .returning(|_, _, _| Ok(()));

    let service = IdentityService::new(mock_i, mock_a);
    let req = RoleAssignmentRequest {
        tenant_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        role_name: "Empty".to_string(),
    };

    assert!(service.assign_role(req, &scopes(&[])).await.is_ok());
}
