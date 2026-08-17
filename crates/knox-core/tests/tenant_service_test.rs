use async_trait::async_trait;
use knox_common::authorization::{AuthorizationRepository, Role, RoleKind};
use knox_common::client::{Client, ClientFilter, ClientRepository, ClientType, ClientUpdates};
use knox_common::error::{RepositoryError, ServiceError};
use knox_common::identity::{
    Identity, IdentityFilter, IdentityHandle, IdentityRepository, IdentityUpdates, Status,
};
use knox_common::key::{
    CreateKeyParams, KeyEncryptionError, KeyEncryptionProvider, KeyRepository, KeyState, TenantKey,
};
use knox_common::pool::{CreatePool, IdentityPool, PoolRepository};
use knox_common::tenant::{Tenant, TenantConfiguration, TenantRepository, TenantUpdates};
use knox_core::client::ClientService;
use knox_core::identity::IdentityService;
use knox_core::key::KeyService;
use knox_core::roles::{admin_tenant_role, basic_user_role, identity_admin_role};
use knox_core::tenant::{
    CreateTenantRequest, IssuerConfig, TenantSearchRequest, TenantService, UpdateTenantRequest,
};
use mockall::{mock, predicate::*};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

mock! {
    pub TenantRepo {}
    #[async_trait]
    impl TenantRepository for TenantRepo {
        async fn create(&self, name: &str, slug: &str, issuer: &str, description: Option<String>, is_platform: bool) -> Result<Tenant, RepositoryError>;
        async fn get(&self, id: Uuid) -> Result<Option<Tenant>, RepositoryError>;
        async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, RepositoryError>;
        async fn update(&self, id: Uuid, updates: &TenantUpdates) -> Result<Tenant, RepositoryError>;
        async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
        async fn list(&self, page: u32, page_size: u32) -> Result<(Vec<Tenant>, u64), RepositoryError>;
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
        async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, RepositoryError>;
        async fn get_identity_roles(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
        async fn get_permissions(&self, identity_id: Uuid) -> Result<Vec<String>, RepositoryError>;
    }
}

mock! {
    pub KeyRepo {}
    #[async_trait]
    impl KeyRepository for KeyRepo {
        async fn create(&self, params: CreateKeyParams) -> Result<TenantKey, RepositoryError>;
        async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
        async fn get_by_kid(&self, tenant_id: Uuid, kid: &str) -> Result<Option<TenantKey>, RepositoryError>;
        async fn get_active_for_tenant(&self, tenant_id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
        async fn list_for_jwks(&self, tenant_id: Uuid) -> Result<Vec<TenantKey>, RepositoryError>;
        async fn list(&self, tenant_id: Uuid, page: u32, page_size: u32) -> Result<(Vec<TenantKey>, u64), RepositoryError>;
        async fn update_state(&self, id: Uuid, new_state: KeyState) -> Result<TenantKey, RepositoryError>;
        async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
        async fn revoke_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
    }
}

mock! {
    pub ClientRepo {}
    #[async_trait]
    impl ClientRepository for ClientRepo {
        async fn create(&self, client: &Client) -> Result<Client, RepositoryError>;
        async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError>;
        async fn get_by_name(&self, tenant_id: Uuid, name: &str) -> Result<Option<Client>, RepositoryError>;
        async fn update(&self, tenant_id: Uuid, id: Uuid, updates: &ClientUpdates) -> Result<Client, RepositoryError>;
        async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
        async fn list(&self, filter: &ClientFilter) -> Result<(Vec<Client>, u64), RepositoryError>;
    }
}

mock! {
    pub IdentityRepo {}
    #[async_trait]
    impl IdentityRepository for IdentityRepo {
        async fn create(&self, identity: &Identity) -> Result<Identity, RepositoryError>;
        async fn get(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<Option<Identity>, RepositoryError>;
        async fn delete(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<(), RepositoryError>;
        async fn update(&self, pool_id: Uuid, handle: IdentityHandle, updates: &IdentityUpdates) -> Result<Identity, RepositoryError>;
        async fn exists(&self, pool_id: Uuid, handle: IdentityHandle) -> Result<bool, RepositoryError>;
        async fn list(&self, filter: IdentityFilter) -> Result<(Vec<Identity>, u64), RepositoryError>;
        async fn count(&self, tenant_id: Uuid, filter: Option<String>) -> Result<u64, RepositoryError>;
    }
}

mock! {
    pub PoolRepo {}
    #[async_trait]
    impl PoolRepository for PoolRepo {
        async fn create(&self, pool: &CreatePool) -> Result<IdentityPool, RepositoryError>;
        async fn get(&self, id: Uuid) -> Result<Option<IdentityPool>, RepositoryError>;
        async fn get_in_tenant(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<IdentityPool>, RepositoryError>;
        async fn get_by_slug(&self, tenant_id: Uuid, slug: &str) -> Result<Option<IdentityPool>, RepositoryError>;
        async fn get_staff_pool(&self, tenant_id: Uuid) -> Result<Option<IdentityPool>, RepositoryError>;
        async fn list(&self, tenant_id: Uuid) -> Result<Vec<IdentityPool>, RepositoryError>;
        async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
    }
}

#[derive(Clone)]
struct MockKmsProvider;

#[async_trait]
impl KeyEncryptionProvider for MockKmsProvider {
    async fn encrypt(
        &self,
        _plaintext: &str,
        _context: Option<&[u8]>,
    ) -> Result<Vec<u8>, KeyEncryptionError> {
        Ok(vec![1, 2, 3, 4, 5])
    }

    async fn decrypt(
        &self,
        _encrypted: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<String, KeyEncryptionError> {
        Ok("decrypted_key".to_string())
    }

    fn provider_id(&self) -> &str {
        "mock-kms"
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

fn make_auth_repo() -> MockAuthRepo {
    let mut auth_repo = MockAuthRepo::new();
    // By default allow any number of create_role calls (used by create_tenant)
    auth_repo.expect_create_role().returning(|_, _, _, _| {
        Ok(Role {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "default".into(),
            permissions: vec![],
            description: None,
            kind: RoleKind::System,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        })
    });
    auth_repo
}

fn make_key_repo() -> MockKeyRepo {
    let mut key_repo = MockKeyRepo::new();
    // By default, create returns a new TenantKey
    key_repo.expect_create().returning(|params| {
        Ok(TenantKey {
            id: Uuid::new_v4(),
            tenant_id: params.tenant_id,
            kid: params.kid,
            use_type: params.use_type,
            kty: params.kty,
            alg: params.alg,
            public_key_pem: params.public_key_pem,
            x509_cert_pem: params.x509_cert_pem,
            encrypted_private_key: params.encrypted_private_key,
            state: KeyState::Active,
            created_at: OffsetDateTime::now_utc(),
            expires_at: params.expires_at,
        })
    });
    key_repo
}

fn make_client_repo() -> MockClientRepo {
    let mut client_repo = MockClientRepo::new();
    // By default, create returns the client with generated values
    client_repo
        .expect_create()
        .returning(|client| Ok(client.clone()));
    client_repo
}

fn make_pool_repo() -> MockPoolRepo {
    let mut pool_repo = MockPoolRepo::new();
    pool_repo.expect_create().returning(|request| {
        Ok(IdentityPool {
            id: Uuid::new_v4(),
            tenant_id: request.tenant_id,
            slug: request.slug.clone(),
            name: request.name.clone(),
            kind: request.kind,
            description: request.description.clone(),
            config: serde_json::json!({}),
            status: Status::Active,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        })
    });
    pool_repo
}

#[allow(dead_code)]
fn make_client(tenant_id: Uuid) -> Client {
    Client {
        id: Uuid::new_v4(),
        tenant_id,
        pool_id: Uuid::new_v4(),
        name: "management".to_string(),
        description: Some("Auto-provisioned M2M client".into()),
        logo_uri: None,
        client_type: ClientType::Confidential,
        client_secret_hash: Some("hash".into()),
        token_endpoint_auth_method: "client_secret_basic".into(),
        allow_refresh_tokens: false,
        grant_types: vec!["client_credentials".into()],
        response_types: vec![],
        redirect_uris: vec![],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["admin".into()],
        require_pkce: false,
        require_auth_time: false,
        access_token_ttl: 3600,
        refresh_token_ttl: 86400,
        id_token_ttl: 3600,
        auth_code_ttl: 300,
        token_version: 1,
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
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

fn make_service(
    tenant_repo: MockTenantRepo,
    auth_repo: MockAuthRepo,
    key_repo: MockKeyRepo,
    client_repo: MockClientRepo,
) -> TenantService<
    MockTenantRepo,
    MockAuthRepo,
    MockKeyRepo,
    MockKmsProvider,
    MockClientRepo,
    MockIdentityRepo,
    MockPoolRepo,
> {
    let key_service = KeyService::new(key_repo, MockKmsProvider);
    let client_service = ClientService::new(client_repo);
    let identity_service = IdentityService::new(MockIdentityRepo::new(), make_auth_repo());
    TenantService::new(
        tenant_repo,
        make_pool_repo(),
        auth_repo,
        key_service,
        client_service,
        identity_service,
        IssuerConfig {
            scheme: "https".into(),
            base_domain: "example.test".into(),
            port: None,
        },
    )
}

fn make_tenant(name: &str) -> Tenant {
    Tenant {
        id: Uuid::new_v4(),
        name: name.to_string(),
        slug: "acme".into(),
        issuer: "https://acme.example.test".into(),
        description: None,
        is_platform: false,
        status: Status::Active,
        config: TenantConfiguration::default(),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

// ---------------------------------------------------------------------------
// create_tenant tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_tenant_success() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_create()
        .with(
            eq("Acme Corp"),
            eq("acme"),
            eq("https://acme.example.test"),
            eq(None),
            eq(false),
        )
        .times(1)
        .return_once(|name, _, _, _, _| Ok(make_tenant(name)));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "Acme Corp".into(),
        slug: "acme".into(),
        description: None,
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.tenant.name, "Acme Corp");
    // Admin client secret should be returned
    assert!(response.admin_client_secret.is_some());
}

#[tokio::test]
async fn test_create_tenant_with_description() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_create()
        .with(
            eq("Acme Corp"),
            eq("acme"),
            eq("https://acme.example.test"),
            eq(Some("A fine company".to_string())),
            eq(false),
        )
        .times(1)
        .return_once(|name, _, _, desc, _| {
            let mut t = make_tenant(name);
            t.description = desc;
            Ok(t)
        });

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "Acme Corp".into(),
        slug: "acme".into(),
        description: Some("A fine company".into()),
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap().tenant.description,
        Some("A fine company".into())
    );
}

#[tokio::test]
async fn test_create_tenant_name_too_short_fails_validation() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_create().times(0);

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "ab".into(), // min 3
        slug: "acme".into(),
        description: None,
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_tenant_name_too_long_fails_validation() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_create().times(0);

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "a".repeat(101), // max 100
        slug: "acme".into(),
        description: None,
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_tenant_name_exactly_3_chars_is_valid() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_create()
        .times(1)
        .return_once(|name, _, _, _, _| Ok(make_tenant(name)));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "abc".into(),
        slug: "acme".into(),
        description: None,
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_tenant_name_exactly_100_chars_is_valid() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_create()
        .times(1)
        .return_once(|name, _, _, _, _| Ok(make_tenant(name)));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "a".repeat(100),
        slug: "acme".into(),
        description: None,
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_tenant_description_too_long_fails_validation() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_create().times(0);

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "Valid Name".into(),
        slug: "acme".into(),
        description: Some("x".repeat(501)), // max 500
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_tenant_reserved_name_admin_rejected() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_create().times(0);

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "admin".into(),
        slug: "admin".into(),
        description: None,
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(
        matches!(result, Err(ServiceError::Validation(ref msg)) if msg.contains("reserved")),
        "Expected Reserved validation error, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_create_tenant_reserved_name_admin_case_insensitive() {
    init_tracing();
    for variant in &["ADMIN", "Admin", "aDmIn"] {
        let mut repo = MockTenantRepo::new();
        repo.expect_create().times(0);

        let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
        let req = CreateTenantRequest {
            name: variant.to_string(),
            slug: variant.to_ascii_lowercase(),
            description: None,
            ..Default::default()
        };

        let result = service.create_tenant(req).await;
        assert!(
            matches!(result, Err(ServiceError::Validation(_))),
            "Expected Validation error for reserved name '{}', got: {:?}",
            variant,
            result
        );
    }
}

#[tokio::test]
async fn test_create_tenant_reserved_name_knox_rejected() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_create().times(0);

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "knox".into(),
        slug: "knox".into(),
        description: None,
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_tenant_reserved_name_knox_case_insensitive() {
    init_tracing();
    for variant in &["KNOX", "Knox", "kNoX"] {
        let mut repo = MockTenantRepo::new();
        repo.expect_create().times(0);

        let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
        let req = CreateTenantRequest {
            name: variant.to_string(),
            slug: variant.to_ascii_lowercase(),
            description: None,
            ..Default::default()
        };

        let result = service.create_tenant(req).await;
        assert!(
            matches!(result, Err(ServiceError::Validation(_))),
            "Expected Validation error for reserved name '{}', got: {:?}",
            variant,
            result
        );
    }
}

#[tokio::test]
async fn test_create_tenant_name_containing_reserved_word_is_allowed() {
    // "adminacme" or "knox-corp" should NOT be rejected — only exact matches
    init_tracing();
    for name in &["adminacme", "knox-corp", "my-admin", "theknox"] {
        let mut repo = MockTenantRepo::new();
        repo.expect_create()
            .times(1)
            .return_once(|n, _, _, _, _| Ok(make_tenant(n)));

        let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
        let req = CreateTenantRequest {
            name: name.to_string(),
            slug: name.to_string(),
            description: None,
            ..Default::default()
        };

        let result = service.create_tenant(req).await;
        assert!(
            result.is_ok(),
            "Name '{}' should be allowed but was rejected: {:?}",
            name,
            result
        );
    }
}

#[tokio::test]
async fn test_create_tenant_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_create()
        .times(1)
        .return_once(|_, _, _, _, _| Err(RepositoryError::Database("DB down".into())));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "Valid Corp".into(),
        slug: "acme".into(),
        description: None,
        ..Default::default()
    };

    let result = service.create_tenant(req).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

#[tokio::test]
async fn test_create_tenant_seeds_default_roles() {
    // An ordinary tenant seeds eight system roles.
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_create()
        .times(1)
        .return_once(|n, _, _, _, _| Ok(make_tenant(n)));

    let expected_names: Vec<&str> = vec![
        "IdentitySelf",
        "IdentityViewer",
        "IdentityCreator",
        "IdentityAdmin",
        "TenantReader",
        "TenantAdmin",
        "ClientAdmin",
        "AuditViewer",
    ];

    let mut auth_repo = MockAuthRepo::new();
    auth_repo
        .expect_create_role()
        .withf(|_, _, _, kind: &RoleKind| *kind == RoleKind::System)
        .times(8)
        .returning(|tid, name, _, kind| {
            Ok(Role {
                id: Uuid::new_v4(),
                tenant_id: tid,
                name: name.to_string(),
                description: None,
                permissions: vec![],
                kind,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })
        });

    let service = make_service(repo, auth_repo, make_key_repo(), make_client_repo());
    let req = CreateTenantRequest {
        name: "Seeded Corp".into(),
        slug: "acme".into(),
        description: None,
        ..Default::default()
    };
    let result = service.create_tenant(req).await;

    assert!(
        result.is_ok(),
        "create_tenant should succeed when auth_repo succeeds: {:?}",
        result
    );
    // Verify the role names are what the service defines (pure, no repo needed)
    assert_eq!(basic_user_role().name(), "IdentitySelf");
    assert_eq!(identity_admin_role().name(), "IdentityAdmin");
    assert_eq!(admin_tenant_role().name(), "TenantAdmin");
    let _ = expected_names; // documents the expected set
}

// TODO: Fix this
//#[tokio::test]
//async fn test_create_tenant_auth_repo_error_propagates() {
//    init_tracing();
//    let mut repo = MockTenantRepo::new();
//    repo.expect_create()
//        .times(1)
//        .return_once(|n, _, _, _, _| Ok(make_tenant(n)));
//
//    let mut auth_repo = MockAuthRepo::new();
//    auth_repo
//        .expect_create_role()
//        .times(2)
//        .return_once(|_, _, _, _| Err(RepositoryError::Database("Auth DB down".into())));
//
//    let service = TenantService::new(repo, auth_repo);
//    let req = CreateTenantRequest {
//        name: "Failing Corp".into(),
//        description: None,
//    };
//    let result = service.create_tenant(req).await;
//
//    assert!(matches!(result, Err(ServiceError::Repository(_))));
//}

// ---------------------------------------------------------------------------
// get_tenant tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_tenant_found() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    let tenant = make_tenant("Found Corp");
    let id = tenant.id;
    let cloned = tenant.clone();

    repo.expect_get()
        .with(eq(id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let result = service.get_tenant(id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, id);
}

#[tokio::test]
async fn test_get_tenant_not_found_returns_validation_error() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_get().times(1).return_once(|_| Ok(None));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let result = service.get_tenant(Uuid::new_v4()).await;

    assert!(
        matches!(result, Err(ServiceError::Validation(ref msg)) if msg.contains("not found")),
        "Expected 'not found' validation error, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_get_tenant_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Timeout".into())));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let result = service.get_tenant(Uuid::new_v4()).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// update_tenant tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_tenant_name_success() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    let id = Uuid::new_v4();
    let mut updated = make_tenant("Updated Corp");
    updated.id = id;

    repo.expect_update()
        .with(eq(id), always())
        .times(1)
        .return_once(move |_, _| Ok(updated));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = UpdateTenantRequest {
        name: Some("Updated Corp".into()),
        description: None,
        status: None,
    };

    let result = service.update_tenant(id, req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().name, "Updated Corp");
}

#[tokio::test]
async fn test_update_tenant_status() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    let id = Uuid::new_v4();
    let mut updated = make_tenant("Corp");
    updated.status = Status::Suspended;

    repo.expect_update()
        .times(1)
        .return_once(move |_, _| Ok(updated));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = UpdateTenantRequest {
        name: None,
        description: None,
        status: Some(Status::Suspended),
    };

    let result = service.update_tenant(id, req).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().status, Status::Suspended);
}

#[tokio::test]
async fn test_update_tenant_name_too_short_fails_validation() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_update().times(0);

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = UpdateTenantRequest {
        name: Some("ab".into()), // min 3
        description: None,
        status: None,
    };

    let result = service.update_tenant(Uuid::new_v4(), req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_update_tenant_name_too_long_fails_validation() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_update().times(0);

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = UpdateTenantRequest {
        name: Some("a".repeat(101)),
        description: None,
        status: None,
    };

    let result = service.update_tenant(Uuid::new_v4(), req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_update_tenant_description_too_long_fails_validation() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    repo.expect_update().times(0);

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = UpdateTenantRequest {
        name: None,
        description: Some("x".repeat(501)),
        status: None,
    };

    let result = service.update_tenant(Uuid::new_v4(), req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_update_tenant_all_none_fields_is_valid() {
    // All optional fields being None is valid — it's a no-op update
    init_tracing();
    let mut repo = MockTenantRepo::new();
    let tenant = make_tenant("Corp");

    repo.expect_update()
        .times(1)
        .return_once(move |_, _| Ok(tenant));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = UpdateTenantRequest {
        name: None,
        description: None,
        status: None,
    };

    let result = service.update_tenant(Uuid::new_v4(), req).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_update_tenant_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_update()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = UpdateTenantRequest {
        name: Some("Valid Name".into()),
        description: None,
        status: None,
    };

    let result = service.update_tenant(Uuid::new_v4(), req).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// delete_tenant tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_tenant_success() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    let id = Uuid::new_v4();

    repo.expect_delete()
        .with(eq(id))
        .times(1)
        .returning(|_| Ok(()));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let result = service.delete_tenant(id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_tenant_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_delete()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Cannot delete".into())));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let result = service.delete_tenant(Uuid::new_v4()).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// list_tenants tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_tenants_returns_results() {
    init_tracing();
    let mut repo = MockTenantRepo::new();
    let tenants = vec![make_tenant("Corp A"), make_tenant("Corp B")];
    let total = 2u64;

    repo.expect_list()
        .with(eq(1u32), eq(10u32))
        .times(1)
        .return_once(move |_, _| Ok((tenants, total)));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = TenantSearchRequest {
        page: 1,
        page_size: 10,
    };

    let result = service.list_tenants(req).await;
    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_list_tenants_empty() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_list()
        .times(1)
        .return_once(|_, _| Ok((vec![], 0)));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = TenantSearchRequest {
        page: 1,
        page_size: 10,
    };

    let result = service.list_tenants(req).await;
    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert!(list.is_empty());
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_list_tenants_passes_correct_page_args() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_list()
        .with(eq(3u32), eq(25u32))
        .times(1)
        .return_once(|_, _| Ok((vec![], 0)));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = TenantSearchRequest {
        page: 3,
        page_size: 25,
    };

    let _ = service.list_tenants(req).await;
}

#[tokio::test]
async fn test_list_tenants_repo_error_propagates() {
    init_tracing();
    let mut repo = MockTenantRepo::new();

    repo.expect_list()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    let service = make_service(repo, make_auth_repo(), make_key_repo(), make_client_repo());
    let req = TenantSearchRequest {
        page: 1,
        page_size: 10,
    };

    let result = service.list_tenants(req).await;
    assert!(matches!(result, Err(ServiceError::Repository(_))));
}
