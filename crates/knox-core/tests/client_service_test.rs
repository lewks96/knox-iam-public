use async_trait::async_trait;
use knox_common::client::{Client, ClientFilter, ClientRepository, ClientType, ClientUpdates};
use knox_common::error::{RepositoryError, ServiceError};
use knox_common::identity::Status;
use knox_core::client::{ClientService, CreateClientRequest, UpdateClientRequest};
use mockall::{mock, predicate::*};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

fn make_stored_client(tenant_id: Uuid) -> Client {
    Client {
        id: Uuid::new_v4(),
        tenant_id,
        pool_id: Uuid::new_v4(),
        name: "stored-client".into(),
        description: None,
        logo_uri: None,
        client_type: ClientType::Confidential,
        client_secret_hash: Some("0".repeat(64)),
        token_endpoint_auth_method: "client_secret_basic".into(),
        allow_refresh_tokens: true,
        grant_types: vec!["authorization_code".into()],
        response_types: vec!["code".into()],
        redirect_uris: vec!["https://app.example.com/callback".into()],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".into()],
        require_pkce: false,
        require_auth_time: false,
        access_token_ttl: 3600,
        refresh_token_ttl: 2592000,
        id_token_ttl: 3600,
        auth_code_ttl: 600,
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

fn confidential_request(tenant_id: Uuid) -> CreateClientRequest {
    CreateClientRequest {
        tenant_id,
        pool_id: Uuid::new_v4(),
        name: "my-app".into(),
        description: None,
        logo_uri: None,
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "client_secret_basic".into(),
        allow_refresh_tokens: true,
        grant_types: vec!["authorization_code".into()],
        response_types: vec!["code".into()],
        redirect_uris: vec!["https://app.example.com/callback".into()],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".into(), "profile".into()],
        access_token_ttl: Some(3600),
        refresh_token_ttl: Some(864_000),
        id_token_ttl: Some(3600),
        auth_code_ttl: Some(600),
        token_version: Some(1),
    }
}

fn public_request(tenant_id: Uuid) -> CreateClientRequest {
    CreateClientRequest {
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".into(),
        ..confidential_request(tenant_id)
    }
}

fn is_sha256_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn empty_update() -> UpdateClientRequest {
    UpdateClientRequest {
        description: None,
        logo_uri: None,
        token_endpoint_auth_method: None,
        allow_refresh_tokens: None,
        grant_types: None,
        response_types: None,
        redirect_uris: None,
        post_logout_redirect_uris: None,
        allowed_scopes: None,
        require_pkce: None,
        access_token_ttl: None,
        refresh_token_ttl: None,
        id_token_ttl: None,
        auth_code_ttl: None,
        status: None,
    }
}

// ---------------------------------------------------------------------------
// create_client — validation tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_client_name_too_short_fails_validation() {
    init_tracing();
    let mut repo = MockClientRepo::new();
    repo.expect_create().times(0);

    let service = ClientService::new(repo);
    let mut req = confidential_request(Uuid::new_v4());
    req.name = "ab".into(); // min 3

    let result = service.create_client(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_client_name_too_long_fails_validation() {
    init_tracing();
    let mut repo = MockClientRepo::new();
    repo.expect_create().times(0);

    let service = ClientService::new(repo);
    let mut req = confidential_request(Uuid::new_v4());
    req.name = "a".repeat(101);

    let result = service.create_client(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_create_client_name_boundary_3_chars_is_valid() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();
    let client = make_stored_client(tenant_id);

    repo.expect_create()
        .times(1)
        .return_once(move |_| Ok(client));

    let service = ClientService::new(repo);
    let mut req = confidential_request(tenant_id);
    req.name = "abc".into();

    assert!(service.create_client(req).await.is_ok());
}

#[tokio::test]
async fn test_create_client_insecure_redirect_uri_rejected() {
    init_tracing();
    let mut repo = MockClientRepo::new();
    repo.expect_create().times(0);

    let service = ClientService::new(repo);
    let mut req = confidential_request(Uuid::new_v4());
    req.redirect_uris = vec!["http://app.example.com/callback".into()]; // http, not localhost

    let result = service.create_client(req).await;
    assert!(
        matches!(result, Err(ServiceError::Validation(ref msg)) if msg.contains("Insecure")),
        "Expected Insecure URI error, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_create_client_https_redirect_uri_allowed() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();
    let client = make_stored_client(tenant_id);
    repo.expect_create()
        .times(1)
        .return_once(move |_| Ok(client));

    let service = ClientService::new(repo);
    let mut req = confidential_request(tenant_id);
    req.redirect_uris = vec!["https://app.example.com/callback".into()];

    assert!(service.create_client(req).await.is_ok());
}

#[tokio::test]
async fn test_create_client_localhost_http_redirect_uri_allowed() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();
    let client = make_stored_client(tenant_id);
    repo.expect_create()
        .times(1)
        .return_once(move |_| Ok(client));

    let service = ClientService::new(repo);
    let mut req = confidential_request(tenant_id);
    req.redirect_uris = vec!["http://localhost:8080/callback".into()];

    assert!(service.create_client(req).await.is_ok());
}

#[tokio::test]
async fn test_create_client_loopback_ip_redirect_uri_allowed() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();
    let client = make_stored_client(tenant_id);
    repo.expect_create()
        .times(1)
        .return_once(move |_| Ok(client));

    let service = ClientService::new(repo);
    let mut req = confidential_request(tenant_id);
    req.redirect_uris = vec!["http://127.0.0.1:8080/callback".into()];

    assert!(service.create_client(req).await.is_ok());
}

#[tokio::test]
async fn test_create_client_one_insecure_uri_among_many_is_rejected() {
    init_tracing();
    let mut repo = MockClientRepo::new();
    repo.expect_create().times(0);

    let service = ClientService::new(repo);
    let mut req = confidential_request(Uuid::new_v4());
    req.redirect_uris = vec![
        "https://app.example.com/callback".into(),
        "http://evil.example.com/callback".into(), // this one is bad
    ];

    let result = service.create_client(req).await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

// ---------------------------------------------------------------------------
// create_client — confidential client behaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_confidential_client_generates_secret() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();
    let client = make_stored_client(tenant_id);
    repo.expect_create()
        .times(1)
        .return_once(move |_| Ok(client));

    let service = ClientService::new(repo);
    let result = service
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap();

    assert!(
        result.client_secret.is_some(),
        "Confidential client creation should return a plaintext secret"
    );
}

#[tokio::test]
async fn test_create_confidential_client_secret_is_40_chars() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();
    let client = make_stored_client(tenant_id);
    repo.expect_create()
        .times(1)
        .return_once(move |_| Ok(client));

    let service = ClientService::new(repo);
    let result = service
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap();

    let secret = result.client_secret.unwrap();
    assert_eq!(secret.len(), 64, "Generated secret should be 64 characters");
}

#[tokio::test]
async fn test_create_confidential_client_stores_sha256_hash() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    // Capture what the service passes to repo.create and verify the hash
    repo.expect_create()
        .withf(|c: &Client| {
            c.client_secret_hash
                .as_deref()
                .map(is_sha256_hash)
                .unwrap_or(false)
        })
        .times(1)
        .returning(|c| Ok(c.clone()));

    let service = ClientService::new(repo);
    service
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_confidential_client_secret_verifies_against_stored_hash() {
    // Verifies the plaintext secret returned actually matches the hash sent to the store
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    let _captured_hash: Option<String> = None;

    repo.expect_create()
        .withf(move |c: &Client| c.client_secret_hash.is_some())
        .times(1)
        .returning(|c| {
            // Return the client as-is so we can inspect the hash
            Ok(c.clone())
        });

    let service = ClientService::new(repo);
    let result = service
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap();

    let plaintext = result.client_secret.unwrap();
    let stored_hash_str = result.client.client_secret_hash.unwrap();
    let calculated_hash = hex::encode(Sha256::digest(plaintext.as_bytes()));
    assert_eq!(
        calculated_hash, stored_hash_str,
        "Returned plaintext secret should verify against the stored hash"
    );
}

#[tokio::test]
async fn test_create_confidential_client_each_secret_is_unique() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut repo1 = MockClientRepo::new();
    let c1 = make_stored_client(tenant_id);
    repo1.expect_create().times(1).return_once(move |_| Ok(c1));

    let mut repo2 = MockClientRepo::new();
    let c2 = make_stored_client(tenant_id);
    repo2.expect_create().times(1).return_once(move |_| Ok(c2));

    let s1 = ClientService::new(repo1)
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap()
        .client_secret
        .unwrap();

    let s2 = ClientService::new(repo2)
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap()
        .client_secret
        .unwrap();

    assert_ne!(s1, s2, "Each generated secret should be unique");
}

#[tokio::test]
async fn test_create_confidential_client_sets_require_pkce_false() {
    // Per the service logic: require_pkce = (client_type == Public)
    // Confidential clients do NOT require PKCE by default
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    repo.expect_create()
        .withf(|c: &Client| !c.require_pkce)
        .times(1)
        .returning(|c| Ok(c.clone()));

    let service = ClientService::new(repo);
    service
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// create_client — public client behaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_public_client_generates_no_secret() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();
    let mut client = make_stored_client(tenant_id);
    client.client_type = ClientType::Public;
    client.client_secret_hash = None;
    repo.expect_create()
        .times(1)
        .return_once(move |_| Ok(client));

    let service = ClientService::new(repo);
    let result = service
        .create_client(public_request(tenant_id))
        .await
        .unwrap();

    assert!(
        result.client_secret.is_none(),
        "Public client creation should NOT return a secret"
    );
}

#[tokio::test]
async fn test_create_public_client_stores_no_secret_hash() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    repo.expect_create()
        .withf(|c: &Client| c.client_secret_hash.is_none())
        .times(1)
        .returning(|c| Ok(c.clone()));

    let service = ClientService::new(repo);
    service
        .create_client(public_request(tenant_id))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_public_client_enforces_require_pkce() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    repo.expect_create()
        .withf(|c: &Client| c.require_pkce)
        .times(1)
        .returning(|c| Ok(c.clone()));

    let service = ClientService::new(repo);
    service
        .create_client(public_request(tenant_id))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// create_client — defaults
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_client_default_ttls() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    repo.expect_create()
        .withf(|c: &Client| {
            c.access_token_ttl == 3600
                && c.refresh_token_ttl == 864_000
                && c.id_token_ttl == 3600
                && c.auth_code_ttl == 600
        })
        .times(1)
        .returning(|c| Ok(c.clone()));

    let service = ClientService::new(repo);
    service
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_client_initial_token_version_is_1() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    repo.expect_create()
        .withf(|c: &Client| c.token_version == 1)
        .times(1)
        .returning(|c| Ok(c.clone()));

    let service = ClientService::new(repo);
    service
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_client_initial_status_is_active() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    repo.expect_create()
        .withf(|c: &Client| c.status == Status::Active)
        .times(1)
        .returning(|c| Ok(c.clone()));

    let service = ClientService::new(repo);
    service
        .create_client(confidential_request(tenant_id))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_client_repo_error_propagates() {
    init_tracing();
    let mut repo = MockClientRepo::new();

    repo.expect_create()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("DB down".into())));

    let service = ClientService::new(repo);
    let result = service
        .create_client(confidential_request(Uuid::new_v4()))
        .await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// get_client tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_client_found() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id);
    let id = client.id;
    let cloned = client.clone();
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    let service = ClientService::new(repo);
    let result = service.get_client(tenant_id, id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, id);
}

#[tokio::test]
async fn test_get_client_not_found_returns_validation_error() {
    init_tracing();
    let mut repo = MockClientRepo::new();

    repo.expect_get().times(1).return_once(|_, _| Ok(None));

    let service = ClientService::new(repo);
    let result = service.get_client(Uuid::new_v4(), Uuid::new_v4()).await;

    assert!(
        matches!(result, Err(ServiceError::Validation(ref msg)) if msg.contains("not found")),
        "Expected 'not found' error, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_get_client_repo_error_propagates() {
    init_tracing();
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Timeout".into())));

    let service = ClientService::new(repo);
    let result = service.get_client(Uuid::new_v4(), Uuid::new_v4()).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

#[tokio::test]
async fn test_authenticate_inactive_client_rejects_correct_secret() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let secret = "correct-client-secret";
    let mut client = make_stored_client(tenant_id);
    client.status = Status::Inactive;
    client.client_secret_hash = Some(hex::encode(Sha256::digest(secret.as_bytes())));
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    let service = ClientService::new(repo);
    let result = service.authenticate_client(tenant_id, id, secret).await;

    assert!(matches!(result, Err(ServiceError::InvalidCredentials)));
}

// ---------------------------------------------------------------------------
// update_client tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_client_description_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id);
    let mut updated = client.clone();
    updated.description = Some("new description".into());
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_update()
        .with(eq(tenant_id), eq(id), always())
        .times(1)
        .return_once(move |_, _, _| Ok(updated));

    let service = ClientService::new(repo);
    let req = UpdateClientRequest {
        description: Some("new description".into()),
        ..empty_update()
    };
    let result = service.update_client(tenant_id, id, req).await;

    assert!(result.is_ok());
    assert_eq!(
        result.unwrap().description.as_deref(),
        Some("new description")
    );
}

#[tokio::test]
async fn test_update_client_insecure_redirect_uri_rejected() {
    init_tracing();
    let mut repo = MockClientRepo::new();
    repo.expect_update().times(0);

    let service = ClientService::new(repo);
    let req = UpdateClientRequest {
        redirect_uris: Some(vec!["http://evil.example.com/callback".into()]),
        ..empty_update()
    };

    let result = service
        .update_client(Uuid::new_v4(), Uuid::new_v4(), req)
        .await;
    assert!(
        matches!(result, Err(ServiceError::Validation(ref msg)) if msg.contains("Insecure")),
        "Expected Insecure URI error, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_update_client_status_to_inactive() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id);
    let mut updated = client.clone();
    updated.status = Status::Inactive;
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));
    repo.expect_update()
        .withf(|_, _, updates: &ClientUpdates| {
            updates.status == Some(Status::Inactive) && updates.token_version == Some(2)
        })
        .times(1)
        .return_once(move |_, _, _| Ok(updated));

    let service = ClientService::new(repo);
    let req = UpdateClientRequest {
        status: Some(Status::Inactive),
        ..empty_update()
    };
    let result = service.update_client(tenant_id, id, req).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().status, Status::Inactive);
}

#[tokio::test]
async fn test_update_client_does_not_expose_secret_hash_fields() {
    // update_client must not allow callers to set client_secret_hash directly
    // (that only goes through rotate_client_secret). Verify the updates struct
    // passed to the repo has secret_hash as None.
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id);
    let cloned = client.clone();
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_update()
        .withf(|_, _, upd: &ClientUpdates| upd.client_secret_hash.is_none())
        .times(1)
        .return_once(move |_, _, _| Ok(cloned));

    let service = ClientService::new(repo);
    let req = UpdateClientRequest {
        description: Some("valid description".into()),
        ..empty_update()
    };
    let _ = service.update_client(tenant_id, id, req).await;
}

#[tokio::test]
async fn test_update_client_repo_error_propagates() {
    init_tracing();
    let mut repo = MockClientRepo::new();

    repo.expect_update()
        .times(1)
        .return_once(|_, _, _| Err(RepositoryError::Database("Store error".into())));

    let service = ClientService::new(repo);
    let req = UpdateClientRequest {
        description: Some("valid description".into()),
        ..empty_update()
    };
    let result = service
        .update_client(Uuid::new_v4(), Uuid::new_v4(), req)
        .await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// delete_client tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_client_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();
    let mut repo = MockClientRepo::new();

    repo.expect_delete()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));

    let service = ClientService::new(repo);
    let result = service.delete_client(tenant_id, id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_client_repo_error_propagates() {
    init_tracing();
    let mut repo = MockClientRepo::new();

    repo.expect_delete()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Cannot delete".into())));

    let service = ClientService::new(repo);
    let result = service.delete_client(Uuid::new_v4(), Uuid::new_v4()).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// list_clients tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_clients_returns_results() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let clients = vec![make_stored_client(tenant_id), make_stored_client(tenant_id)];
    let total = 2u64;
    let mut repo = MockClientRepo::new();

    repo.expect_list()
        .times(1)
        .return_once(move |_| Ok((clients, total)));

    let service = ClientService::new(repo);
    let filter = ClientFilter {
        tenant_id,
        page: 1,
        page_size: 10,
        status: None,
    };
    let result = service.list_clients(&filter).await;

    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_list_clients_repo_error_propagates() {
    init_tracing();
    let mut repo = MockClientRepo::new();

    repo.expect_list()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let service = ClientService::new(repo);
    let filter = ClientFilter {
        tenant_id: Uuid::new_v4(),
        page: 1,
        page_size: 10,
        status: None,
    };
    let result = service.list_clients(&filter).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// rotate_token_version tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rotate_token_version_increments_by_one() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id); // token_version = 1
    let mut bumped = client.clone();
    bumped.token_version = 2;
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    repo.expect_update()
        .withf(|_, _, upd: &ClientUpdates| upd.token_version == Some(2))
        .times(1)
        .return_once(move |_, _, _| Ok(bumped));

    let service = ClientService::new(repo);
    let result = service.rotate_token_version(tenant_id, id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().token_version, 2);
}

#[tokio::test]
async fn test_rotate_token_version_from_version_5() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut client = make_stored_client(tenant_id);
    client.token_version = 5;
    let mut bumped = client.clone();
    bumped.token_version = 6;
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    repo.expect_update()
        .withf(|_, _, upd: &ClientUpdates| upd.token_version == Some(6))
        .times(1)
        .return_once(move |_, _, _| Ok(bumped));

    let service = ClientService::new(repo);
    let result = service.rotate_token_version(tenant_id, id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().token_version, 6);
}

#[tokio::test]
async fn test_rotate_token_version_client_not_found() {
    init_tracing();
    let mut repo = MockClientRepo::new();

    repo.expect_get().times(1).return_once(|_, _| Ok(None));

    repo.expect_update().times(0);

    let service = ClientService::new(repo);
    let result = service
        .rotate_token_version(Uuid::new_v4(), Uuid::new_v4())
        .await;

    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_rotate_token_version_repo_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id);
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    repo.expect_update()
        .times(1)
        .return_once(|_, _, _| Err(RepositoryError::Database("Store error".into())));

    let service = ClientService::new(repo);
    let result = service.rotate_token_version(tenant_id, id).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

// ---------------------------------------------------------------------------
// rotate_client_secret tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rotate_client_secret_returns_new_plaintext_secret() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id);
    let mut rotated = client.clone();
    rotated.client_secret_hash = Some("$argon2id$new_hash".into());
    rotated.token_version = 2;
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    repo.expect_update()
        .times(1)
        .return_once(move |_, _, _| Ok(rotated));

    let service = ClientService::new(repo);
    let result = service.rotate_client_secret(tenant_id, id).await.unwrap();

    assert!(
        result.client_secret.is_some(),
        "Rotation should return a new plaintext secret"
    );
    let secret = result.client_secret.unwrap();
    assert_eq!(secret.len(), 64, "Rotated secret should be 64 chars");
}

#[tokio::test]
async fn test_rotate_client_secret_also_bumps_token_version() {
    // Rotating the secret must invalidate existing tokens by bumping version
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id); // token_version = 1
    let id = client.id;
    let mut rotated = client.clone();
    rotated.token_version = 2;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    repo.expect_update()
        .withf(|_, _, upd: &ClientUpdates| {
            upd.client_secret_hash.is_some() && upd.token_version == Some(2)
        })
        .times(1)
        .return_once(move |_, _, _| Ok(rotated));

    let service = ClientService::new(repo);
    service.rotate_client_secret(tenant_id, id).await.unwrap();
}

#[tokio::test]
async fn test_rotate_client_secret_stores_sha256_hash() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id);
    let rotated = client.clone();
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    repo.expect_update()
        .withf(|_, _, upd: &ClientUpdates| {
            upd.client_secret_hash
                .as_deref()
                .map(is_sha256_hash)
                .unwrap_or(false)
        })
        .times(1)
        .return_once(move |_, _, _| Ok(rotated));

    let service = ClientService::new(repo);
    service.rotate_client_secret(tenant_id, id).await.unwrap();
}

#[tokio::test]
async fn test_rotate_client_secret_public_client_rejected() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut client = make_stored_client(tenant_id);
    client.client_type = ClientType::Public;
    client.client_secret_hash = None;
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    repo.expect_update().times(0);

    let service = ClientService::new(repo);
    let result = service.rotate_client_secret(tenant_id, id).await;

    assert!(
        matches!(result, Err(ServiceError::Validation(ref msg)) if msg.contains("public")),
        "Expected error mentioning 'public', got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_rotate_client_secret_client_not_found() {
    init_tracing();
    let mut repo = MockClientRepo::new();

    repo.expect_get().times(1).return_once(|_, _| Ok(None));

    repo.expect_update().times(0);

    let service = ClientService::new(repo);
    let result = service
        .rotate_client_secret(Uuid::new_v4(), Uuid::new_v4())
        .await;

    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

#[tokio::test]
async fn test_rotate_client_secret_repo_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_stored_client(tenant_id);
    let id = client.id;
    let mut repo = MockClientRepo::new();

    repo.expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client)));

    repo.expect_update()
        .times(1)
        .return_once(|_, _, _| Err(RepositoryError::Database("Store error".into())));

    let service = ClientService::new(repo);
    let result = service.rotate_client_secret(tenant_id, id).await;

    assert!(matches!(result, Err(ServiceError::Repository(_))));
}

#[tokio::test]
async fn test_rotate_client_secret_new_secret_differs_from_previous() {
    // Two consecutive rotations should produce different secrets
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let client1 = make_stored_client(tenant_id);
    let rotated1 = client1.clone();
    let id = client1.id;
    let mut repo1 = MockClientRepo::new();
    repo1
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client1)));
    repo1
        .expect_update()
        .times(1)
        .return_once(move |_, _, _| Ok(rotated1));

    let client2 = make_stored_client(tenant_id);
    let rotated2 = client2.clone();
    let mut repo2 = MockClientRepo::new();
    repo2
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(client2)));
    repo2
        .expect_update()
        .times(1)
        .return_once(move |_, _, _| Ok(rotated2));

    let secret1 = ClientService::new(repo1)
        .rotate_client_secret(tenant_id, id)
        .await
        .unwrap()
        .client_secret
        .unwrap();

    let secret2 = ClientService::new(repo2)
        .rotate_client_secret(tenant_id, id)
        .await
        .unwrap()
        .client_secret
        .unwrap();

    assert_ne!(
        secret1, secret2,
        "Each rotation should produce a unique secret"
    );
}
