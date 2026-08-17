use async_trait::async_trait;
use knox_common::client::{Client, ClientFilter, ClientRepository, ClientType, ClientUpdates};
use knox_common::error::RepositoryError;
use knox_common::identity::Status;
use knox_storage::client::cache::ClientCache;
use knox_storage::client::repository::KnoxClientRepository;
use knox_storage::client::store::ClientStore;
use mockall::{mock, predicate::*};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks — implement the real traits from knox_storage
// ---------------------------------------------------------------------------

mock! {
    pub ClientStore {}
    #[async_trait]
    impl ClientStore for ClientStore {
        async fn create(&self, client: &Client) -> Result<Client, RepositoryError>;
        async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError>;
        async fn get_by_name(&self, tenant_id: Uuid, name: &str) -> Result<Option<Client>, RepositoryError>;
        async fn update(&self, tenant_id: Uuid, id: Uuid, updates: &ClientUpdates) -> Result<Client, RepositoryError>;
        async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
        async fn list(&self, filter: &ClientFilter) -> Result<(Vec<Client>, u64), RepositoryError>;
    }
}

mock! {
    pub ClientCache {}
    #[async_trait]
    impl ClientCache for ClientCache {
        async fn set(&self, client: &Client) -> Result<(), RepositoryError>;
        async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<Client>, RepositoryError>;
        async fn get_by_name(&self, tenant_id: Uuid, name: &str) -> Result<Option<Client>, RepositoryError>;
        async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;
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

fn make_client(tenant_id: Uuid) -> Client {
    Client {
        id: Uuid::new_v4(),
        tenant_id,
        pool_id: Uuid::new_v4(),
        name: format!("client_{}", Uuid::new_v4()),
        description: Some("A test client".into()),
        logo_uri: None,
        client_type: ClientType::Confidential,
        client_secret_hash: Some("$argon2id$...".into()),
        token_endpoint_auth_method: "client_secret_basic".into(),
        allow_refresh_tokens: true,
        grant_types: vec!["authorization_code".into()],
        response_types: vec!["code".into()],
        redirect_uris: vec!["https://app.example.com/callback".into()],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".into(), "profile".into()],
        require_pkce: true,
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

fn make_public_client(tenant_id: Uuid) -> Client {
    Client {
        client_type: ClientType::Public,
        client_secret_hash: None,
        token_endpoint_auth_method: "none".into(),
        require_pkce: true, // public clients must use PKCE
        ..make_client(tenant_id)
    }
}

fn make_repo(
    store: MockClientStore,
    cache: MockClientCache,
) -> KnoxClientRepository<MockClientStore, MockClientCache> {
    KnoxClientRepository::new(store, cache)
}

// ---------------------------------------------------------------------------
// create tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_persists_to_store_and_warms_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let cloned = client.clone();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.create(&client).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, client.id);
}

#[tokio::test]
async fn test_create_store_error_does_not_call_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("DB write failed".into())));

    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    let result = repo.create(&client).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_create_cache_failure_is_non_fatal() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let cloned = client.clone();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo.create(&client).await;

    assert!(
        result.is_ok(),
        "Cache failure on create should not fail the operation"
    );
}

#[tokio::test]
async fn test_create_public_client() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_public_client(tenant_id);
    let cloned = client.clone();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.create(&client).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().client_type, ClientType::Public);
}

// ---------------------------------------------------------------------------
// get tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_cache_hit_does_not_call_store() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let cloned = client.clone();
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    cache
        .expect_get()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    store.expect_get().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(tenant_id, id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, id);
}

#[tokio::test]
async fn test_get_cache_miss_falls_back_to_store_and_backfills() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let cloned = client.clone();
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    cache
        .expect_get()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .return_once(|_, _| Ok(None));

    store
        .expect_get()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.get(tenant_id, id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, id);
}

#[tokio::test]
async fn test_get_cache_miss_store_returns_none() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    cache.expect_get().times(1).return_once(|_, _| Ok(None));

    store.expect_get().times(1).return_once(|_, _| Ok(None));

    // No backfill when store returns None
    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(tenant_id, id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_cache_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    cache
        .expect_get()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Cache error".into())));

    store.expect_get().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(tenant_id, id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_get_store_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    cache.expect_get().times(1).return_once(|_, _| Ok(None));

    store
        .expect_get()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    let result = repo.get(tenant_id, id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_get_store_fallback_backfill_failure_is_non_fatal() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let cloned = client.clone();
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    cache.expect_get().times(1).return_once(|_, _| Ok(None));

    store
        .expect_get()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo.get(tenant_id, id).await;

    assert!(result.is_ok(), "Backfill failure should not fail the get");
    assert_eq!(result.unwrap().unwrap().id, id);
}

#[tokio::test]
async fn test_get_uses_correct_tenant_id_for_cache_lookup() {
    init_tracing();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    // Only tenant_a's cache should be queried
    cache
        .expect_get()
        .with(eq(tenant_a), eq(id))
        .times(1)
        .return_once(|_, _| Ok(None));

    store
        .expect_get()
        .with(eq(tenant_a), eq(id))
        .times(1)
        .return_once(|_, _| Ok(None));

    let repo = make_repo(store, cache);
    let _ = repo.get(tenant_a, id).await;
    let _ = tenant_b; // never used — proves isolation
}

// ---------------------------------------------------------------------------
// update tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_calls_store_and_refreshes_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let mut updated = client.clone();
    updated.description = Some("Updated client".into());
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_update()
        .with(eq(tenant_id), eq(id), always())
        .times(1)
        .return_once(move |_, _, _| Ok(updated));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = ClientUpdates {
        description: Some("Updated client".into()),
        ..Default::default()
    };
    let result = repo.update(tenant_id, id, &updates).await;

    assert!(result.is_ok());
    assert_eq!(
        result.unwrap().description.as_deref(),
        Some("Updated client")
    );
}

#[tokio::test]
async fn test_update_store_error_does_not_touch_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(|_, _, _| Err(RepositoryError::Database("Store error".into())));

    cache.expect_set().times(0);
    cache.expect_delete().times(0);

    let repo = make_repo(store, cache);
    let result = repo.update(tenant_id, id, &ClientUpdates::default()).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_update_cache_failure_is_non_fatal() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let updated = client.clone();
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(move |_, _, _| Ok(updated));

    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis write failed".into())));

    let repo = make_repo(store, cache);
    let result = repo.update(tenant_id, id, &ClientUpdates::default()).await;

    assert!(result.is_ok(), "Cache set failure should not fail update");
}

#[tokio::test]
async fn test_update_status_to_inactive() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let mut updated = client.clone();
    updated.status = Status::Inactive;
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(move |_, _, _| Ok(updated));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = ClientUpdates {
        status: Some(Status::Inactive),
        ..Default::default()
    };
    let result = repo.update(tenant_id, id, &updates).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().status, Status::Inactive);
}

#[tokio::test]
async fn test_update_secret_hash() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let mut updated = client.clone();
    updated.client_secret_hash = Some("$argon2id$new_hash".into());
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_update()
        .withf(|_, _, upd: &ClientUpdates| upd.client_secret_hash.is_some())
        .times(1)
        .return_once(move |_, _, _| Ok(updated));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = ClientUpdates {
        client_secret_hash: Some("$argon2id$new_hash".into()),
        ..Default::default()
    };
    let result = repo.update(tenant_id, id, &updates).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_update_redirect_uris() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let mut updated = client.clone();
    updated.redirect_uris = vec![
        "https://app.example.com/callback".into(),
        "https://app.example.com/callback2".into(),
    ];
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_update()
        .times(1)
        .return_once(move |_, _, _| Ok(updated));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = ClientUpdates {
        redirect_uris: Some(vec![
            "https://app.example.com/callback".into(),
            "https://app.example.com/callback2".into(),
        ]),
        ..Default::default()
    };
    let result = repo.update(tenant_id, id, &updates).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().redirect_uris.len(), 2);
}

#[tokio::test]
async fn test_update_token_version_rotation() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let client = make_client(tenant_id);
    let mut updated = client.clone();
    updated.token_version = 2;
    let id = client.id;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_update()
        .withf(|_, _, upd: &ClientUpdates| upd.token_version == Some(2))
        .times(1)
        .return_once(move |_, _, _| Ok(updated));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let updates = ClientUpdates {
        token_version: Some(2),
        ..Default::default()
    };
    let result = repo.update(tenant_id, id, &updates).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().token_version, 2);
}

// ---------------------------------------------------------------------------
// delete tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_calls_store_then_invalidates_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_delete()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));

    cache
        .expect_delete()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.delete(tenant_id, id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_store_error_does_not_touch_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_delete()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Store error".into())));

    cache.expect_delete().times(0);

    let repo = make_repo(store, cache);
    let result = repo.delete(tenant_id, id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_delete_cache_failure_is_non_fatal() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store.expect_delete().times(1).returning(|_, _| Ok(()));

    cache
        .expect_delete()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Redis gone".into())));

    let repo = make_repo(store, cache);
    let result = repo.delete(tenant_id, id).await;

    assert!(
        result.is_ok(),
        "Cache invalidation failure should not fail delete"
    );
}

#[tokio::test]
async fn test_delete_uses_correct_tenant_id_for_cache_invalidation() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store.expect_delete().times(1).returning(|_, _| Ok(()));

    cache
        .expect_delete()
        .with(eq(tenant_id), eq(id))
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.delete(tenant_id, id).await;

    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// list tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_delegates_to_store_only() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let clients = vec![make_client(tenant_id), make_client(tenant_id)];
    let total = 2u64;

    let mut store = MockClientStore::new();
    let mut cache = MockClientCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(move |_| Ok((clients, total)));

    // Cache must never be touched for list operations
    cache.expect_get().times(0);
    cache.expect_set().times(0);
    cache.expect_delete().times(0);

    let repo = make_repo(store, cache);
    let filter = ClientFilter {
        tenant_id,
        page: 1,
        page_size: 10,
        status: None,
    };
    let result = repo.list(&filter).await;

    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_list_empty_returns_zero() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let cache = MockClientCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(|_| Ok((vec![], 0)));

    let repo = make_repo(store, cache);
    let filter = ClientFilter {
        tenant_id,
        page: 1,
        page_size: 10,
        status: None,
    };
    let result = repo.list(&filter).await;

    assert!(result.is_ok());
    let (list, count) = result.unwrap();
    assert!(list.is_empty());
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_list_with_status_filter() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let cache = MockClientCache::new();

    store
        .expect_list()
        .withf(|f: &ClientFilter| f.status == Some(Status::Active))
        .times(1)
        .return_once(|_| Ok((vec![], 0)));

    let repo = make_repo(store, cache);
    let filter = ClientFilter {
        tenant_id,
        page: 1,
        page_size: 10,
        status: Some(Status::Active),
    };
    let _ = repo.list(&filter).await;
}

#[tokio::test]
async fn test_list_passes_correct_pagination() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let cache = MockClientCache::new();

    store
        .expect_list()
        .withf(|f: &ClientFilter| f.page == 3 && f.page_size == 20)
        .times(1)
        .return_once(|_| Ok((vec![], 0)));

    let repo = make_repo(store, cache);
    let filter = ClientFilter {
        tenant_id,
        page: 3,
        page_size: 20,
        status: None,
    };
    let _ = repo.list(&filter).await;
}

#[tokio::test]
async fn test_list_store_error_propagates() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockClientStore::new();
    let cache = MockClientCache::new();

    store
        .expect_list()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(store, cache);
    let filter = ClientFilter {
        tenant_id,
        page: 1,
        page_size: 10,
        status: None,
    };
    let result = repo.list(&filter).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}
