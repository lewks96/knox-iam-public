use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::key::{CreateKeyParams, KeyRepository, KeyState, TenantKey};
use knox_storage::key::cache::KeyCache;
use knox_storage::key::repository::KnoxKeyRepository;
use knox_storage::key::store::KeyStore;
use mockall::{mock, predicate::*};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub KeyStore {}
    #[async_trait]
    impl KeyStore for KeyStore {
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
    pub KeyCache {}
    #[async_trait]
    impl KeyCache for KeyCache {
        async fn get(&self, id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
        async fn set(&self, key: &TenantKey) -> Result<(), RepositoryError>;
        async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
        async fn get_by_kid(&self, tenant_id: Uuid, kid: &str) -> Result<Option<TenantKey>, RepositoryError>;
        async fn set_by_kid(&self, key: &TenantKey) -> Result<(), RepositoryError>;
        async fn delete_by_kid(&self, tenant_id: Uuid, kid: &str) -> Result<(), RepositoryError>;
        async fn get_active_for_tenant(&self, tenant_id: Uuid) -> Result<Option<TenantKey>, RepositoryError>;
        async fn set_active_for_tenant(&self, key: &TenantKey) -> Result<(), RepositoryError>;
        async fn delete_active_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
        async fn get_jwks(&self, tenant_id: Uuid) -> Result<Option<Vec<TenantKey>>, RepositoryError>;
        async fn set_jwks(&self, tenant_id: Uuid, keys: &[TenantKey]) -> Result<(), RepositoryError>;
        async fn delete_jwks(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
        async fn invalidate_all_for_tenant(&self, tenant_id: Uuid) -> Result<(), RepositoryError>;
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

fn make_tenant_key(tenant_id: Uuid) -> TenantKey {
    TenantKey {
        id: Uuid::new_v4(),
        tenant_id,
        kid: format!("kid-{}", Uuid::new_v4()),
        use_type: "sig".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
        x509_cert_pem: None,
        encrypted_private_key: vec![0u8; 32],
        state: KeyState::Active,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::days(365),
    }
}

fn make_create_params(tenant_id: Uuid) -> CreateKeyParams {
    CreateKeyParams {
        tenant_id,
        kid: format!("kid-{}", Uuid::new_v4()),
        use_type: "sig".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
        x509_cert_pem: None,
        encrypted_private_key: vec![0u8; 32],
        expires_at: OffsetDateTime::now_utc() + time::Duration::days(365),
    }
}

fn make_repo(
    store: MockKeyStore,
    cache: MockKeyCache,
) -> KnoxKeyRepository<MockKeyStore, MockKeyCache> {
    KnoxKeyRepository::new(store, cache)
}

// ---------------------------------------------------------------------------
// create tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_persists_to_store_and_warms_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let cloned = key.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache.expect_set().times(1).returning(|_| Ok(()));
    cache.expect_set_by_kid().times(1).returning(|_| Ok(()));
    cache.expect_delete_jwks().times(1).returning(|_| Ok(()));
    cache
        .expect_delete_active_for_tenant()
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let params = make_create_params(tenant_id);
    let result = repo.create(params).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().tenant_id, tenant_id);
}

#[tokio::test]
async fn test_create_store_error_does_not_call_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("DB write failed".into())));

    cache.expect_set().times(0);
    cache.expect_set_by_kid().times(0);

    let repo = make_repo(store, cache);
    let params = make_create_params(tenant_id);
    let result = repo.create(params).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_create_cache_failure_is_non_fatal() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let cloned = key.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache
        .expect_set()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));
    cache.expect_set_by_kid().times(1).returning(|_| Ok(()));
    cache.expect_delete_jwks().times(1).returning(|_| Ok(()));
    cache
        .expect_delete_active_for_tenant()
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let params = make_create_params(tenant_id);
    let result = repo.create(params).await;

    assert!(
        result.is_ok(),
        "Cache failure on create should not fail the operation"
    );
}

#[tokio::test]
async fn test_create_invalidates_jwks_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let cloned = key.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache.expect_set().times(1).returning(|_| Ok(()));
    cache.expect_set_by_kid().times(1).returning(|_| Ok(()));
    cache
        .expect_delete_jwks()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(()));
    cache
        .expect_delete_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let params = make_create_params(tenant_id);
    let _ = repo.create(params).await;
}

#[tokio::test]
async fn test_create_duplicate_kid_returns_error() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let cache = MockKeyCache::new();

    store.expect_create().times(1).return_once(|_| {
        Err(RepositoryError::Duplicate(
            "Key with kid 'existing' already exists".into(),
        ))
    });

    let repo = make_repo(store, cache);
    let params = make_create_params(tenant_id);
    let result = repo.create(params).await;

    assert!(matches!(result, Err(RepositoryError::Duplicate(_))));
}

// ---------------------------------------------------------------------------
// get tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_cache_hit_does_not_call_store() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let cloned = key.clone();
    let id = key.id;

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get()
        .with(eq(id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    store.expect_get().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, id);
}

#[tokio::test]
async fn test_get_cache_miss_falls_back_to_store_and_backfills() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let cloned = key.clone();
    let id = key.id;

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get()
        .with(eq(id))
        .times(1)
        .return_once(|_| Ok(None));

    store
        .expect_get()
        .with(eq(id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    cache.expect_set().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, id);
}

#[tokio::test]
async fn test_get_cache_miss_store_returns_none() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache.expect_get().times(1).return_once(|_| Ok(None));
    store.expect_get().times(1).return_once(|_| Ok(None));
    cache.expect_set().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_cache_error_propagates() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Cache error".into())));

    store.expect_get().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get(id).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

// ---------------------------------------------------------------------------
// get_by_kid tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_by_kid_cache_hit() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let kid = key.kid.clone();
    let cloned = key.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get_by_kid()
        .with(eq(tenant_id), eq(kid.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    store.expect_get_by_kid().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get_by_kid(tenant_id, &kid).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().kid, kid);
}

#[tokio::test]
async fn test_get_by_kid_cache_miss_backfills() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let kid = key.kid.clone();
    let cloned = key.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get_by_kid()
        .times(1)
        .return_once(|_, _| Ok(None));

    store
        .expect_get_by_kid()
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    cache.expect_set_by_kid().times(1).returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.get_by_kid(tenant_id, &kid).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

// ---------------------------------------------------------------------------
// get_active_for_tenant tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_active_for_tenant_cache_hit() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let cloned = key.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    store.expect_get_active_for_tenant().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get_active_for_tenant(tenant_id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().state, KeyState::Active);
}

#[tokio::test]
async fn test_get_active_for_tenant_cache_miss_backfills() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let cloned = key.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get_active_for_tenant()
        .times(1)
        .return_once(|_| Ok(None));

    store
        .expect_get_active_for_tenant()
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    cache
        .expect_set_active_for_tenant()
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.get_active_for_tenant(tenant_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[tokio::test]
async fn test_get_active_for_tenant_no_active_key() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get_active_for_tenant()
        .times(1)
        .return_once(|_| Ok(None));

    store
        .expect_get_active_for_tenant()
        .times(1)
        .return_once(|_| Ok(None));

    cache.expect_set_active_for_tenant().times(0);

    let repo = make_repo(store, cache);
    let result = repo.get_active_for_tenant(tenant_id).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// list_for_jwks tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_for_jwks_cache_hit() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let keys = vec![make_tenant_key(tenant_id), make_tenant_key(tenant_id)];
    let cloned = keys.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache
        .expect_get_jwks()
        .with(eq(tenant_id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    store.expect_list_for_jwks().times(0);

    let repo = make_repo(store, cache);
    let result = repo.list_for_jwks(tenant_id).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_for_jwks_cache_miss_backfills() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let keys = vec![make_tenant_key(tenant_id)];
    let cloned = keys.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache.expect_get_jwks().times(1).return_once(|_| Ok(None));

    store
        .expect_list_for_jwks()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache.expect_set_jwks().times(1).returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.list_for_jwks(tenant_id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_list_for_jwks_excludes_revoked() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut active_key = make_tenant_key(tenant_id);
    active_key.state = KeyState::Active;
    let mut expired_key = make_tenant_key(tenant_id);
    expired_key.state = KeyState::Expired;
    // Note: Revoked keys should NOT be returned by list_for_jwks
    let keys = vec![active_key, expired_key];
    let cloned = keys.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    cache.expect_get_jwks().times(1).return_once(|_| Ok(None));

    store
        .expect_list_for_jwks()
        .times(1)
        .return_once(move |_| Ok(cloned));

    cache.expect_set_jwks().times(1).returning(|_, _| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.list_for_jwks(tenant_id).await;

    assert!(result.is_ok());
    let keys = result.unwrap();
    // Both active and expired should be present for token verification
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| k.state != KeyState::Revoked));
}

// ---------------------------------------------------------------------------
// list tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_bypasses_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let keys = vec![make_tenant_key(tenant_id)];
    let cloned = keys.clone();

    let mut store = MockKeyStore::new();
    let cache = MockKeyCache::new();

    store
        .expect_list()
        .with(eq(tenant_id), eq(1u32), eq(10u32))
        .times(1)
        .return_once(move |_, _, _| Ok((cloned, 1)));

    let repo = make_repo(store, cache);
    let result = repo.list(tenant_id, 1, 10).await;

    assert!(result.is_ok());
    let (keys, total) = result.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(total, 1);
}

// ---------------------------------------------------------------------------
// update_state tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_state_updates_store_and_invalidates_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut key = make_tenant_key(tenant_id);
    key.state = KeyState::Expired;
    let cloned = key.clone();
    let id = key.id;

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_update_state()
        .with(eq(id), eq(KeyState::Expired))
        .times(1)
        .return_once(move |_, _| Ok(cloned));

    cache.expect_set().times(1).returning(|_| Ok(()));
    cache.expect_set_by_kid().times(1).returning(|_| Ok(()));
    cache.expect_delete_jwks().times(1).returning(|_| Ok(()));
    cache
        .expect_delete_active_for_tenant()
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.update_state(id, KeyState::Expired).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().state, KeyState::Expired);
}

#[tokio::test]
async fn test_update_state_to_revoked() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let mut key = make_tenant_key(tenant_id);
    key.state = KeyState::Revoked;
    let cloned = key.clone();
    let id = key.id;

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_update_state()
        .with(eq(id), eq(KeyState::Revoked))
        .times(1)
        .return_once(move |_, _| Ok(cloned));

    cache.expect_set().times(1).returning(|_| Ok(()));
    cache.expect_set_by_kid().times(1).returning(|_| Ok(()));
    cache.expect_delete_jwks().times(1).returning(|_| Ok(()));
    cache
        .expect_delete_active_for_tenant()
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.update_state(id, KeyState::Revoked).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_update_state_not_found() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let cache = MockKeyCache::new();

    store
        .expect_update_state()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::NotFound));

    let repo = make_repo(store, cache);
    let result = repo.update_state(id, KeyState::Expired).await;

    assert!(matches!(result, Err(RepositoryError::NotFound)));
}

// ---------------------------------------------------------------------------
// delete tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_removes_from_store_and_invalidates_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let key = make_tenant_key(tenant_id);
    let cloned = key.clone();
    let id = key.id;
    let kid = key.kid.clone();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_get()
        .with(eq(id))
        .times(1)
        .return_once(move |_| Ok(Some(cloned)));

    store
        .expect_delete()
        .with(eq(id))
        .times(1)
        .return_once(|_| Ok(()));

    cache
        .expect_delete()
        .with(eq(id))
        .times(1)
        .returning(|_| Ok(()));
    cache
        .expect_delete_by_kid()
        .with(eq(tenant_id), eq(kid))
        .times(1)
        .returning(|_, _| Ok(()));
    cache
        .expect_delete_jwks()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(()));
    cache
        .expect_delete_active_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.delete(id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_not_found() {
    init_tracing();
    let id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let cache = MockKeyCache::new();

    store.expect_get().times(1).return_once(|_| Ok(None));

    store
        .expect_delete()
        .times(1)
        .return_once(|_| Err(RepositoryError::NotFound));

    // cache.delete is never called because store.delete returns early with NotFound

    let repo = make_repo(store, cache);
    let result = repo.delete(id).await;

    assert!(matches!(result, Err(RepositoryError::NotFound)));
}

// ---------------------------------------------------------------------------
// revoke_all_for_tenant tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_all_for_tenant() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_revoke_all_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .return_once(|_| Ok(()));

    cache
        .expect_invalidate_all_for_tenant()
        .with(eq(tenant_id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(store, cache);
    let result = repo.revoke_all_for_tenant(tenant_id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_all_for_tenant_cache_failure_non_fatal() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let mut store = MockKeyStore::new();
    let mut cache = MockKeyCache::new();

    store
        .expect_revoke_all_for_tenant()
        .times(1)
        .return_once(|_| Ok(()));

    cache
        .expect_invalidate_all_for_tenant()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(store, cache);
    let result = repo.revoke_all_for_tenant(tenant_id).await;

    assert!(
        result.is_ok(),
        "Cache failure should not fail the operation"
    );
}
