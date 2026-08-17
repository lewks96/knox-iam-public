use async_trait::async_trait;
use knox_common::error::RepositoryError;
use knox_common::token::AuthCodeCache;
use knox_common::token::RefreshTokenStore;
use knox_common::token::{AuthCodeContext, RefreshToken, TokenRepository};
use knox_storage::token::repository::KnoxTokenRepository;
use mockall::{mock, predicate::*};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub AuthCodeCache {}
    #[async_trait]
    impl AuthCodeCache for AuthCodeCache {
        async fn set_value(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> Result<(), RepositoryError>;
        async fn get_value(&self, key: &str) -> Result<Option<String>, RepositoryError>;
        async fn get_and_delete_value(&self, key: &str) -> Result<Option<String>, RepositoryError>;
        async fn increment_value(&self, key: &str, ttl_seconds: u64) -> Result<u64, RepositoryError>;
        async fn touch_value(&self, key: &str, ttl_seconds: u64) -> Result<(), RepositoryError>;

        // Deprecated methods
        async fn set_code(
            &self,
            hashed_code: &str,
            context: &AuthCodeContext,
            ttl_seconds: u64,
        ) -> Result<(), RepositoryError>;
        async fn exchange_code(
            &self,
            hashed_code: &str,
        ) -> Result<Option<AuthCodeContext>, RepositoryError>;
    }
}

mock! {
    pub RefreshTokenStore {}
    #[async_trait]
    impl RefreshTokenStore for RefreshTokenStore {
        async fn create(&self, token: &RefreshToken) -> Result<RefreshToken, RepositoryError>;
        async fn get_by_hash(&self, tenant_id: Uuid, token_hash: &str) -> Result<Option<RefreshToken>, RepositoryError>;
        async fn revoke(&self, id: Uuid) -> Result<(), RepositoryError>;
        async fn revoke_family(&self, family_id: Uuid) -> Result<(), RepositoryError>;
        async fn revoke_all_for_identity(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), RepositoryError>;
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

fn make_auth_code_context() -> AuthCodeContext {
    AuthCodeContext {
        client_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        scopes: vec!["openid".into(), "profile".into()],
        pkce_code_challenge: "s256_challenge_value".to_string(),
        pkce_code_challenge_method: "S256".to_string(),
        nonce: Some("random-nonce-value".into()),
        amr: vec!["pwd".into()],
        auth_time: Some(OffsetDateTime::now_utc()),
        created_at: OffsetDateTime::now_utc(),
    }
}

fn make_refresh_token(tenant_id: Uuid, identity_id: Uuid) -> RefreshToken {
    RefreshToken {
        id: Uuid::new_v4(),
        tenant_id,
        identity_id,
        client_id: Uuid::new_v4(),
        family_id: Uuid::new_v4(),
        token_hash: format!("sha256_hash_{}", Uuid::new_v4()),
        scopes: vec!["openid".into(), "offline_access".into()],
        amr: vec!["pwd".into(), "otp".into(), "mfa".into()],
        auth_time: Some(OffsetDateTime::now_utc()),
        revoked_at: None,
        updated_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::days(30),
        created_at: OffsetDateTime::now_utc(),
    }
}

fn make_repo(
    cache: MockAuthCodeCache,
    store: MockRefreshTokenStore,
) -> KnoxTokenRepository<MockAuthCodeCache, MockRefreshTokenStore> {
    KnoxTokenRepository::new(cache, store)
}

// ---------------------------------------------------------------------------
// store_transient_string tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_store_transient_string_delegates_to_cache() {
    init_tracing();
    let hashed_code = "sha256_abc123";
    let context = make_auth_code_context();
    let ttl = 600u64;
    let value = serde_json::to_string(&context).unwrap();

    let mut cache = MockAuthCodeCache::new();
    let store = MockRefreshTokenStore::new();

    cache
        .expect_set_value()
        .with(eq(hashed_code), eq(value.clone()), eq(ttl))
        .times(1)
        .returning(|_, _, _| Ok(()));

    let repo = make_repo(cache, store);
    let result = repo.store_transient_string(hashed_code, &value, ttl).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_store_transient_string_never_touches_store() {
    init_tracing();
    let context = make_auth_code_context();
    let value = serde_json::to_string(&context).unwrap();

    let mut cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    cache
        .expect_set_value()
        .times(1)
        .returning(|_, _, _| Ok(()));

    // Transient strings must never go to the Postgres store
    store.expect_create().times(0);
    store.expect_get_by_hash().times(0);

    let repo = make_repo(cache, store);
    let _ = repo.store_transient_string("code", &value, 600).await;
}

#[tokio::test]
async fn test_store_transient_string_cache_error_propagates() {
    init_tracing();
    let context = make_auth_code_context();
    let value = serde_json::to_string(&context).unwrap();

    let mut cache = MockAuthCodeCache::new();
    let store = MockRefreshTokenStore::new();

    cache
        .expect_set_value()
        .times(1)
        .returning(|_, _, _| Err(RepositoryError::Database("Redis down".into())));

    let repo = make_repo(cache, store);
    let result = repo.store_transient_string("code", &value, 600).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_store_transient_string_passes_correct_ttl() {
    init_tracing();
    let context = make_auth_code_context();
    let value = serde_json::to_string(&context).unwrap();

    let mut cache = MockAuthCodeCache::new();
    let store = MockRefreshTokenStore::new();

    // Verify the TTL is passed through exactly — important for expiry correctness
    cache
        .expect_set_value()
        .with(always(), always(), eq(300u64))
        .times(1)
        .returning(|_, _, _| Ok(()));

    let repo = make_repo(cache, store);
    let _ = repo.store_transient_string("code", &value, 300).await;
}

// ---------------------------------------------------------------------------
// get_and_delete_transient_string tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_and_delete_transient_string_returns_value_on_hit() {
    init_tracing();
    let hashed_code = "sha256_valid_code";
    let context = make_auth_code_context();
    let value = serde_json::to_string(&context).unwrap();

    let mut cache = MockAuthCodeCache::new();
    let store = MockRefreshTokenStore::new();

    cache
        .expect_get_and_delete_value()
        .with(eq(hashed_code))
        .times(1)
        .return_once(move |_| Ok(Some(value)));

    let repo = make_repo(cache, store);
    let result = repo.get_and_delete_transient_string(hashed_code).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[tokio::test]
async fn test_get_and_delete_transient_string_returns_none_on_miss() {
    init_tracing();
    let mut cache = MockAuthCodeCache::new();
    let store = MockRefreshTokenStore::new();

    cache
        .expect_get_and_delete_value()
        .times(1)
        .return_once(|_| Ok(None));

    let repo = make_repo(cache, store);
    let result = repo.get_and_delete_transient_string("unknown_code").await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_and_delete_transient_string_never_touches_store() {
    init_tracing();
    let mut cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    cache
        .expect_get_and_delete_value()
        .times(1)
        .return_once(|_| Ok(None));

    store.expect_get_by_hash().times(0);

    let repo = make_repo(cache, store);
    let _ = repo.get_and_delete_transient_string("code").await;
}

#[tokio::test]
async fn test_get_and_delete_transient_string_cache_error_propagates() {
    init_tracing();
    let mut cache = MockAuthCodeCache::new();
    let store = MockRefreshTokenStore::new();

    cache
        .expect_get_and_delete_value()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Redis error".into())));

    let repo = make_repo(cache, store);
    let result = repo.get_and_delete_transient_string("code").await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

// ---------------------------------------------------------------------------
// save_refresh_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_save_refresh_token_delegates_to_store() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let token = make_refresh_token(tenant_id, identity_id);
    let cloned = token.clone();

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));

    let repo = make_repo(cache, store);
    let result = repo.save_refresh_token(&token).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, token.id);
}

#[tokio::test]
async fn test_save_refresh_token_never_touches_cache() {
    init_tracing();
    let token = make_refresh_token(Uuid::new_v4(), Uuid::new_v4());
    let cloned = token.clone();

    let mut cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    // Refresh tokens must never go to the Redis cache
    cache.expect_set_value().times(0);
    cache.expect_get_and_delete_value().times(0);

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));

    let repo = make_repo(cache, store);
    let _ = repo.save_refresh_token(&token).await;
}

#[tokio::test]
async fn test_save_refresh_token_store_error_propagates() {
    init_tracing();
    let token = make_refresh_token(Uuid::new_v4(), Uuid::new_v4());

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_create()
        .times(1)
        .return_once(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(cache, store);
    let result = repo.save_refresh_token(&token).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_save_refresh_token_returns_stored_token() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let input = make_refresh_token(tenant_id, identity_id);
    let mut stored = input.clone();
    stored.id = Uuid::new_v4(); // store assigned a different ID

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(stored.clone()));

    let repo = make_repo(cache, store);
    let result = repo.save_refresh_token(&input).await.unwrap();

    assert_ne!(
        result.id, input.id,
        "Repo should return the store's version of the token"
    );
}

// ---------------------------------------------------------------------------
// get_refresh_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_refresh_token_found() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let token = make_refresh_token(tenant_id, identity_id);
    let hash = token.token_hash.clone();
    let cloned = token.clone();

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_get_by_hash()
        .with(eq(tenant_id), eq(hash.clone()))
        .times(1)
        .return_once(move |_, _| Ok(Some(cloned)));

    let repo = make_repo(cache, store);
    let result = repo.get_refresh_token(tenant_id, &hash).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap().id, token.id);
}

#[tokio::test]
async fn test_get_refresh_token_not_found() {
    init_tracing();
    let tenant_id = Uuid::new_v4();

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_get_by_hash()
        .times(1)
        .return_once(|_, _| Ok(None));

    let repo = make_repo(cache, store);
    let result = repo.get_refresh_token(tenant_id, "unknown_hash").await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_refresh_token_forwards_correct_tenant_id() {
    init_tracing();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let hash = "shared_looking_hash";

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_get_by_hash()
        .with(eq(tenant_a), eq(hash))
        .times(1)
        .return_once(|_, _| Ok(None));

    let repo = make_repo(cache, store);
    let _ = repo.get_refresh_token(tenant_a, hash).await;
    let _ = tenant_b; // never used — proves the correct tenant was forwarded
}

#[tokio::test]
async fn test_get_refresh_token_store_error_propagates() {
    init_tracing();
    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_get_by_hash()
        .times(1)
        .return_once(|_, _| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(cache, store);
    let result = repo.get_refresh_token(Uuid::new_v4(), "hash").await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

// ---------------------------------------------------------------------------
// revoke_refresh_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_refresh_token_delegates_to_store() {
    init_tracing();
    let id = Uuid::new_v4();

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_revoke()
        .with(eq(id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(cache, store);
    let result = repo.revoke_refresh_token(id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_refresh_token_store_error_propagates() {
    init_tracing();
    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_revoke()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(cache, store);
    let result = repo.revoke_refresh_token(Uuid::new_v4()).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_revoke_refresh_token_never_touches_cache() {
    init_tracing();
    let mut cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    cache.expect_set_value().times(0);
    cache.expect_get_and_delete_value().times(0);

    store.expect_revoke().times(1).returning(|_| Ok(()));

    let repo = make_repo(cache, store);
    let _ = repo.revoke_refresh_token(Uuid::new_v4()).await;
}

// ---------------------------------------------------------------------------
// revoke_token_family tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_token_family_delegates_to_store() {
    init_tracing();
    let family_id = Uuid::new_v4();

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_revoke_family()
        .with(eq(family_id))
        .times(1)
        .returning(|_| Ok(()));

    let repo = make_repo(cache, store);
    let result = repo.revoke_token_family(family_id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_token_family_store_error_propagates() {
    init_tracing();
    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_revoke_family()
        .times(1)
        .returning(|_| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(cache, store);
    let result = repo.revoke_token_family(Uuid::new_v4()).await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_revoke_token_family_does_not_call_single_revoke() {
    init_tracing();
    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store.expect_revoke().times(0);
    store.expect_revoke_family().times(1).returning(|_| Ok(()));

    let repo = make_repo(cache, store);
    let _ = repo.revoke_token_family(Uuid::new_v4()).await;
}

// ---------------------------------------------------------------------------
// revoke_all_for_identity tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_revoke_all_for_identity_delegates_to_store() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_revoke_all_for_identity()
        .with(eq(tenant_id), eq(identity_id))
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(cache, store);
    let result = repo.revoke_all_for_identity(tenant_id, identity_id).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_all_for_identity_forwards_correct_tenant_id() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();

    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_revoke_all_for_identity()
        .with(eq(tenant_id), eq(identity_id))
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(cache, store);
    let _ = repo.revoke_all_for_identity(tenant_id, identity_id).await;
}

#[tokio::test]
async fn test_revoke_all_for_identity_store_error_propagates() {
    init_tracing();
    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store
        .expect_revoke_all_for_identity()
        .times(1)
        .returning(|_, _| Err(RepositoryError::Database("Store error".into())));

    let repo = make_repo(cache, store);
    let result = repo
        .revoke_all_for_identity(Uuid::new_v4(), Uuid::new_v4())
        .await;

    assert!(matches!(result, Err(RepositoryError::Database(_))));
}

#[tokio::test]
async fn test_revoke_all_for_identity_does_not_call_single_revoke() {
    init_tracing();
    let cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    store.expect_revoke().times(0);
    store.expect_revoke_family().times(0);
    store
        .expect_revoke_all_for_identity()
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(cache, store);
    let _ = repo
        .revoke_all_for_identity(Uuid::new_v4(), Uuid::new_v4())
        .await;
}

// ---------------------------------------------------------------------------
// Cross-cutting: routing isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auth_code_operations_never_touch_refresh_token_store() {
    init_tracing();
    let context = make_auth_code_context();
    let value = serde_json::to_string(&context).unwrap();

    let mut cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    cache
        .expect_set_value()
        .times(1)
        .returning(|_, _, _| Ok(()));
    cache
        .expect_get_and_delete_value()
        .times(1)
        .return_once(|_| Ok(None));

    store.expect_create().times(0);
    store.expect_get_by_hash().times(0);
    store.expect_revoke().times(0);
    store.expect_revoke_family().times(0);
    store.expect_revoke_all_for_identity().times(0);

    let repo = make_repo(cache, store);
    let _ = repo.store_transient_string("code", &value, 600).await;
    let _ = repo.get_and_delete_transient_string("code").await;
}

#[tokio::test]
async fn test_refresh_token_operations_never_touch_auth_code_cache() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let token = make_refresh_token(tenant_id, identity_id);
    let cloned = token.clone();

    let mut cache = MockAuthCodeCache::new();
    let mut store = MockRefreshTokenStore::new();

    cache.expect_set_value().times(0);
    cache.expect_get_value().times(0);
    cache.expect_get_and_delete_value().times(0);

    store
        .expect_create()
        .times(1)
        .return_once(move |_| Ok(cloned));
    store
        .expect_get_by_hash()
        .times(1)
        .return_once(|_, _| Ok(None));
    store.expect_revoke().times(1).returning(|_| Ok(()));
    store.expect_revoke_family().times(1).returning(|_| Ok(()));
    store
        .expect_revoke_all_for_identity()
        .times(1)
        .returning(|_, _| Ok(()));

    let repo = make_repo(cache, store);
    let _ = repo.save_refresh_token(&token).await;
    let _ = repo.get_refresh_token(tenant_id, &token.token_hash).await;
    let _ = repo.revoke_refresh_token(token.id).await;
    let _ = repo.revoke_token_family(Uuid::new_v4()).await;
    let _ = repo.revoke_all_for_identity(tenant_id, identity_id).await;
}
