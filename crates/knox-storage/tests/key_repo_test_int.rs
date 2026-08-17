use knox_common::key::{CreateKeyParams, KeyRepository, KeyState};
use knox_storage::key::cache::RedisKeyCache;
use knox_storage::key::repository::KnoxKeyRepository;
use knox_storage::key::store::PgKeyStore;
use redis::Client;
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use std::env;
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

async fn setup() -> impl KeyRepository {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://admin:password@localhost:5432/knox".to_string());
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    let client = Client::open(redis_url).expect("Invalid Redis URL");
    let manager = client
        .get_connection_manager()
        .await
        .expect("Failed to connect to Redis");

    let store = PgKeyStore::new(pool);
    let cache = RedisKeyCache::new(manager);
    KnoxKeyRepository::new(store, cache)
}

async fn create_test_tenant() -> Uuid {
    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://admin:password@localhost:5432/knox".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    let suffix = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO tenants (name, slug, issuer, description, is_platform, status)
        VALUES ($1, $2, $3, 'Test tenant for key tests', false, 'active')
        RETURNING id
        "#,
    )
    .bind(format!("Key Test Tenant {suffix}"))
    .bind(format!("key-test-{suffix}"))
    .bind(format!("https://key-test-{suffix}.example.test"))
    .fetch_one(&pool)
    .await
    .expect("Failed to create test tenant")
}

async fn cleanup_tenant(tenant_id: Uuid) {
    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://admin:password@localhost:5432/knox".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    let _ = sqlx::query!("DELETE FROM tenants WHERE id = $1", tenant_id)
        .execute(&pool)
        .await;
}

fn make_create_params(tenant_id: Uuid) -> CreateKeyParams {
    CreateKeyParams {
        tenant_id,
        kid: format!("kid-{}", Uuid::new_v4()),
        use_type: "sig".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        public_key_pem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\ntest_public_key_material\n-----END PUBLIC KEY-----".to_string(),
        x509_cert_pem: None,
        encrypted_private_key: vec![0u8; 64], // Simulated encrypted key blob
        expires_at: OffsetDateTime::now_utc() + time::Duration::days(365),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_key_lifecycle() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create
    let params = make_create_params(tenant_id);
    let kid = params.kid.clone();
    let created = repo.create(params).await.expect("Failed to create key");

    assert_eq!(created.tenant_id, tenant_id);
    assert_eq!(created.kid, kid);
    assert_eq!(created.state, KeyState::Active);
    assert_eq!(created.alg, "RS256");

    // Get by ID
    let fetched = repo
        .get(created.id)
        .await
        .expect("Failed to get key")
        .expect("Key not found");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.kid, kid);

    // Get by kid
    let fetched_by_kid = repo
        .get_by_kid(tenant_id, &kid)
        .await
        .expect("Failed to get by kid")
        .expect("Key not found by kid");
    assert_eq!(fetched_by_kid.id, created.id);

    // Update state to expired
    let expired = repo
        .update_state(created.id, KeyState::Expired)
        .await
        .expect("Failed to update state");
    assert_eq!(expired.state, KeyState::Expired);

    // Delete
    repo.delete(created.id).await.expect("Failed to delete");
    let gone = repo.get(created.id).await.unwrap();
    assert!(gone.is_none());

    cleanup_tenant(tenant_id).await;
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_create_with_x509_cert() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    let mut params = make_create_params(tenant_id);
    params.x509_cert_pem =
        Some("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string());

    let created = repo
        .create(params)
        .await
        .expect("Create with x509 should succeed");
    assert!(created.x509_cert_pem.is_some());

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_create_duplicate_kid_fails() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    let params1 = make_create_params(tenant_id);
    let kid = params1.kid.clone();
    repo.create(params1)
        .await
        .expect("First create should succeed");

    // Try to create another key with the same kid
    let mut params2 = make_create_params(tenant_id);
    params2.kid = kid; // Same kid
    let result = repo.create(params2).await;

    assert!(result.is_err());
    if let Err(knox_common::error::RepositoryError::Duplicate(msg)) = result {
        assert!(msg.contains("already exists"));
    } else {
        panic!("Expected Duplicate error");
    }

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_create_with_ec_key() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    let mut params = make_create_params(tenant_id);
    params.kty = "EC".to_string();
    params.alg = "ES256".to_string();

    let created = repo
        .create(params)
        .await
        .expect("Create EC key should succeed");
    assert_eq!(created.kty, "EC");
    assert_eq!(created.alg, "ES256");

    cleanup_tenant(tenant_id).await;
}

// ---------------------------------------------------------------------------
// Get Active Key
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_get_active_for_tenant() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // No keys initially
    let none = repo.get_active_for_tenant(tenant_id).await.unwrap();
    assert!(none.is_none());

    // Create an active key
    let params = make_create_params(tenant_id);
    let created = repo.create(params).await.unwrap();

    // Should find the active key
    let active = repo
        .get_active_for_tenant(tenant_id)
        .await
        .expect("Failed to get active")
        .expect("No active key found");
    assert_eq!(active.id, created.id);
    assert_eq!(active.state, KeyState::Active);

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_get_active_returns_most_recent() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create first key
    let params1 = make_create_params(tenant_id);
    let _first = repo.create(params1).await.unwrap();

    // Small delay to ensure different timestamps
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Create second key
    let params2 = make_create_params(tenant_id);
    let second = repo.create(params2).await.unwrap();

    // Should return the most recent active key
    let active = repo
        .get_active_for_tenant(tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.id, second.id);

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_expired_key_not_returned_as_active() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    let params = make_create_params(tenant_id);
    let created = repo.create(params).await.unwrap();

    // Expire the key
    repo.update_state(created.id, KeyState::Expired)
        .await
        .unwrap();

    // Should not find an active key
    let active = repo.get_active_for_tenant(tenant_id).await.unwrap();
    assert!(active.is_none());

    cleanup_tenant(tenant_id).await;
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_list_for_jwks_includes_active_and_expired() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create active key
    let params1 = make_create_params(tenant_id);
    let active_key = repo.create(params1).await.unwrap();

    // Create and expire another key
    let params2 = make_create_params(tenant_id);
    let expired_key = repo.create(params2).await.unwrap();
    repo.update_state(expired_key.id, KeyState::Expired)
        .await
        .unwrap();

    // JWKS should include both
    let jwks_keys = repo.list_for_jwks(tenant_id).await.unwrap();
    assert_eq!(jwks_keys.len(), 2);

    let ids: Vec<_> = jwks_keys.iter().map(|k| k.id).collect();
    assert!(ids.contains(&active_key.id));
    assert!(ids.contains(&expired_key.id));

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_list_for_jwks_excludes_revoked() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create and revoke a key
    let params = make_create_params(tenant_id);
    let key = repo.create(params).await.unwrap();
    repo.update_state(key.id, KeyState::Revoked).await.unwrap();

    // JWKS should not include revoked keys
    let jwks_keys = repo.list_for_jwks(tenant_id).await.unwrap();
    assert!(jwks_keys.is_empty());

    cleanup_tenant(tenant_id).await;
}

// ---------------------------------------------------------------------------
// List with Pagination
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_list_pagination() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create 5 keys
    for _ in 0..5 {
        let params = make_create_params(tenant_id);
        repo.create(params).await.unwrap();
    }

    // First page
    let (page1, total) = repo.list(tenant_id, 1, 2).await.unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(total, 5);

    // Second page
    let (page2, _) = repo.list(tenant_id, 2, 2).await.unwrap();
    assert_eq!(page2.len(), 2);

    // Third page
    let (page3, _) = repo.list(tenant_id, 3, 2).await.unwrap();
    assert_eq!(page3.len(), 1);

    // Ensure no duplicates
    let all_ids: Vec<_> = page1
        .iter()
        .chain(page2.iter())
        .chain(page3.iter())
        .map(|k| k.id)
        .collect();
    let unique_ids: std::collections::HashSet<_> = all_ids.iter().collect();
    assert_eq!(all_ids.len(), unique_ids.len());

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_list_includes_all_states() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create keys with different states
    let params1 = make_create_params(tenant_id);
    let _active = repo.create(params1).await.unwrap();

    let params2 = make_create_params(tenant_id);
    let expired = repo.create(params2).await.unwrap();
    repo.update_state(expired.id, KeyState::Expired)
        .await
        .unwrap();

    let params3 = make_create_params(tenant_id);
    let revoked = repo.create(params3).await.unwrap();
    repo.update_state(revoked.id, KeyState::Revoked)
        .await
        .unwrap();

    // List should include all states (unlike JWKS)
    let (keys, total) = repo.list(tenant_id, 1, 10).await.unwrap();
    assert_eq!(total, 3);
    assert_eq!(keys.len(), 3);

    cleanup_tenant(tenant_id).await;
}

// ---------------------------------------------------------------------------
// State Transitions
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_state_transition_active_to_expired() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    let params = make_create_params(tenant_id);
    let key = repo.create(params).await.unwrap();
    assert_eq!(key.state, KeyState::Active);

    let updated = repo.update_state(key.id, KeyState::Expired).await.unwrap();
    assert_eq!(updated.state, KeyState::Expired);

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_state_transition_active_to_revoked() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    let params = make_create_params(tenant_id);
    let key = repo.create(params).await.unwrap();

    let updated = repo.update_state(key.id, KeyState::Revoked).await.unwrap();
    assert_eq!(updated.state, KeyState::Revoked);

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_update_state_not_found() {
    let repo = setup().await;
    let fake_id = Uuid::new_v4();

    let result = repo.update_state(fake_id, KeyState::Expired).await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Revoke All
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_revoke_all_for_tenant() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create multiple keys
    for _ in 0..3 {
        let params = make_create_params(tenant_id);
        repo.create(params).await.unwrap();
    }

    // Verify we have active keys
    let active = repo.get_active_for_tenant(tenant_id).await.unwrap();
    assert!(active.is_some());

    // Revoke all
    repo.revoke_all_for_tenant(tenant_id)
        .await
        .expect("Revoke all failed");

    // Should have no active keys now
    let active_after = repo.get_active_for_tenant(tenant_id).await.unwrap();
    assert!(active_after.is_none());

    // JWKS should be empty (all revoked)
    let jwks = repo.list_for_jwks(tenant_id).await.unwrap();
    assert!(jwks.is_empty());

    // But list should still show them
    let (all_keys, _) = repo.list(tenant_id, 1, 10).await.unwrap();
    assert_eq!(all_keys.len(), 3);
    assert!(all_keys.iter().all(|k| k.state == KeyState::Revoked));

    cleanup_tenant(tenant_id).await;
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_delete_nonexistent_key() {
    let repo = setup().await;
    let fake_id = Uuid::new_v4();

    let result = repo.delete(fake_id).await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Cache Behavior (Integration)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_cache_hit_after_create() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    let params = make_create_params(tenant_id);
    let created = repo.create(params).await.unwrap();

    // Second fetch should hit cache (we can't directly verify, but it should work)
    let fetched = repo.get(created.id).await.unwrap().unwrap();
    assert_eq!(fetched.id, created.id);

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_jwks_cache_invalidation_on_create() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create first key and fetch JWKS (populates cache)
    let params1 = make_create_params(tenant_id);
    repo.create(params1).await.unwrap();
    let jwks1 = repo.list_for_jwks(tenant_id).await.unwrap();
    assert_eq!(jwks1.len(), 1);

    // Create second key (should invalidate JWKS cache)
    let params2 = make_create_params(tenant_id);
    repo.create(params2).await.unwrap();

    // JWKS should now have 2 keys
    let jwks2 = repo.list_for_jwks(tenant_id).await.unwrap();
    assert_eq!(jwks2.len(), 2);

    cleanup_tenant(tenant_id).await;
}

#[tokio::test]
#[serial]
async fn test_active_key_cache_invalidation_on_state_change() {
    let repo = setup().await;
    let tenant_id = create_test_tenant().await;

    // Create key and fetch active (populates cache)
    let params = make_create_params(tenant_id);
    let key = repo.create(params).await.unwrap();
    let active1 = repo
        .get_active_for_tenant(tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active1.id, key.id);

    // Expire the key (should invalidate active cache)
    repo.update_state(key.id, KeyState::Expired).await.unwrap();

    // Should now have no active key
    let active2 = repo.get_active_for_tenant(tenant_id).await.unwrap();
    assert!(active2.is_none());

    cleanup_tenant(tenant_id).await;
}
