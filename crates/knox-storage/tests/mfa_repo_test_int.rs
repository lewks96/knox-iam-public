use knox_common::error::RepositoryError;
use knox_common::identity::{Identity, IdentityKind, IdentityRepository, Status};
use knox_common::mfa::{MfaMethodKind, MfaRepository, NewMfaMethod};
use knox_common::tenant::TenantRepository;
use knox_storage::identity::cache::RedisIdentityCache;
use knox_storage::identity::repository::KnoxIdentityRepository;
use knox_storage::identity::store::PgIdentityStore;
use knox_storage::mfa::cache::RedisMfaCache;
use knox_storage::mfa::repository::KnoxMfaRepository;
use knox_storage::mfa::store::PgMfaStore;
use knox_storage::tenant::cache::RedisTenantCache;
use knox_storage::tenant::repository::KnoxTenantRepository;
use knox_storage::tenant::store::PgTenantStore;
use redis::Client;
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use std::env;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

async fn setup() -> (
    impl MfaRepository,
    impl TenantRepository,
    impl IdentityRepository,
    sqlx::PgPool,
) {
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

    let client = Client::open(redis_url).unwrap();
    let manager = client.get_connection_manager().await.unwrap();

    let tenant_repo = KnoxTenantRepository::new(
        PgTenantStore::new(pool.clone()),
        RedisTenantCache::new(manager.clone()),
    );

    let identity_repo = KnoxIdentityRepository::new(
        PgIdentityStore::new(pool.clone(), pool.clone()),
        RedisIdentityCache::new(manager.clone()),
    );

    let mfa_repo =
        KnoxMfaRepository::new(PgMfaStore::new(pool.clone()), RedisMfaCache::new(manager));

    (mfa_repo, tenant_repo, identity_repo, pool)
}

fn make_identity(tenant_id: Uuid, pool_id: Uuid) -> Identity {
    Identity {
        id: Uuid::new_v4(),
        tenant_id,
        pool_id,
        kind: IdentityKind::Human,
        username: format!("mfa_user_{}", Uuid::new_v4()),
        email: Some(format!("mfa.{}@knox.com", Uuid::new_v4())),
        password_hash: None,
        email_verified: false,
        first_name: None,
        last_name: None,
        metadata: serde_json::json!({}),
        custom_attributes: serde_json::json!({}),
        status: Status::Active,
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    }
}

async fn create_fixtures(
    tenant_repo: &impl TenantRepository,
    identity_repo: &impl IdentityRepository,
    db: &sqlx::PgPool,
) -> (Uuid, Uuid, Uuid) {
    let suffix = Uuid::new_v4();
    let tenant = tenant_repo
        .create(
            &format!("MFA Test Corp {}", suffix),
            &format!("mfa-test-{}", suffix),
            &format!("https://mfa-test-{}.example.test", suffix),
            None,
            false,
        )
        .await
        .expect("Failed to create tenant");

    let pool_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO pools (tenant_id, slug, name, kind) VALUES ($1, 'staff', 'Staff', 'staff') RETURNING id",
    )
    .bind(tenant.id)
    .fetch_one(db)
    .await
    .expect("Failed to create staff pool");

    let identity = identity_repo
        .create(&make_identity(tenant.id, pool_id))
        .await
        .expect("Failed to create identity");

    (tenant.id, pool_id, identity.id)
}

fn new_totp_method(tenant_id: Uuid, identity_id: Uuid) -> NewMfaMethod {
    NewMfaMethod {
        tenant_id,
        identity_id,
        method: MfaMethodKind::Totp,
        secret_enc: Some(vec![1, 2, 3, 4]),
        public_data: serde_json::json!({"algorithm": "SHA1", "digits": 6, "step": 30}),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_mfa_totp_full_lifecycle() {
    let (mfa_repo, tenant_repo, identity_repo, db) = setup().await;
    let (tenant_id, _, identity_id) = create_fixtures(&tenant_repo, &identity_repo, &db).await;

    // CREATE (unverified)
    let created = mfa_repo
        .create_method(&new_totp_method(tenant_id, identity_id))
        .await
        .expect("Failed to create method");
    assert_eq!(created.method, MfaMethodKind::Totp);
    assert!(created.verified_at.is_none());

    // Unverified enrollment can be restarted: a second create replaces it
    let replacement = mfa_repo
        .create_method(&new_totp_method(tenant_id, identity_id))
        .await
        .expect("Restarting an unverified enrollment should succeed");
    assert_ne!(replacement.id, created.id);
    assert!(
        mfa_repo
            .get_method(tenant_id, identity_id, created.id)
            .await
            .unwrap()
            .is_none(),
        "Replaced enrollment should be gone"
    );

    // Not visible as verified yet
    let verified = mfa_repo
        .list_verified_methods(tenant_id, identity_id)
        .await
        .unwrap();
    assert!(verified.is_empty());

    // VERIFY
    let marked = mfa_repo
        .mark_verified(tenant_id, replacement.id)
        .await
        .expect("Failed to mark verified");
    assert!(marked.verified_at.is_some());

    // Cache was invalidated by mark_verified -> fresh list shows the method
    let verified = mfa_repo
        .list_verified_methods(tenant_id, identity_id)
        .await
        .unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].id, replacement.id);

    // A verified TOTP enrollment cannot be replaced
    let dup = mfa_repo
        .create_method(&new_totp_method(tenant_id, identity_id))
        .await;
    assert!(
        matches!(dup, Err(RepositoryError::Duplicate(_))),
        "Expected Duplicate, got: {:?}",
        dup
    );

    // GET by kind
    let by_kind = mfa_repo
        .get_method_by_kind(tenant_id, identity_id, MfaMethodKind::Totp)
        .await
        .unwrap()
        .expect("Expected Some");
    assert_eq!(by_kind.id, replacement.id);

    // DELETE
    mfa_repo
        .delete_method(tenant_id, identity_id, replacement.id)
        .await
        .expect("Failed to delete");
    let verified = mfa_repo
        .list_verified_methods(tenant_id, identity_id)
        .await
        .unwrap();
    assert!(verified.is_empty());

    // Deleting again -> NotFound
    let missing = mfa_repo
        .delete_method(tenant_id, identity_id, replacement.id)
        .await;
    assert!(matches!(missing, Err(RepositoryError::NotFound)));
}

#[tokio::test]
#[serial]
async fn test_claim_totp_step_is_monotonic() {
    let (mfa_repo, tenant_repo, identity_repo, db) = setup().await;
    let (tenant_id, _, identity_id) = create_fixtures(&tenant_repo, &identity_repo, &db).await;

    let method = mfa_repo
        .create_method(&new_totp_method(tenant_id, identity_id))
        .await
        .unwrap();

    // First claim succeeds
    assert!(
        mfa_repo
            .claim_totp_step(tenant_id, method.id, 100)
            .await
            .unwrap()
    );
    // Same step again (replay) fails
    assert!(
        !mfa_repo
            .claim_totp_step(tenant_id, method.id, 100)
            .await
            .unwrap()
    );
    // Older step fails
    assert!(
        !mfa_repo
            .claim_totp_step(tenant_id, method.id, 99)
            .await
            .unwrap()
    );
    // Newer step succeeds
    assert!(
        mfa_repo
            .claim_totp_step(tenant_id, method.id, 101)
            .await
            .unwrap()
    );

    // Wrong tenant cannot claim
    assert!(
        !mfa_repo
            .claim_totp_step(Uuid::new_v4(), method.id, 200)
            .await
            .unwrap()
    );
}

#[tokio::test]
#[serial]
async fn test_backup_codes_lifecycle() {
    let (mfa_repo, tenant_repo, identity_repo, db) = setup().await;
    let (tenant_id, _, identity_id) = create_fixtures(&tenant_repo, &identity_repo, &db).await;

    let hashes: Vec<String> = (0..3)
        .map(|i| format!("hash_{}_{}", i, Uuid::new_v4()))
        .collect();
    mfa_repo
        .replace_backup_codes(tenant_id, identity_id, &hashes)
        .await
        .expect("Failed to store codes");
    assert_eq!(
        mfa_repo
            .count_unused_backup_codes(tenant_id, identity_id)
            .await
            .unwrap(),
        3
    );

    // Consume once
    assert!(
        mfa_repo
            .consume_backup_code(tenant_id, identity_id, &hashes[0])
            .await
            .unwrap()
    );
    // Double-spend fails
    assert!(
        !mfa_repo
            .consume_backup_code(tenant_id, identity_id, &hashes[0])
            .await
            .unwrap()
    );
    // Unknown code fails
    assert!(
        !mfa_repo
            .consume_backup_code(tenant_id, identity_id, "nonexistent")
            .await
            .unwrap()
    );
    assert_eq!(
        mfa_repo
            .count_unused_backup_codes(tenant_id, identity_id)
            .await
            .unwrap(),
        2
    );

    // Regeneration replaces everything: old codes stop working
    let new_hashes: Vec<String> = (0..2)
        .map(|i| format!("new_{}_{}", i, Uuid::new_v4()))
        .collect();
    mfa_repo
        .replace_backup_codes(tenant_id, identity_id, &new_hashes)
        .await
        .unwrap();
    assert!(
        !mfa_repo
            .consume_backup_code(tenant_id, identity_id, &hashes[1])
            .await
            .unwrap()
    );
    assert!(
        mfa_repo
            .consume_backup_code(tenant_id, identity_id, &new_hashes[0])
            .await
            .unwrap()
    );

    // Delete all
    mfa_repo
        .delete_backup_codes(tenant_id, identity_id)
        .await
        .unwrap();
    assert_eq!(
        mfa_repo
            .count_unused_backup_codes(tenant_id, identity_id)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
#[serial]
async fn test_identity_delete_cascades_mfa_rows() {
    let (mfa_repo, tenant_repo, identity_repo, db) = setup().await;
    let (tenant_id, pool_id, identity_id) =
        create_fixtures(&tenant_repo, &identity_repo, &db).await;

    let method = mfa_repo
        .create_method(&new_totp_method(tenant_id, identity_id))
        .await
        .unwrap();
    mfa_repo
        .replace_backup_codes(tenant_id, identity_id, &["h1".to_string()])
        .await
        .unwrap();

    identity_repo
        .delete(
            pool_id,
            knox_common::identity::IdentityHandle::Id(identity_id),
        )
        .await
        .expect("Failed to delete identity");

    assert!(
        mfa_repo
            .get_method(tenant_id, identity_id, method.id)
            .await
            .unwrap()
            .is_none(),
        "MFA method should cascade-delete with the identity"
    );
    assert_eq!(
        mfa_repo
            .count_unused_backup_codes(tenant_id, identity_id)
            .await
            .unwrap(),
        0,
        "Backup codes should cascade-delete with the identity"
    );
}

#[tokio::test]
#[serial]
async fn test_webauthn_allows_multiple_credentials() {
    let (mfa_repo, tenant_repo, identity_repo, db) = setup().await;
    let (tenant_id, _, identity_id) = create_fixtures(&tenant_repo, &identity_repo, &db).await;

    let make_webauthn = |label: &str| NewMfaMethod {
        tenant_id,
        identity_id,
        method: MfaMethodKind::WebAuthn,
        secret_enc: None,
        public_data: serde_json::json!({"label": label}),
    };

    let first = mfa_repo
        .create_method(&make_webauthn("YubiKey"))
        .await
        .unwrap();
    let second = mfa_repo
        .create_method(&make_webauthn("Passkey"))
        .await
        .unwrap();
    assert_ne!(first.id, second.id);

    let all = mfa_repo.list_methods(tenant_id, identity_id).await.unwrap();
    assert_eq!(all.len(), 2);
}
