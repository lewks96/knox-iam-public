use knox_common::client::{Client, ClientFilter, ClientRepository, ClientType, ClientUpdates};
use knox_common::identity::Status;
use knox_common::tenant::TenantRepository;
use knox_storage::client::cache::RedisClientCache;
use knox_storage::client::repository::KnoxClientRepository;
use knox_storage::client::store::PgClientStore;
use knox_storage::tenant::cache::RedisTenantCache;
use knox_storage::tenant::repository::KnoxTenantRepository;
use knox_storage::tenant::store::PgTenantStore;
use redis::Client as RedisClient;
use serial_test::serial;
use sqlx::postgres::PgPoolOptions;
use std::env;
use uuid::Uuid;

// --- Helper: Setup Repositories ---
async fn setup() -> (impl ClientRepository, impl TenantRepository, sqlx::PgPool) {
    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://admin:password@localhost:5432/knox".to_string());
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    let client = RedisClient::open(redis_url).unwrap();
    let manager = client.get_connection_manager().await.unwrap();

    // Tenant Repo
    let t_store = PgTenantStore::new(pool.clone());
    let t_cache = RedisTenantCache::new(manager.clone());
    let tenant_repo = KnoxTenantRepository::new(t_store, t_cache);

    // Client Repo
    let c_store = PgClientStore::new(pool.clone());
    let c_cache = RedisClientCache::new(manager);
    let client_repo = KnoxClientRepository::new(c_store, c_cache);

    (client_repo, tenant_repo, pool)
}

#[tokio::test]
#[serial]
async fn test_client_full_lifecycle() {
    let (client_repo, tenant_repo, db) = setup().await;

    // 1. PRE-REQ: Create a Tenant
    let suffix = Uuid::new_v4();
    let tenant = tenant_repo
        .create(
            &format!("Client Test Corp {suffix}"),
            &format!("client-test-{suffix}"),
            &format!("https://client-test-{suffix}.example.test"),
            None,
            false,
        )
        .await
        .expect("Failed to create tenant");
    let pool_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO pools (tenant_id, slug, name, kind) VALUES ($1, 'staff', 'Staff', 'staff') RETURNING id",
    )
    .bind(tenant.id)
    .fetch_one(&db)
    .await
    .expect("Failed to create staff pool");

    // 2. CREATE CLIENT (e.g., a Public SPA like a React App)
    let client_id = Uuid::new_v4();
    let new_client = Client {
        id: client_id,
        tenant_id: tenant.id,
        pool_id,
        name: "My React Frontend".to_string(),
        description: Some("Main customer portal".to_string()),
        logo_uri: None,

        client_type: ClientType::Public,
        client_secret_hash: None, // Public clients have no secret
        token_endpoint_auth_method: "none".to_string(), // PKCE only
        allow_refresh_tokens: true,

        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        response_types: vec!["code".to_string()],
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        post_logout_redirect_uris: vec!["https://app.example.com/".to_string()],
        allowed_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],

        require_pkce: true, // Mandatory for SPAs
        require_auth_time: false,

        access_token_ttl: 3600,
        refresh_token_ttl: 86400 * 7, // 7 days
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
        metadata: serde_json::json!({"environment": "production"}),
        custom_attributes: serde_json::json!({}),

        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    };

    let created = client_repo
        .create(&new_client)
        .await
        .expect("Failed to create client");
    assert_eq!(created.name, "My React Frontend");
    assert!(created.require_pkce);

    // 3. GET (Should Hit DB and Populate Cache)
    let fetched = client_repo
        .get(tenant.id, client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.id, client_id);

    // 4. GET AGAIN (Should Hit Cache)
    let fetched_cached = client_repo
        .get(tenant.id, client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_cached.token_version, 1);

    // 5. UPDATE (Rotate Token Version & Update Description)
    let updates = ClientUpdates {
        description: Some("Main customer portal (V2)".to_string()),
        token_version: Some(2), // Invalidates all existing tokens for this client!
        ..Default::default()
    };

    let updated = client_repo
        .update(tenant.id, client_id, &updates)
        .await
        .expect("Failed to update client");
    assert_eq!(
        updated.description.as_deref(),
        Some("Main customer portal (V2)")
    );
    assert_eq!(updated.token_version, 2);

    // 6. VERIFY CACHE WRITE-THROUGH
    let check = client_repo
        .get(tenant.id, client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(check.token_version, 2);

    // 7. LIST CLIENTS
    let filter = ClientFilter {
        tenant_id: tenant.id,
        page: 1,
        page_size: 10,
        status: None,
    };
    let (list, total) = client_repo
        .list(&filter)
        .await
        .expect("Failed to list clients");
    assert_eq!(total, 1);
    assert_eq!(list[0].id, client_id);

    // 8. DELETE CLIENT
    client_repo
        .delete(tenant.id, client_id)
        .await
        .expect("Failed to delete client");

    // 9. VERIFY DELETION (From both DB and Cache)
    let gone = client_repo.get(tenant.id, client_id).await.unwrap();
    assert!(gone.is_none(), "Client should be deleted");
}
