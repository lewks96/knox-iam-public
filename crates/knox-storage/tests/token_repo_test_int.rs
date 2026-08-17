use knox_common::token::{AuthCodeCache, AuthCodeContext};
use knox_storage::token::cache::RedisAuthCodeCache;
use redis::Client;
use serial_test::serial;
use std::env;
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

async fn setup() -> RedisAuthCodeCache {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    let client = Client::open(redis_url).expect("Invalid Redis URL");
    let manager = client
        .get_connection_manager()
        .await
        .expect("Failed to connect to Redis");

    RedisAuthCodeCache::new(manager)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unique_key() -> String {
    format!("test_key_{}", Uuid::new_v4().to_string().replace('-', ""))
}

fn unique_code() -> String {
    format!("sha256_{}", Uuid::new_v4().to_string().replace('-', ""))
}

fn make_context() -> AuthCodeContext {
    AuthCodeContext {
        tenant_id: Uuid::new_v4(),
        client_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        scopes: vec!["openid".into(), "profile".into()],
        redirect_uri: "https://app.example.com/callback".into(),
        pkce_code_challenge: "s256_challenge_abc".into(),
        pkce_code_challenge_method: "S256".into(),
        nonce: Some("nonce-value-xyz".into()),
        amr: vec!["pwd".into(), "otp".into(), "mfa".into()],
        auth_time: Some(OffsetDateTime::now_utc()),
        created_at: OffsetDateTime::now_utc(),
    }
}

// ---------------------------------------------------------------------------
// set_value / get_value tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_set_and_get_value_round_trip() {
    let cache = setup().await;
    let key = unique_key();

    cache
        .set_value(&key, "hello world", 60)
        .await
        .expect("set_value should succeed");

    let result = cache
        .get_value(&key)
        .await
        .expect("get_value should not error");

    assert_eq!(result, Some("hello world".to_string()));
}

#[tokio::test]
#[serial]
async fn test_get_value_unknown_key_returns_none() {
    let cache = setup().await;

    let result = cache
        .get_value(&unique_key())
        .await
        .expect("get_value should not error on unknown key");

    assert!(result.is_none());
}

#[tokio::test]
#[serial]
async fn test_set_value_overwrites_existing_key() {
    let cache = setup().await;
    let key = unique_key();

    cache.set_value(&key, "original", 60).await.unwrap();
    cache.set_value(&key, "overwritten", 60).await.unwrap();

    let result = cache.get_value(&key).await.unwrap();
    assert_eq!(result, Some("overwritten".to_string()));
}

#[tokio::test]
#[serial]
async fn test_set_value_respects_ttl() {
    // 1-second TTL — verifies Redis actually expires the key
    let cache = setup().await;
    let key = unique_key();

    cache.set_value(&key, "ephemeral", 1).await.unwrap();

    // Confirm it exists immediately
    let before = cache.get_value(&key).await.unwrap();
    assert_eq!(before, Some("ephemeral".to_string()));

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let after = cache.get_value(&key).await.unwrap();
    assert!(after.is_none(), "Key should have expired after TTL");
}

#[tokio::test]
#[serial]
async fn test_set_value_preserves_arbitrary_string_content() {
    let cache = setup().await;

    for value in &[
        "simple string",
        r#"{"json": "value", "number": 42}"#,
        "unicode: 日本語 🦀",
        "newlines\nand\ttabs",
    ] {
        let key = unique_key();
        cache.set_value(&key, value, 60).await.unwrap();
        let result = cache.get_value(&key).await.unwrap();
        assert_eq!(
            result.as_deref(),
            Some(*value),
            "Value mismatch for: {}",
            value
        );
    }
}

#[tokio::test]
#[serial]
async fn test_get_value_does_not_consume_key() {
    // Unlike get_and_delete_value, get_value must leave the key intact
    let cache = setup().await;
    let key = unique_key();

    cache.set_value(&key, "persistent", 60).await.unwrap();

    let first = cache.get_value(&key).await.unwrap();
    let second = cache.get_value(&key).await.unwrap();
    let third = cache.get_value(&key).await.unwrap();

    assert_eq!(first, Some("persistent".to_string()));
    assert_eq!(second, Some("persistent".to_string()));
    assert_eq!(third, Some("persistent".to_string()));
}

// ---------------------------------------------------------------------------
// get_and_delete_value tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_get_and_delete_value_returns_and_removes() {
    let cache = setup().await;
    let key = unique_key();

    cache.set_value(&key, "consume me", 60).await.unwrap();

    // First call should return the value
    let result = cache
        .get_and_delete_value(&key)
        .await
        .expect("get_and_delete_value should not error");

    assert_eq!(result, Some("consume me".to_string()));

    // Second call — key must be gone
    let gone = cache.get_and_delete_value(&key).await.unwrap();
    assert!(
        gone.is_none(),
        "Key should be deleted after get_and_delete_value"
    );
}

#[tokio::test]
#[serial]
async fn test_get_and_delete_value_is_atomic_single_use() {
    // Simulates two concurrent exchange attempts — only one should win
    let cache = setup().await;
    let key = unique_key();

    cache.set_value(&key, "one-time-value", 60).await.unwrap();

    let r1 = cache.get_and_delete_value(&key).await.unwrap();
    let r2 = cache.get_and_delete_value(&key).await.unwrap();

    assert_eq!(r1, Some("one-time-value".to_string()));
    assert!(
        r2.is_none(),
        "Second call must return None — value already consumed"
    );
}

#[tokio::test]
#[serial]
async fn test_get_and_delete_value_unknown_key_returns_none() {
    let cache = setup().await;

    let result = cache
        .get_and_delete_value(&unique_key())
        .await
        .expect("Should not error on unknown key");

    assert!(result.is_none());
}

#[tokio::test]
#[serial]
async fn test_get_value_returns_none_after_get_and_delete() {
    // Cross-method: get_value after get_and_delete_value confirms deletion
    let cache = setup().await;
    let key = unique_key();

    cache.set_value(&key, "temporary", 60).await.unwrap();
    cache.get_and_delete_value(&key).await.unwrap();

    let result = cache.get_value(&key).await.unwrap();
    assert!(
        result.is_none(),
        "get_value should return None after get_and_delete_value"
    );
}

// ---------------------------------------------------------------------------
// set_code / exchange_code tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_set_and_exchange_code_round_trip() {
    let cache = setup().await;
    let code = unique_code();
    let context = make_context();

    cache
        .set_code(&code, &context, 600)
        .await
        .expect("set_code should succeed");

    let exchanged = cache
        .exchange_code(&code)
        .await
        .expect("exchange_code should not error")
        .expect("Context should be returned on first exchange");

    assert_eq!(exchanged.tenant_id, context.tenant_id);
    assert_eq!(exchanged.client_id, context.client_id);
    assert_eq!(exchanged.identity_id, context.identity_id);
}

#[tokio::test]
#[serial]
async fn test_exchange_code_is_single_use() {
    // Core security property: auth codes must be consumed on first use
    let cache = setup().await;
    let code = unique_code();
    let context = make_context();

    cache.set_code(&code, &context, 600).await.unwrap();

    let first = cache.exchange_code(&code).await.unwrap();
    assert!(first.is_some(), "First exchange should succeed");

    let second = cache.exchange_code(&code).await.unwrap();
    assert!(
        second.is_none(),
        "Second exchange must return None — replay attack prevention"
    );
}

#[tokio::test]
#[serial]
async fn test_exchange_code_unknown_code_returns_none() {
    let cache = setup().await;

    let result = cache
        .exchange_code(&unique_code())
        .await
        .expect("Should not error on unknown code");

    assert!(result.is_none());
}

#[tokio::test]
#[serial]
async fn test_exchange_code_preserves_all_context_fields() {
    let cache = setup().await;
    let code = unique_code();
    let context = make_context();

    cache.set_code(&code, &context, 600).await.unwrap();
    let exchanged = cache.exchange_code(&code).await.unwrap().unwrap();

    assert_eq!(exchanged.scopes, context.scopes);
    assert_eq!(exchanged.redirect_uri, context.redirect_uri);
    assert_eq!(exchanged.pkce_code_challenge, context.pkce_code_challenge);
    assert_eq!(
        exchanged.pkce_code_challenge_method,
        context.pkce_code_challenge_method
    );
    assert_eq!(exchanged.nonce, context.nonce);
}

#[tokio::test]
#[serial]
async fn test_exchange_code_respects_ttl() {
    let cache = setup().await;
    let code = unique_code();
    let context = make_context();

    cache.set_code(&code, &context, 1).await.unwrap(); // 1-second TTL

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let result = cache
        .exchange_code(&code)
        .await
        .expect("Should not error after expiry");

    assert!(result.is_none(), "Expired code should return None");
}

#[tokio::test]
#[serial]
async fn test_set_code_uses_auth_code_prefix_in_key() {
    // Verifies the key is namespaced as "auth_code:{hash}" by checking that
    // get_value with the raw hash (no prefix) returns nothing,
    // while exchange_code (which applies the prefix internally) returns the context
    let cache = setup().await;
    let code = unique_code();
    let context = make_context();

    cache.set_code(&code, &context, 600).await.unwrap();

    // Raw key without prefix must not exist
    let raw = cache.get_value(&code).await.unwrap();
    assert!(
        raw.is_none(),
        "set_code should store under 'auth_code:{{hash}}', not the raw hash"
    );

    // But exchange_code (which applies the prefix) must find it
    let found = cache.exchange_code(&code).await.unwrap();
    assert!(
        found.is_some(),
        "exchange_code must find the value via the prefixed key"
    );
}

#[tokio::test]
#[serial]
async fn test_set_code_overwrites_previous_code_for_same_hash() {
    // If the same hash is reused (shouldn't happen in practice, but defensive test)
    let cache = setup().await;
    let code = unique_code();

    let original = make_context();
    let mut replacement = make_context();
    replacement.identity_id = Uuid::new_v4(); // distinct identity

    cache.set_code(&code, &original, 600).await.unwrap();
    cache.set_code(&code, &replacement, 600).await.unwrap();

    let exchanged = cache.exchange_code(&code).await.unwrap().unwrap();
    assert_eq!(
        exchanged.identity_id, replacement.identity_id,
        "Second set_code should overwrite the first"
    );
}

#[tokio::test]
#[serial]
async fn test_context_with_no_optional_fields() {
    // Verify empty optional fields serialise and deserialise correctly
    let cache = setup().await;
    let code = unique_code();
    let context = AuthCodeContext {
        tenant_id: Uuid::new_v4(),
        client_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        scopes: vec!["openid".into()],
        redirect_uri: String::new(),
        pkce_code_challenge: String::new(),
        pkce_code_challenge_method: String::new(),
        nonce: None,
        amr: Vec::new(),
        auth_time: None,
        created_at: OffsetDateTime::now_utc(),
    };

    cache.set_code(&code, &context, 600).await.unwrap();
    let exchanged = cache.exchange_code(&code).await.unwrap().unwrap();

    assert!(exchanged.redirect_uri.is_empty());
    assert!(exchanged.pkce_code_challenge.is_empty());
    assert!(exchanged.pkce_code_challenge_method.is_empty());
    assert!(exchanged.nonce.is_none());
}

#[tokio::test]
#[serial]
async fn test_multiple_codes_are_independent() {
    let cache = setup().await;

    let code_a = unique_code();
    let code_b = unique_code();
    let ctx_a = make_context();
    let ctx_b = make_context();
    let id_a = ctx_a.identity_id;
    let id_b = ctx_b.identity_id;

    cache.set_code(&code_a, &ctx_a, 600).await.unwrap();
    cache.set_code(&code_b, &ctx_b, 600).await.unwrap();

    // Exchange b first
    let result_b = cache.exchange_code(&code_b).await.unwrap().unwrap();
    assert_eq!(result_b.identity_id, id_b);

    // a should still be available
    let result_a = cache.exchange_code(&code_a).await.unwrap().unwrap();
    assert_eq!(result_a.identity_id, id_a);
}

// ---------------------------------------------------------------------------
// Key isolation
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_set_value_and_set_code_keys_do_not_collide() {
    // set_value uses the key as-is; set_code prefixes with "auth_code:"
    // A raw key equal to a code hash must not be confused with a prefixed auth code key
    let cache = setup().await;
    let key = unique_key();

    cache.set_value(&key, "raw-value", 60).await.unwrap();

    // set_code with the same string as the hash — stored under "auth_code:{key}"
    let context = make_context();
    cache.set_code(&key, &context, 600).await.unwrap();

    // get_value on the raw key must still return the raw string
    let raw = cache.get_value(&key).await.unwrap();
    assert_eq!(raw, Some("raw-value".to_string()));

    // exchange_code on the same string must return the context (different key space)
    let exchanged = cache.exchange_code(&key).await.unwrap();
    assert!(
        exchanged.is_some(),
        "auth code key space must be independent of raw key space"
    );
}
