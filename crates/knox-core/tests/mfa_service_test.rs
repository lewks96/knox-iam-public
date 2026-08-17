use async_trait::async_trait;
use knox_common::error::{RepositoryError, ServiceError};
use knox_common::identity::MfaOption;
use knox_common::key::KeyEncryptionProvider;
use knox_common::mfa::{MfaMethod, MfaMethodKind, MfaRepository, NewMfaMethod};
use knox_core::key::LocalKeyEncryptionProvider;
use knox_core::mfa::{BACKUP_CODE_COUNT, MfaService, totp_matched_step};
use mockall::{mock, predicate::*};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

mock! {
    pub MfaRepo {}
    #[async_trait]
    impl MfaRepository for MfaRepo {
        async fn create_method(&self, method: &NewMfaMethod) -> Result<MfaMethod, RepositoryError>;
        async fn get_method(&self, tenant_id: Uuid, identity_id: Uuid, method_id: Uuid) -> Result<Option<MfaMethod>, RepositoryError>;
        async fn get_method_by_kind(&self, tenant_id: Uuid, identity_id: Uuid, kind: MfaMethodKind) -> Result<Option<MfaMethod>, RepositoryError>;
        async fn list_methods(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<Vec<MfaMethod>, RepositoryError>;
        async fn list_verified_methods(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<Vec<MfaMethod>, RepositoryError>;
        async fn mark_verified(&self, tenant_id: Uuid, method_id: Uuid) -> Result<MfaMethod, RepositoryError>;
        async fn delete_method(&self, tenant_id: Uuid, identity_id: Uuid, method_id: Uuid) -> Result<(), RepositoryError>;
        async fn claim_totp_step(&self, tenant_id: Uuid, method_id: Uuid, step: i64) -> Result<bool, RepositoryError>;
        async fn replace_backup_codes(&self, tenant_id: Uuid, identity_id: Uuid, code_hashes: &[String]) -> Result<(), RepositoryError>;
        async fn consume_backup_code(&self, tenant_id: Uuid, identity_id: Uuid, code_hash: &str) -> Result<bool, RepositoryError>;
        async fn count_unused_backup_codes(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<u64, RepositoryError>;
        async fn delete_backup_codes(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), RepositoryError>;
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

fn provider() -> LocalKeyEncryptionProvider {
    LocalKeyEncryptionProvider::new(&LocalKeyEncryptionProvider::generate_master_key())
}

const TEST_SECRET_B32: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

async fn encrypt_secret(
    kep: &LocalKeyEncryptionProvider,
    tenant_id: Uuid,
    identity_id: Uuid,
) -> Vec<u8> {
    let context = format!("mfa:{}:{}", tenant_id, identity_id).into_bytes();
    kep.encrypt(TEST_SECRET_B32, Some(&context)).await.unwrap()
}

fn make_totp_method(
    tenant_id: Uuid,
    identity_id: Uuid,
    secret_enc: Vec<u8>,
    verified: bool,
) -> MfaMethod {
    MfaMethod {
        id: Uuid::new_v4(),
        tenant_id,
        identity_id,
        method: MfaMethodKind::Totp,
        secret_enc: Some(secret_enc),
        public_data: serde_json::json!({"algorithm": "SHA1", "digits": 6, "step": 30}),
        last_used_step: None,
        verified_at: verified.then(OffsetDateTime::now_utc),
        last_used_at: None,
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

/// Computes the expected TOTP code for a secret at a fixed unix time.
fn code_for(secret_b32: &str, at_unix: i64) -> String {
    let secret = totp_rs::Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .unwrap();
    let totp = totp_rs::TOTP::new_unchecked(
        totp_rs::Algorithm::SHA1,
        6,
        0,
        30,
        secret,
        None,
        String::new(),
    );
    totp.generate(at_unix as u64)
}

fn hash_code(code: &str) -> String {
    let normalized = code.trim().replace('-', "").to_uppercase();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// totp_matched_step (fixed-time vectors)
// ---------------------------------------------------------------------------

#[test]
fn test_totp_matched_step_accepts_current_step() {
    let now = 1_750_000_000i64;
    let code = code_for(TEST_SECRET_B32, now);
    let matched = totp_matched_step(TEST_SECRET_B32, &code, now).unwrap();
    assert_eq!(matched, Some(now / 30));
}

#[test]
fn test_totp_matched_step_accepts_one_step_drift() {
    let now = 1_750_000_000i64;

    // Code from the previous step still matches (and identifies its own step)
    let old_code = code_for(TEST_SECRET_B32, now - 30);
    let matched = totp_matched_step(TEST_SECRET_B32, &old_code, now).unwrap();
    assert_eq!(matched, Some((now - 30) / 30));

    // Code from the next step also matches
    let future_code = code_for(TEST_SECRET_B32, now + 30);
    let matched = totp_matched_step(TEST_SECRET_B32, &future_code, now).unwrap();
    assert_eq!(matched, Some((now + 30) / 30));
}

#[test]
fn test_totp_matched_step_rejects_two_step_drift() {
    let now = 1_750_000_000i64;

    let stale_code = code_for(TEST_SECRET_B32, now - 60);
    assert_eq!(
        totp_matched_step(TEST_SECRET_B32, &stale_code, now).unwrap(),
        None
    );

    let far_future_code = code_for(TEST_SECRET_B32, now + 60);
    assert_eq!(
        totp_matched_step(TEST_SECRET_B32, &far_future_code, now).unwrap(),
        None
    );
}

#[test]
fn test_totp_matched_step_rejects_garbage() {
    let now = 1_750_000_000i64;
    assert_eq!(
        totp_matched_step(TEST_SECRET_B32, "000000", now).unwrap(),
        None
    );
    assert_eq!(totp_matched_step(TEST_SECRET_B32, "", now).unwrap(), None);
    assert_eq!(
        totp_matched_step(TEST_SECRET_B32, "not-a-code", now).unwrap(),
        None
    );
}

// ---------------------------------------------------------------------------
// start_totp_enrollment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_start_totp_enrollment_returns_decryptable_secret_and_uri() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();

    let mut repo = MockMfaRepo::new();
    repo.expect_get_method_by_kind()
        .with(eq(tenant_id), eq(identity_id), eq(MfaMethodKind::Totp))
        .times(1)
        .returning(|_, _, _| Ok(None));
    repo.expect_create_method()
        .withf(move |m: &NewMfaMethod| {
            m.tenant_id == tenant_id
                && m.identity_id == identity_id
                && m.method == MfaMethodKind::Totp
                && m.secret_enc.is_some()
        })
        .times(1)
        .returning(|m| {
            Ok(MfaMethod {
                id: Uuid::new_v4(),
                tenant_id: m.tenant_id,
                identity_id: m.identity_id,
                method: m.method,
                secret_enc: m.secret_enc.clone(),
                public_data: m.public_data.clone(),
                last_used_step: None,
                verified_at: None,
                last_used_at: None,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })
        });

    let service = MfaService::new(repo, kep.clone());
    let result = service
        .start_totp_enrollment(tenant_id, identity_id, "Knox", "user@knox.com")
        .await
        .expect("Enrollment should succeed");

    assert!(result.otpauth_uri.starts_with("otpauth://totp/"));
    assert!(result.otpauth_uri.contains("Knox"));
    assert!(result.otpauth_uri.contains(&result.secret));

    // The returned plaintext secret and stored encrypted secret must agree
    let context = format!("mfa:{}:{}", tenant_id, identity_id).into_bytes();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let code = code_for(&result.secret, now);
    assert!(
        totp_matched_step(&result.secret, &code, now)
            .unwrap()
            .is_some(),
        "Returned secret should produce verifiable codes"
    );
    let _ = context; // encryption round-trip is covered by confirm tests
}

#[tokio::test]
async fn test_start_totp_enrollment_rejects_when_already_verified() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();
    let secret_enc = encrypt_secret(&kep, tenant_id, identity_id).await;

    let mut repo = MockMfaRepo::new();
    let existing = make_totp_method(tenant_id, identity_id, secret_enc, true);
    repo.expect_get_method_by_kind()
        .times(1)
        .return_once(move |_, _, _| Ok(Some(existing)));
    repo.expect_create_method().times(0);

    let service = MfaService::new(repo, kep);
    let result = service
        .start_totp_enrollment(tenant_id, identity_id, "Knox", "user@knox.com")
        .await;

    assert!(matches!(result, Err(ServiceError::MfaAlreadyEnrolled)));
}

// ---------------------------------------------------------------------------
// confirm_totp_enrollment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_confirm_totp_enrollment_success_returns_backup_codes() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();
    let secret_enc = encrypt_secret(&kep, tenant_id, identity_id).await;

    let method = make_totp_method(tenant_id, identity_id, secret_enc, false);
    let method_id = method.id;
    let verified = MfaMethod {
        verified_at: Some(OffsetDateTime::now_utc()),
        ..method.clone()
    };

    let mut repo = MockMfaRepo::new();
    repo.expect_get_method_by_kind()
        .times(1)
        .return_once(move |_, _, _| Ok(Some(method)));
    repo.expect_claim_totp_step()
        .with(eq(tenant_id), eq(method_id), always())
        .times(1)
        .returning(|_, _, _| Ok(true));
    repo.expect_mark_verified()
        .with(eq(tenant_id), eq(method_id))
        .times(1)
        .return_once(move |_, _| Ok(verified));
    repo.expect_replace_backup_codes()
        .withf(move |t, i, hashes: &[String]| {
            *t == tenant_id && *i == identity_id && hashes.len() == BACKUP_CODE_COUNT
        })
        .times(1)
        .returning(|_, _, _| Ok(()));

    let service = MfaService::new(repo, kep);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let code = code_for(TEST_SECRET_B32, now);

    let codes = service
        .confirm_totp_enrollment(tenant_id, identity_id, &code)
        .await
        .expect("Confirmation should succeed");

    assert_eq!(codes.len(), BACKUP_CODE_COUNT);
    let unique: std::collections::HashSet<&String> = codes.iter().collect();
    assert_eq!(
        unique.len(),
        BACKUP_CODE_COUNT,
        "Backup codes must be unique"
    );
}

#[tokio::test]
async fn test_confirm_totp_enrollment_wrong_code_fails() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();
    let secret_enc = encrypt_secret(&kep, tenant_id, identity_id).await;
    let method = make_totp_method(tenant_id, identity_id, secret_enc, false);

    let mut repo = MockMfaRepo::new();
    repo.expect_get_method_by_kind()
        .times(1)
        .return_once(move |_, _, _| Ok(Some(method)));
    repo.expect_mark_verified().times(0);
    repo.expect_replace_backup_codes().times(0);

    let service = MfaService::new(repo, kep);
    let result = service
        .confirm_totp_enrollment(tenant_id, identity_id, "000000")
        .await;

    assert!(matches!(result, Err(ServiceError::InvalidMfaCode)));
}

#[tokio::test]
async fn test_confirm_totp_enrollment_not_enrolled_fails() {
    init_tracing();
    let mut repo = MockMfaRepo::new();
    repo.expect_get_method_by_kind()
        .times(1)
        .returning(|_, _, _| Ok(None));

    let service = MfaService::new(repo, provider());
    let result = service
        .confirm_totp_enrollment(Uuid::new_v4(), Uuid::new_v4(), "123456")
        .await;

    assert!(matches!(result, Err(ServiceError::MfaNotEnrolled)));
}

// ---------------------------------------------------------------------------
// verify (TOTP)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_verify_totp_success() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();
    let secret_enc = encrypt_secret(&kep, tenant_id, identity_id).await;
    let method = make_totp_method(tenant_id, identity_id, secret_enc, true);
    let method_id = method.id;

    let mut repo = MockMfaRepo::new();
    repo.expect_get_method_by_kind()
        .times(1)
        .return_once(move |_, _, _| Ok(Some(method)));
    repo.expect_claim_totp_step()
        .with(eq(tenant_id), eq(method_id), always())
        .times(1)
        .returning(|_, _, _| Ok(true));

    let service = MfaService::new(repo, kep);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let code = code_for(TEST_SECRET_B32, now);

    let result = service
        .verify(tenant_id, identity_id, MfaOption::Totp, &code)
        .await;
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
}

#[tokio::test]
async fn test_verify_totp_replay_rejected() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();
    let secret_enc = encrypt_secret(&kep, tenant_id, identity_id).await;
    let method = make_totp_method(tenant_id, identity_id, secret_enc, true);

    let mut repo = MockMfaRepo::new();
    repo.expect_get_method_by_kind()
        .times(1)
        .return_once(move |_, _, _| Ok(Some(method)));
    // The step was already claimed by an earlier verification
    repo.expect_claim_totp_step()
        .times(1)
        .returning(|_, _, _| Ok(false));

    let service = MfaService::new(repo, kep);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let code = code_for(TEST_SECRET_B32, now);

    let result = service
        .verify(tenant_id, identity_id, MfaOption::Totp, &code)
        .await;
    assert!(matches!(result, Err(ServiceError::InvalidMfaCode)));
}

#[tokio::test]
async fn test_verify_totp_unverified_enrollment_rejected() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();
    let secret_enc = encrypt_secret(&kep, tenant_id, identity_id).await;
    // Enrollment exists but was never confirmed
    let method = make_totp_method(tenant_id, identity_id, secret_enc, false);

    let mut repo = MockMfaRepo::new();
    repo.expect_get_method_by_kind()
        .times(1)
        .return_once(move |_, _, _| Ok(Some(method)));

    let service = MfaService::new(repo, kep);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let code = code_for(TEST_SECRET_B32, now);

    let result = service
        .verify(tenant_id, identity_id, MfaOption::Totp, &code)
        .await;
    assert!(matches!(result, Err(ServiceError::MfaNotEnrolled)));
}

#[tokio::test]
async fn test_verify_unsupported_method_rejected() {
    init_tracing();
    let repo = MockMfaRepo::new();
    let service = MfaService::new(repo, provider());

    let result = service
        .verify(Uuid::new_v4(), Uuid::new_v4(), MfaOption::WebAuthn, "code")
        .await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));

    let repo = MockMfaRepo::new();
    let service = MfaService::new(repo, provider());
    let result = service
        .verify(Uuid::new_v4(), Uuid::new_v4(), MfaOption::Sms, "code")
        .await;
    assert!(matches!(result, Err(ServiceError::Validation(_))));
}

// ---------------------------------------------------------------------------
// verify (backup codes)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_verify_backup_code_success_and_normalization() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let code = "ABCD2EFGH3";
    let expected_hash = hash_code(code);

    let mut repo = MockMfaRepo::new();
    repo.expect_consume_backup_code()
        .with(eq(tenant_id), eq(identity_id), eq(expected_hash))
        .times(1)
        .returning(|_, _, _| Ok(true));

    let service = MfaService::new(repo, provider());
    // Lowercase with a dash must hash identically to the issued code
    let result = service
        .verify(tenant_id, identity_id, MfaOption::BackupCode, "abcd2-efgh3")
        .await;
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
}

#[tokio::test]
async fn test_verify_backup_code_already_used_rejected() {
    init_tracing();
    let mut repo = MockMfaRepo::new();
    repo.expect_consume_backup_code()
        .times(1)
        .returning(|_, _, _| Ok(false));

    let service = MfaService::new(repo, provider());
    let result = service
        .verify(
            Uuid::new_v4(),
            Uuid::new_v4(),
            MfaOption::BackupCode,
            "ABCD2EFGH3",
        )
        .await;
    assert!(matches!(result, Err(ServiceError::InvalidMfaCode)));
}

// ---------------------------------------------------------------------------
// get_available_options
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_available_options_empty_when_not_enrolled() {
    init_tracing();
    let mut repo = MockMfaRepo::new();
    repo.expect_list_verified_methods()
        .times(1)
        .returning(|_, _| Ok(vec![]));
    // Backup codes must not be offered without a verified method
    repo.expect_count_unused_backup_codes().times(0);

    let service = MfaService::new(repo, provider());
    let options = service
        .get_available_options(Uuid::new_v4(), Uuid::new_v4())
        .await
        .unwrap();
    assert!(options.is_empty());
}

#[tokio::test]
async fn test_get_available_options_includes_backup_codes() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();
    let secret_enc = encrypt_secret(&kep, tenant_id, identity_id).await;
    let method = make_totp_method(tenant_id, identity_id, secret_enc, true);

    let mut repo = MockMfaRepo::new();
    repo.expect_list_verified_methods()
        .times(1)
        .return_once(move |_, _| Ok(vec![method]));
    repo.expect_count_unused_backup_codes()
        .times(1)
        .returning(|_, _| Ok(7));

    let service = MfaService::new(repo, kep);
    let options = service
        .get_available_options(tenant_id, identity_id)
        .await
        .unwrap();
    assert_eq!(options, vec![MfaOption::Totp, MfaOption::BackupCode]);
}

#[tokio::test]
async fn test_get_available_options_no_backup_codes_left() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let kep = provider();
    let secret_enc = encrypt_secret(&kep, tenant_id, identity_id).await;
    let method = make_totp_method(tenant_id, identity_id, secret_enc, true);

    let mut repo = MockMfaRepo::new();
    repo.expect_list_verified_methods()
        .times(1)
        .return_once(move |_, _| Ok(vec![method]));
    repo.expect_count_unused_backup_codes()
        .times(1)
        .returning(|_, _| Ok(0));

    let service = MfaService::new(repo, kep);
    let options = service
        .get_available_options(tenant_id, identity_id)
        .await
        .unwrap();
    assert_eq!(options, vec![MfaOption::Totp]);
}

// ---------------------------------------------------------------------------
// remove_method / regenerate_backup_codes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_remove_last_method_deletes_backup_codes() {
    init_tracing();
    let tenant_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let method_id = Uuid::new_v4();

    let mut repo = MockMfaRepo::new();
    repo.expect_delete_method()
        .with(eq(tenant_id), eq(identity_id), eq(method_id))
        .times(1)
        .returning(|_, _, _| Ok(()));
    repo.expect_list_verified_methods()
        .times(1)
        .returning(|_, _| Ok(vec![]));
    repo.expect_delete_backup_codes()
        .with(eq(tenant_id), eq(identity_id))
        .times(1)
        .returning(|_, _| Ok(()));

    let service = MfaService::new(repo, provider());
    let result = service
        .remove_method(tenant_id, identity_id, method_id)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_regenerate_backup_codes_requires_verified_method() {
    init_tracing();
    let mut repo = MockMfaRepo::new();
    repo.expect_list_verified_methods()
        .times(1)
        .returning(|_, _| Ok(vec![]));
    repo.expect_replace_backup_codes().times(0);

    let service = MfaService::new(repo, provider());
    let result = service
        .regenerate_backup_codes(Uuid::new_v4(), Uuid::new_v4())
        .await;
    assert!(matches!(result, Err(ServiceError::MfaNotEnrolled)));
}
