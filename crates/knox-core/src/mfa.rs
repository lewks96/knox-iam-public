use knox_common::error::{RepositoryError, ServiceError};
use knox_common::identity::MfaOption;
use knox_common::key::KeyEncryptionProvider;
use knox_common::mfa::{MfaMethod, MfaMethodKind, MfaMethodSummary, MfaRepository, NewMfaMethod};
use rand::{Rng, RngExt};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::{debug, instrument, warn};
use uuid::Uuid;

pub const TOTP_DIGITS: usize = 6;
pub const TOTP_STEP_SECONDS: u64 = 30;
/// Accepted clock drift, in steps either side of "now" (RFC 6238 §5.2).
pub const TOTP_SKEW_STEPS: i64 = 1;
pub const TOTP_SECRET_BYTES: usize = 20;

pub const BACKUP_CODE_COUNT: usize = 10;
pub const BACKUP_CODE_LENGTH: usize = 10;
// Unambiguous uppercase alphanumerics; input is normalized before matching.
const BACKUP_CODE_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Serialize)]
pub struct StartTotpEnrollmentResponse {
    pub method_id: Uuid,
    /// Base32 secret, shown to the user exactly once at enrollment.
    pub secret: String,
    /// otpauth:// provisioning URI; clients render this as a QR code.
    pub otpauth_uri: String,
}

#[derive(Clone)]
pub struct MfaService<M: MfaRepository, KP: KeyEncryptionProvider> {
    repo: M,
    kep: KP,
}

impl<M: MfaRepository, KP: KeyEncryptionProvider> MfaService<M, KP> {
    pub fn new(repo: M, kep: KP) -> Self {
        Self { repo, kep }
    }

    /// Creates an unverified TOTP enrollment and returns the provisioning
    /// details. The enrollment only becomes usable for login after
    /// `confirm_totp_enrollment` proves the user's authenticator works.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn start_totp_enrollment(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        issuer: &str,
        account_name: &str,
    ) -> Result<StartTotpEnrollmentResponse, ServiceError> {
        if let Some(existing) = self
            .repo
            .get_method_by_kind(tenant_id, identity_id, MfaMethodKind::Totp)
            .await?
            && existing.verified_at.is_some()
        {
            return Err(ServiceError::MfaAlreadyEnrolled);
        }

        let mut secret_bytes = [0u8; TOTP_SECRET_BYTES];
        rand::rng().fill_bytes(&mut secret_bytes);
        let secret_b32 = match Secret::Raw(secret_bytes.to_vec()).to_encoded() {
            Secret::Encoded(s) => s,
            Secret::Raw(_) => unreachable!("to_encoded always returns Encoded"),
        };

        // otpauth URIs use ':' as the issuer/account separator
        let issuer = issuer.replace(':', "");
        let account_name = account_name.replace(':', "");
        let totp = TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            1,
            TOTP_STEP_SECONDS,
            secret_bytes.to_vec(),
            Some(issuer),
            account_name,
        )
        .map_err(|e| ServiceError::Internal(format!("TOTP setup failed: {}", e)))?;

        let secret_enc = self
            .kep
            .encrypt(
                &secret_b32,
                Some(&encryption_context(tenant_id, identity_id)),
            )
            .await
            .map_err(|e| ServiceError::Internal(format!("Secret encryption failed: {}", e)))?;

        let created = self
            .repo
            .create_method(&NewMfaMethod {
                tenant_id,
                identity_id,
                method: MfaMethodKind::Totp,
                secret_enc: Some(secret_enc),
                public_data: json!({
                    "algorithm": "SHA1",
                    "digits": TOTP_DIGITS,
                    "step": TOTP_STEP_SECONDS,
                }),
            })
            .await
            .map_err(|e| match e {
                RepositoryError::Duplicate(_) => ServiceError::MfaAlreadyEnrolled,
                other => ServiceError::Repository(other),
            })?;

        debug!(
            "Started TOTP enrollment {} for identity {}",
            created.id, identity_id
        );

        Ok(StartTotpEnrollmentResponse {
            method_id: created.id,
            secret: secret_b32,
            otpauth_uri: totp.get_url(),
        })
    }

    /// Verifies the first code from the user's authenticator, marks the
    /// enrollment verified, and returns freshly generated backup codes
    /// (shown to the user exactly once).
    #[instrument(skip(self, code), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn confirm_totp_enrollment(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code: &str,
    ) -> Result<Vec<String>, ServiceError> {
        let method = self
            .repo
            .get_method_by_kind(tenant_id, identity_id, MfaMethodKind::Totp)
            .await?
            .ok_or(ServiceError::MfaNotEnrolled)?;

        if method.verified_at.is_some() {
            return Err(ServiceError::MfaAlreadyEnrolled);
        }

        self.check_totp_code(&method, code).await?;
        self.repo.mark_verified(tenant_id, method.id).await?;

        let codes = generate_backup_codes();
        let hashes: Vec<String> = codes.iter().map(|c| hash_backup_code(c)).collect();
        self.repo
            .replace_backup_codes(tenant_id, identity_id, &hashes)
            .await?;

        debug!(
            "TOTP enrollment {} confirmed for identity {}",
            method.id, identity_id
        );

        Ok(codes)
    }

    /// Verifies an MFA code during login. Dispatches on the chosen option;
    /// adding a new factor later means adding a match arm here.
    #[instrument(skip(self, code), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn verify(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method: MfaOption,
        code: &str,
    ) -> Result<(), ServiceError> {
        match method {
            MfaOption::Totp => self.verify_totp(tenant_id, identity_id, code).await,
            MfaOption::BackupCode => self.verify_backup_code(tenant_id, identity_id, code).await,
            MfaOption::WebAuthn | MfaOption::Sms => Err(ServiceError::Validation(
                "MFA method not supported yet".into(),
            )),
        }
    }

    /// The verification options available to an identity at login. Empty
    /// means MFA is not required for this identity.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn get_available_options(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaOption>, ServiceError> {
        let methods = self
            .repo
            .list_verified_methods(tenant_id, identity_id)
            .await?;

        let mut options: Vec<MfaOption> = methods.iter().map(|m| m.method.into()).collect();

        if !options.is_empty()
            && self
                .repo
                .count_unused_backup_codes(tenant_id, identity_id)
                .await?
                > 0
        {
            options.push(MfaOption::BackupCode);
        }

        Ok(options)
    }

    #[instrument(skip(self), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn list_methods(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<MfaMethodSummary>, ServiceError> {
        let methods = self.repo.list_methods(tenant_id, identity_id).await?;
        Ok(methods.iter().map(MfaMethodSummary::from).collect())
    }

    /// Removes an enrollment. When no verified methods remain the backup
    /// codes are deleted too - they are only meaningful alongside a factor.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn remove_method(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        method_id: Uuid,
    ) -> Result<(), ServiceError> {
        self.repo
            .delete_method(tenant_id, identity_id, method_id)
            .await?;

        let remaining = self
            .repo
            .list_verified_methods(tenant_id, identity_id)
            .await?;
        if remaining.is_empty() {
            self.repo
                .delete_backup_codes(tenant_id, identity_id)
                .await?;
        }

        Ok(())
    }

    /// Clears every MFA enrolment for an identity, backup codes included.
    ///
    /// Admin break-glass for a user who has lost their only second factor: with
    /// no verified method and no backup codes, login stops demanding MFA, so a
    /// password reset can actually get them back in. Removing each method
    /// individually would leave the same end state, but this states the intent
    /// and drops the backup codes once (they are meaningless without a factor).
    #[instrument(skip(self), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn remove_all(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), ServiceError> {
        let methods = self.repo.list_methods(tenant_id, identity_id).await?;
        for method in &methods {
            self.repo
                .delete_method(tenant_id, identity_id, method.id)
                .await?;
        }
        self.repo
            .delete_backup_codes(tenant_id, identity_id)
            .await?;
        Ok(())
    }

    /// Replaces all backup codes; previously issued codes stop working.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn regenerate_backup_codes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<String>, ServiceError> {
        let verified = self
            .repo
            .list_verified_methods(tenant_id, identity_id)
            .await?;
        if verified.is_empty() {
            return Err(ServiceError::MfaNotEnrolled);
        }

        let codes = generate_backup_codes();
        let hashes: Vec<String> = codes.iter().map(|c| hash_backup_code(c)).collect();
        self.repo
            .replace_backup_codes(tenant_id, identity_id, &hashes)
            .await?;

        Ok(codes)
    }

    async fn verify_totp(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code: &str,
    ) -> Result<(), ServiceError> {
        let method = self
            .repo
            .get_method_by_kind(tenant_id, identity_id, MfaMethodKind::Totp)
            .await?
            .filter(|m| m.verified_at.is_some())
            .ok_or(ServiceError::MfaNotEnrolled)?;

        self.check_totp_code(&method, code).await
    }

    /// Decrypts the stored secret, matches the code within the drift window,
    /// and atomically claims the matched step so a code can never be
    /// accepted twice.
    async fn check_totp_code(&self, method: &MfaMethod, code: &str) -> Result<(), ServiceError> {
        let secret_enc = method
            .secret_enc
            .as_deref()
            .ok_or_else(|| ServiceError::Internal("TOTP enrollment missing secret".into()))?;

        let secret_b32 = self
            .kep
            .decrypt(
                secret_enc,
                Some(&encryption_context(method.tenant_id, method.identity_id)),
            )
            .await
            .map_err(|e| ServiceError::Internal(format!("Secret decryption failed: {}", e)))?;

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let matched_step =
            totp_matched_step(&secret_b32, code, now)?.ok_or(ServiceError::InvalidMfaCode)?;

        let claimed = self
            .repo
            .claim_totp_step(method.tenant_id, method.id, matched_step)
            .await?;
        if !claimed {
            warn!(
                "TOTP replay or stale step rejected for method {}",
                method.id
            );
            return Err(ServiceError::InvalidMfaCode);
        }

        Ok(())
    }

    async fn verify_backup_code(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        code: &str,
    ) -> Result<(), ServiceError> {
        let hash = hash_backup_code(code);
        let consumed = self
            .repo
            .consume_backup_code(tenant_id, identity_id, &hash)
            .await?;
        if !consumed {
            return Err(ServiceError::InvalidMfaCode);
        }
        Ok(())
    }
}

fn encryption_context(tenant_id: Uuid, identity_id: Uuid) -> Vec<u8> {
    format!("mfa:{}:{}", tenant_id, identity_id).into_bytes()
}

/// Returns the time-step whose expected code matches, checking
/// ±`TOTP_SKEW_STEPS` around `at_unix`. Pure so tests can pin the clock.
pub fn totp_matched_step(
    secret_b32: &str,
    code: &str,
    at_unix: i64,
) -> Result<Option<i64>, ServiceError> {
    let secret_bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| ServiceError::Internal(format!("Corrupt TOTP secret: {:?}", e)))?;

    // Skew 0: drift is handled explicitly below so we know WHICH step
    // matched and can claim exactly that one.
    let totp = TOTP::new_unchecked(
        Algorithm::SHA1,
        TOTP_DIGITS,
        0,
        TOTP_STEP_SECONDS,
        secret_bytes,
        None,
        String::new(),
    );

    for offset in -TOTP_SKEW_STEPS..=TOTP_SKEW_STEPS {
        let t = at_unix + offset * TOTP_STEP_SECONDS as i64;
        if t < 0 {
            continue;
        }
        let expected = totp.generate(t as u64);
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            return Ok(Some(t / TOTP_STEP_SECONDS as i64));
        }
    }

    Ok(None)
}

fn generate_backup_codes() -> Vec<String> {
    let mut rng = rand::rng();
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            (0..BACKUP_CODE_LENGTH)
                .map(|_| {
                    let idx = rng.random_range(0..BACKUP_CODE_CHARSET.len());
                    BACKUP_CODE_CHARSET[idx] as char
                })
                .collect()
        })
        .collect()
}

/// Codes are high-entropy random strings, so SHA-256 suffices (same
/// rationale as refresh token hashing). Input is normalized so users can
/// type codes with dashes or in lowercase.
fn hash_backup_code(code: &str) -> String {
    let normalized = code.trim().replace('-', "").to_uppercase();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}
