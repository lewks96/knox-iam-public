use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, rand_core::RngCore},
};
use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use knox_common::error::ServiceError;
use knox_common::key::{
    CreateKeyParams, GeneratedKeyPair, Jwks, JwksKey, KeyAlgorithm, KeyEncryptionError,
    KeyEncryptionProvider, KeyRepository, KeyState, KeyUse, TenantKey,
};
use rand_core::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    traits::PublicKeyParts,
};
use serde::Deserialize;
use spki::DecodePublicKey;
use time::{Duration, OffsetDateTime};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;
use validator::Validate;

const DEFAULT_KEY_VALIDITY_DAYS: i64 = 365;

const RSA_KEY_SIZE: usize = 2048;

#[derive(Debug, Validate, Deserialize)]
pub struct CreateKeyRequest {
    #[validate(length(min = 1, max = 64, message = "Custom kid must be 1-64 characters"))]
    pub kid: Option<String>,
    pub algorithm: Option<KeyAlgorithm>,
    pub validity_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RotateKeysRequest {
    pub algorithm: Option<KeyAlgorithm>,
    pub validity_days: Option<i64>,
    pub revoke_existing: bool,
}

const NONCE_SIZE: usize = 12;
const BLOB_VERSION: u8 = 0x01;

#[derive(Clone)]
pub struct LocalKeyEncryptionProvider {
    cipher: Aes256Gcm,
}

impl LocalKeyEncryptionProvider {
    pub fn new(master_key: &[u8]) -> Self {
        assert_eq!(master_key.len(), 32, "Master key must be exactly 32 bytes");
        let cipher =
            Aes256Gcm::new_from_slice(master_key).expect("Invalid key length for AES-256-GCM");
        Self { cipher }
    }
    pub fn from_base64(master_key_b64: &str) -> Result<Self, KeyEncryptionError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let key_bytes = STANDARD
            .decode(master_key_b64)
            .map_err(|e| KeyEncryptionError(format!("Invalid base64 master key: {}", e)))?;
        if key_bytes.len() != 32 {
            return Err(KeyEncryptionError(format!(
                "Master key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }
        Ok(Self::new(&key_bytes))
    }
    pub fn generate_master_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }
}

#[async_trait]
impl KeyEncryptionProvider for LocalKeyEncryptionProvider {
    async fn encrypt(
        &self,
        plaintext_key_pem: &str,
        context: Option<&[u8]>,
    ) -> Result<Vec<u8>, KeyEncryptionError> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = plaintext_key_pem.as_bytes();

        let ciphertext = if let Some(aad) = context {
            self.cipher
                .encrypt(
                    nonce,
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| KeyEncryptionError(format!("Encryption failed: {}", e)))?
        } else {
            self.cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| KeyEncryptionError(format!("Encryption failed: {}", e)))?
        };

        let mut blob = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
        blob.push(BLOB_VERSION);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        Ok(blob)
    }

    async fn decrypt(
        &self,
        encrypted_blob: &[u8],
        context: Option<&[u8]>,
    ) -> Result<String, KeyEncryptionError> {
        let min_size = 1 + NONCE_SIZE + 16; // version + nonce + min tag
        if encrypted_blob.len() < min_size {
            return Err(KeyEncryptionError("Encrypted blob too short".into()));
        }

        let version = encrypted_blob[0];
        if version != BLOB_VERSION {
            return Err(KeyEncryptionError(format!(
                "Unsupported blob version: {}",
                version
            )));
        }

        let nonce_bytes = &encrypted_blob[1..1 + NONCE_SIZE];
        let ciphertext = &encrypted_blob[1 + NONCE_SIZE..];
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext_bytes = if let Some(aad) = context {
            self.cipher
                .decrypt(
                    nonce,
                    aes_gcm::aead::Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| {
                    KeyEncryptionError("Decryption failed (bad key or tampered data)".into())
                })?
        } else {
            self.cipher.decrypt(nonce, ciphertext).map_err(|_| {
                KeyEncryptionError("Decryption failed (bad key or tampered data)".into())
            })?
        };

        String::from_utf8(plaintext_bytes)
            .map_err(|e| KeyEncryptionError(format!("Decrypted key is not valid UTF-8: {}", e)))
    }

    fn provider_id(&self) -> &str {
        "local-aes-256-gcm"
    }
}

#[derive(Clone)]
pub struct KeyService<R: KeyRepository, K: KeyEncryptionProvider> {
    repo: R,
    kep: K,
}

impl<R: KeyRepository, K: KeyEncryptionProvider> KeyService<R, K> {
    pub fn new(repo: R, kep: K) -> Self {
        Self { repo, kep }
    }
    #[instrument(skip(self))]
    pub async fn create_key(
        &self,
        tenant_id: Uuid,
        req: CreateKeyRequest,
    ) -> Result<TenantKey, ServiceError> {
        if let Some(kid) = &req.kid
            && kid.len() > 64
        {
            return Err(ServiceError::Validation("Kid too long".into()));
        }

        let algorithm = req.algorithm.unwrap_or_default();
        let validity_days = req.validity_days.unwrap_or(DEFAULT_KEY_VALIDITY_DAYS);
        let kid = req.kid.unwrap_or_else(|| Self::generate_kid());

        info!(
            tenant_id = %tenant_id,
            algorithm = %algorithm,
            kid = %kid,
            "Creating new signing key"
        );

        let key_pair = self.generate_key_pair(algorithm)?;

        let context = tenant_id.as_bytes().to_vec();

        let encrypted_private_key = self
            .kep
            .encrypt(&key_pair.private_key_pem, Some(&context))
            .await
            .map_err(|e| ServiceError::Internal(format!("Key encryption failed: {}", e)))?;

        let expires_at = OffsetDateTime::now_utc() + Duration::days(validity_days);

        let params = CreateKeyParams {
            tenant_id,
            kid,
            use_type: KeyUse::Signature.as_str().to_string(),
            kty: algorithm.key_type().to_string(),
            alg: algorithm.as_str().to_string(),
            public_key_pem: key_pair.public_key_pem,
            x509_cert_pem: None, // X.509 cert generation can be added later for SAML
            encrypted_private_key,
            expires_at,
        };

        let key = self
            .repo
            .create(params)
            .await
            .map_err(ServiceError::Repository)?;

        info!(key_id = %key.id, "Signing key created successfully");
        Ok(key)
    }
    #[instrument(skip(self))]
    pub async fn rotate_keys(
        &self,
        tenant_id: Uuid,
        req: RotateKeysRequest,
    ) -> Result<TenantKey, ServiceError> {
        info!(tenant_id = %tenant_id, "Starting key rotation");

        let current_active = self.repo.get_active_for_tenant(tenant_id).await?;

        let new_key = self
            .create_key(
                tenant_id,
                CreateKeyRequest {
                    kid: None,
                    algorithm: req.algorithm,
                    validity_days: req.validity_days,
                },
            )
            .await?;

        if let Some(old_key) = current_active {
            if req.revoke_existing {
                warn!(
                    old_key_id = %old_key.id,
                    "Emergency rotation: revoking existing key"
                );
                self.repo
                    .update_state(old_key.id, KeyState::Revoked)
                    .await?;
            } else {
                debug!(
                    old_key_id = %old_key.id,
                    "Graceful rotation: expiring existing key"
                );
                self.repo
                    .update_state(old_key.id, KeyState::Expired)
                    .await?;
            }
        }

        info!(
            new_key_id = %new_key.id,
            "Key rotation completed"
        );
        Ok(new_key)
    }
    #[instrument(skip(self))]
    pub async fn get_active_key(&self, tenant_id: Uuid) -> Result<Option<TenantKey>, ServiceError> {
        self.repo
            .get_active_for_tenant(tenant_id)
            .await
            .map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn get_key(&self, id: Uuid) -> Result<Option<TenantKey>, ServiceError> {
        self.repo.get(id).await.map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    /// Looks up a signing key by `kid` within a tenant.
    ///
    /// The lookup stays tenant-scoped deliberately. `kid` is only unique per
    /// tenant (`UNIQUE (tenant_id, kid)`), so a global lookup could not
    /// identify a single row. Scoping also avoids confirming to a caller that
    /// a `kid` exists under some *other* tenant — callers get a uniform
    /// "not found" either way, and operators get the detail from the logs.
    pub async fn get_key_by_kid(
        &self,
        tenant_id: Uuid,
        kid: &str,
    ) -> Result<Option<TenantKey>, ServiceError> {
        let key = self
            .repo
            .get_by_kid(tenant_id, kid)
            .await
            .map_err(ServiceError::Repository)?;

        if key.is_none() {
            debug!(%tenant_id, kid, "No signing key for kid under this tenant");
        }

        Ok(key)
    }
    #[instrument(skip(self))]
    pub async fn list_keys(
        &self,
        tenant_id: Uuid,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<TenantKey>, u64), ServiceError> {
        self.repo
            .list(tenant_id, page, page_size)
            .await
            .map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn expire_key(&self, id: Uuid) -> Result<TenantKey, ServiceError> {
        info!(key_id = %id, "Expiring key");
        self.repo
            .update_state(id, KeyState::Expired)
            .await
            .map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn revoke_key(&self, id: Uuid) -> Result<TenantKey, ServiceError> {
        warn!(key_id = %id, "Revoking key");
        self.repo
            .update_state(id, KeyState::Revoked)
            .await
            .map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn revoke_all_keys(&self, tenant_id: Uuid) -> Result<(), ServiceError> {
        warn!(tenant_id = %tenant_id, "Revoking ALL keys for tenant");
        self.repo
            .revoke_all_for_tenant(tenant_id)
            .await
            .map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn delete_key(&self, id: Uuid) -> Result<(), ServiceError> {
        warn!(key_id = %id, "Permanently deleting key");
        self.repo.delete(id).await.map_err(ServiceError::Repository)
    }
    #[instrument(skip(self))]
    pub async fn get_jwks(&self, tenant_id: Uuid) -> Result<Jwks, ServiceError> {
        let keys = self
            .repo
            .list_for_jwks(tenant_id)
            .await
            .map_err(ServiceError::Repository)?;

        let jwks_keys: Vec<JwksKey> = keys
            .into_iter()
            .filter_map(|k| self.tenant_key_to_jwks(&k).ok())
            .collect();

        Ok(Jwks { keys: jwks_keys })
    }
    fn tenant_key_to_jwks(&self, key: &TenantKey) -> Result<JwksKey, ServiceError> {
        match key.kty.as_str() {
            "RSA" => self.rsa_key_to_jwks(key),
            "EC" => self.ec_key_to_jwks(key),
            _ => Err(ServiceError::Internal(format!(
                "Unsupported key type: {}",
                key.kty
            ))),
        }
    }

    fn rsa_key_to_jwks(&self, key: &TenantKey) -> Result<JwksKey, ServiceError> {
        let public_key = RsaPublicKey::from_public_key_pem(&key.public_key_pem).map_err(|e| {
            ServiceError::Internal(format!("Failed to parse RSA public key: {}", e))
        })?;

        let n = Base64UrlUnpadded::encode_string(&public_key.n().to_bytes_be());
        let e = Base64UrlUnpadded::encode_string(&public_key.e().to_bytes_be());

        Ok(JwksKey {
            kid: key.kid.clone(),
            kty: key.kty.clone(),
            alg: key.alg.clone(),
            use_type: key.use_type.clone(),
            n: Some(n),
            e: Some(e),
            crv: None,
            x: None,
            y: None,
            x5c: key.x509_cert_pem.as_ref().map(|cert| vec![cert.clone()]),
        })
    }

    fn ec_key_to_jwks(&self, _key: &TenantKey) -> Result<JwksKey, ServiceError> {
        // EC key JWKS conversion would go here
        // For now, return an error as EC is not fully implemented
        Err(ServiceError::Internal(
            "EC key JWKS conversion not yet implemented".into(),
        ))
    }

    // TODO: rethink this function maybe, should we just return plaintext keys?
    #[instrument(skip(self))]
    pub async fn decrypt_private_key(&self, key: &TenantKey) -> Result<String, ServiceError> {
        if key.state == KeyState::Revoked {
            return Err(ServiceError::Forbidden);
        }

        let context = key.tenant_id.as_bytes().to_vec();

        self.kep
            .decrypt(&key.encrypted_private_key, Some(&context))
            .await
            .map_err(|e| ServiceError::Internal(format!("Key decryption failed: {}", e)))
    }

    #[instrument(skip(self))]
    pub async fn get_signing_key(
        &self,
        tenant_id: Uuid,
    ) -> Result<(TenantKey, String), ServiceError> {
        let key = self.get_active_key(tenant_id).await?.ok_or_else(|| {
            ServiceError::Internal(format!("No active signing key for tenant {}", tenant_id))
        })?;

        let decrypted = self.decrypt_private_key(&key).await?;
        Ok((key, decrypted))
    }

    fn generate_key_pair(&self, algorithm: KeyAlgorithm) -> Result<GeneratedKeyPair, ServiceError> {
        match algorithm {
            KeyAlgorithm::RS256 | KeyAlgorithm::RS384 | KeyAlgorithm::RS512 => {
                self.generate_rsa_key_pair()
            }
            KeyAlgorithm::ES256 | KeyAlgorithm::ES384 => Err(ServiceError::Internal(
                "EC key generation not yet implemented".into(),
            )),
        }
    }

    fn generate_rsa_key_pair(&self) -> Result<GeneratedKeyPair, ServiceError> {
        let private_key = RsaPrivateKey::new(&mut OsRng, RSA_KEY_SIZE)
            .map_err(|e| ServiceError::Internal(format!("RSA key generation failed: {}", e)))?;

        let public_key = RsaPublicKey::from(&private_key);

        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| ServiceError::Internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        let public_key_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| ServiceError::Internal(format!("Failed to encode public key: {}", e)))?;

        Ok(GeneratedKeyPair {
            public_key_pem,
            private_key_pem,
            algorithm: KeyAlgorithm::RS256,
        })
    }
    fn generate_kid() -> String {
        // Use a timestamp prefix for sortability + random suffix for uniqueness
        let timestamp = OffsetDateTime::now_utc().unix_timestamp();
        let random: u32 = rand::random();
        format!("k{}-{:08x}", timestamp, random)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_encryption_roundtrip() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let master_key = LocalKeyEncryptionProvider::generate_master_key();
            let provider = LocalKeyEncryptionProvider::new(&master_key);

            let plaintext = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----";
            let context = b"tenant-123";

            let encrypted = provider.encrypt(plaintext, Some(context)).await.unwrap();
            let decrypted = provider.decrypt(&encrypted, Some(context)).await.unwrap();

            assert_eq!(decrypted, plaintext);
        });
    }

    #[test]
    fn test_local_encryption_wrong_context_fails() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let master_key = LocalKeyEncryptionProvider::generate_master_key();
            let provider = LocalKeyEncryptionProvider::new(&master_key);

            let plaintext = "secret key material";
            let encrypted = provider
                .encrypt(plaintext, Some(b"context1"))
                .await
                .unwrap();

            // Wrong context should fail
            let result = provider.decrypt(&encrypted, Some(b"context2")).await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_generate_kid_format() {
        let kid = KeyService::<DummyRepository, DummyKmsProvider>::generate_kid();
        assert!(kid.starts_with('k'));
        assert!(kid.contains('-'));
    }
}

// Local test types to satisfy orphan rules
#[cfg(test)]
struct DummyRepository;

#[cfg(test)]
struct DummyKmsProvider;

#[cfg(test)]
#[async_trait]
impl KeyRepository for DummyRepository {
    async fn create(
        &self,
        _params: CreateKeyParams,
    ) -> Result<TenantKey, knox_common::error::RepositoryError> {
        unimplemented!()
    }
    async fn get(
        &self,
        _id: Uuid,
    ) -> Result<Option<TenantKey>, knox_common::error::RepositoryError> {
        unimplemented!()
    }
    async fn get_by_kid(
        &self,
        _tenant_id: Uuid,
        _kid: &str,
    ) -> Result<Option<TenantKey>, knox_common::error::RepositoryError> {
        unimplemented!()
    }
    async fn get_active_for_tenant(
        &self,
        _tenant_id: Uuid,
    ) -> Result<Option<TenantKey>, knox_common::error::RepositoryError> {
        unimplemented!()
    }
    async fn list_for_jwks(
        &self,
        _tenant_id: Uuid,
    ) -> Result<Vec<TenantKey>, knox_common::error::RepositoryError> {
        unimplemented!()
    }
    async fn list(
        &self,
        _tenant_id: Uuid,
        _page: u32,
        _page_size: u32,
    ) -> Result<(Vec<TenantKey>, u64), knox_common::error::RepositoryError> {
        unimplemented!()
    }
    async fn update_state(
        &self,
        _id: Uuid,
        _new_state: KeyState,
    ) -> Result<TenantKey, knox_common::error::RepositoryError> {
        unimplemented!()
    }
    async fn delete(&self, _id: Uuid) -> Result<(), knox_common::error::RepositoryError> {
        unimplemented!()
    }
    async fn revoke_all_for_tenant(
        &self,
        _tenant_id: Uuid,
    ) -> Result<(), knox_common::error::RepositoryError> {
        unimplemented!()
    }
}

#[cfg(test)]
#[async_trait]
impl KeyEncryptionProvider for DummyKmsProvider {
    async fn encrypt(
        &self,
        _plaintext: &str,
        _context: Option<&[u8]>,
    ) -> Result<Vec<u8>, KeyEncryptionError> {
        unimplemented!()
    }
    async fn decrypt(
        &self,
        _encrypted: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<String, KeyEncryptionError> {
        unimplemented!()
    }
    fn provider_id(&self) -> &str {
        "test"
    }
}
