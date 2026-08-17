use crate::key::KeyService;
use base64::Engine as _;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use knox_common::{
    client::Client,
    error::ServiceError,
    key::{KeyEncryptionProvider, KeyRepository, KeyState},
    pool::PoolKind,
    token::{AuthCodeContext, RefreshToken, TokenRepository},
};
use rand::{RngExt, distr::Alphanumeric};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tracing::{debug, instrument, warn};
use uuid::Uuid;

/// `typ` header for access tokens, per RFC 9068 §2.1.
///
/// The point is to stop a token being accepted as a kind it is not: a resource
/// server that requires `at+jwt` cannot be handed an ID token, an SSO token or
/// an MFA challenge token in place of an access token. So it belongs on access
/// tokens *only* — the transient tokens minted through `mint_jwt_custom` keep
/// the generic `JWT`.
pub const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// Authentication method references, from the RFC 8176 registry.
///
/// Registry values only: an unregistered string means nothing to a relying
/// party. `AMR_OTP` covers backup codes as well as authenticator apps — a
/// backup code is a pre-issued one-time password, and the registry has no
/// finer value. The audit log records which of the two was actually used.
pub const AMR_PASSWORD: &str = "pwd";
pub const AMR_OTP: &str = "otp";
pub const AMR_SMS: &str = "sms";
pub const AMR_SOFTWARE_KEY: &str = "swk";
/// Multiple factors were used. Present alongside the individual methods so a
/// resource server can test for it without knowing every method Knox supports.
pub const AMR_MULTI_FACTOR: &str = "mfa";

/// Authentication context class references.
///
/// OIDC Core §2 leaves these to the deployment, so they are namespaced to Knox
/// rather than borrowed from a framework whose assurance definitions we do not
/// actually implement.
pub const ACR_PASSWORD: &str = "urn:knox:loa:pwd";
pub const ACR_MULTI_FACTOR: &str = "urn:knox:loa:mfa";

/// How the human authenticated, for access tokens minted from an interactive
/// login.
///
/// Absent for `client_credentials`: there is no user, so `amr`/`acr`/`auth_time`
/// would be describing nobody. Carried through the authorization code and then
/// the refresh token so it survives rotation — an `amr` that silently vanished
/// an hour after login would be worse than no `amr` at all, because a resource
/// server could not tell a refreshed session from an unauthenticated one.
#[derive(Clone, Debug)]
pub struct AuthenticationContext {
    pub amr: Vec<String>,
    /// When the credentials were actually presented, not when this token was
    /// minted — the two diverge on refresh, which is the whole point.
    pub auth_time: OffsetDateTime,
}

impl AuthenticationContext {
    pub fn new(amr: Vec<String>, auth_time: OffsetDateTime) -> Self {
        Self { amr, auth_time }
    }

    /// Derived rather than stored, so it cannot contradict `amr`.
    pub fn acr(&self) -> &'static str {
        if self.amr.iter().any(|m| m == AMR_MULTI_FACTOR) {
            ACR_MULTI_FACTOR
        } else {
            ACR_PASSWORD
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    /// The OAuth client the token was issued to (RFC 9068 §2.2).
    ///
    /// Required there, and load-bearing here for a second reason: `sub` holds an
    /// identity UUID for user tokens and the client identifier for
    /// `client_credentials`, so without this a resource server reading `sub`
    /// alone cannot tell which kind of principal it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Methods used at the authentication this token descends from (RFC 8176).
    /// Empty for `client_credentials`, and omitted from the JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Seconds since the epoch at which the user authenticated. Survives
    /// refresh, so it ages while `iat` resets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    pub tenant_id: Uuid,
    /// The identity pool the subject belongs to.
    ///
    /// `RequireAuth` asserts this equals the pool of the client named by `aud`,
    /// which is what lets the management API refuse a token minted by an
    /// end-user-facing client of the same tenant. Without it, `aud` alone is no
    /// help: it doubles as the client-id lookup key, so validating the audience
    /// only ever compares it against itself.
    pub pool_id: Uuid,
    /// Whether `pool_id` names a staff pool. Derived from the pool at mint time
    /// and safe to trust because `pool_id` is cross-checked against the client.
    pub pool_kind: PoolKind,
    pub scopes: Vec<String>,
    /// Token version from the client at the time of issuance.
    /// Tokens with a version lower than the client's current version are invalid.
    #[serde(default)]
    pub token_version: i32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtCustomClaims {
    pub sub: String,
    pub aud: String,
    pub tenant_id: Uuid,
    pub pool_id: Uuid,
    pub scopes: Vec<String>,
}

/// The identity attributes an ID token may carry, plus the context needed to
/// bind it to a login. The caller populates only the profile fields the granted
/// scopes permit (`email`/`email_verified` for the `email` scope,
/// `preferred_username`/`name` for `profile`), so this type holds no scope logic
/// of its own — `mint_id_token` serialises whatever it is given.
#[derive(Clone, Debug, Default)]
pub struct IdTokenInput {
    pub subject: String,
    /// The identifier the Relying Party knows itself by (the client name), which
    /// OIDC requires as the ID token's audience and authorized party.
    pub audience: String,
    pub auth: Option<AuthenticationContext>,
    pub nonce: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

/// OIDC ID Token claims (OIDC Core §2). Distinct from `JwtClaims`: an ID token
/// describes *who authenticated* to a relying party, so it carries no scopes,
/// pool, or token-version — those belong to the access token that authorises API
/// calls, not to the identity assertion the client consumes.
#[derive(Clone, Debug, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    amr: Vec<String>,
    /// Authorized party — the client the ID token was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    azp: Option<String>,
    /// Binds the ID token to the access token issued alongside it (OIDC Core
    /// §3.1.3.6): base64url of the left-most half of SHA-256(access_token).
    #[serde(skip_serializing_if = "Option::is_none")]
    at_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Clone)]
pub struct TokenService<R: TokenRepository, KR: KeyRepository, KP: KeyEncryptionProvider> {
    repo: R,
    key_service: KeyService<KR, KP>,
    //jwt_encoding_key: EncodingKey,
    //jwt_decoding_key: DecodingKey,
}

pub enum TransientKind {
    SsoToken,
    AuthCode,
    PasswordReset,
    MagicLink,
    /// Single-use marker for consumed MFA tokens (keyed by jti).
    MfaUsed,
    /// Verification attempt counter per MFA token (keyed by jti).
    MfaAttempts,
    /// Monotonic per-identity session epoch (keyed by `{tenant_id}:{identity_id}`).
    /// Stamped into every SSO session at mint and compared at redemption;
    /// bumping it invalidates every session for that identity at once. This is
    /// what lets a password change revoke live SSO cookies the process never saw.
    SsoEpoch,
    /// Rate-limit counter for self-service reset requests, keyed by
    /// `{pool_id}:{username}`. Caps how often a link can be requested for one
    /// handle, so the endpoint cannot be used to enumerate or spam accounts.
    PasswordResetThrottle,
    /// Failed password attempts for one tenant+pool+handle.
    LoginAccountAttempts,
    /// Failed password attempts across one tenant.
    LoginTenantAttempts,
    /// Failed password attempts from one source IP within a tenant.
    LoginIpAttempts,
}

impl TransientKind {
    fn prefix(&self) -> &'static str {
        match self {
            Self::SsoToken => "sso",
            TransientKind::AuthCode => "auth_code",
            TransientKind::PasswordReset => "pwd_reset",
            TransientKind::MagicLink => "magic_link",
            TransientKind::MfaUsed => "mfa_used",
            TransientKind::MfaAttempts => "mfa_att",
            TransientKind::SsoEpoch => "sso_epoch",
            TransientKind::PasswordResetThrottle => "pwd_reset_throttle",
            TransientKind::LoginAccountAttempts => "login_att_acct",
            TransientKind::LoginTenantAttempts => "login_att_tenant",
            TransientKind::LoginIpAttempts => "login_att_ip",
        }
    }
}

impl<R: TokenRepository, KR: KeyRepository, KP: KeyEncryptionProvider> TokenService<R, KR, KP> {
    pub fn new(repo: R, key_service: KeyService<KR, KP>) -> Self {
        Self { repo, key_service }
    }

    #[instrument(skip(self, kind, key, token))]
    pub async fn store_transient_token<T>(
        &self,
        kind: TransientKind,
        key: &str,
        token: &T,
        ttl: Duration,
    ) -> Result<(), ServiceError>
    where
        T: Serialize,
    {
        let full_key = format!("{}:{}", kind.prefix(), key);
        let json_value = serde_json::to_string(&token)
            .map_err(|e| ServiceError::Internal(format!("Failed to serialize token: {}", e)))?;
        let ttl_seconds = ttl.whole_seconds() as u64;

        self.repo
            .store_transient_string(&full_key, &json_value, ttl_seconds)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self, kind, key))]
    pub async fn retrieve_transient_token<T>(
        &self,
        kind: TransientKind,
        key: &str,
    ) -> Result<Option<T>, ServiceError>
    where
        T: DeserializeOwned,
    {
        let full_key = format!("{}:{}", kind.prefix(), key);
        let value = self
            .repo
            .read_transient_string(&full_key)
            .await
            .map_err(ServiceError::Repository)?;
        if let Some(json_value) = value {
            let token = serde_json::from_str(&json_value).map_err(|e| {
                ServiceError::Internal(format!("Failed to deserialize token: {}", e))
            })?;
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    /// Atomic counter with the TTL set on first increment. Returns the
    /// post-increment value.
    #[instrument(skip(self, kind, key))]
    pub async fn increment_transient_counter(
        &self,
        kind: TransientKind,
        key: &str,
        ttl: Duration,
    ) -> Result<u64, ServiceError> {
        let full_key = format!("{}:{}", kind.prefix(), key);
        self.repo
            .increment_transient_counter(&full_key, ttl.whole_seconds() as u64)
            .await
            .map_err(ServiceError::Repository)
    }

    /// Reads and deletes a transient token in one step — single-use redemption.
    /// Used by the password-reset flow, where presenting the token must consume
    /// it whether or not a second factor still stands between it and the reset.
    #[instrument(skip(self, kind, key))]
    pub async fn take_transient_token<T>(
        &self,
        kind: TransientKind,
        key: &str,
    ) -> Result<Option<T>, ServiceError>
    where
        T: DeserializeOwned,
    {
        let full_key = format!("{}:{}", kind.prefix(), key);
        let value = self
            .repo
            .get_and_delete_transient_string(&full_key)
            .await
            .map_err(ServiceError::Repository)?;
        match value {
            Some(json_value) => {
                let token = serde_json::from_str(&json_value).map_err(|e| {
                    ServiceError::Internal(format!("Failed to deserialize token: {}", e))
                })?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    /// Refreshes the TTL on an existing transient key. A no-op if absent.
    #[instrument(skip(self, kind, key))]
    pub async fn touch_transient(
        &self,
        kind: TransientKind,
        key: &str,
        ttl: Duration,
    ) -> Result<(), ServiceError> {
        let full_key = format!("{}:{}", kind.prefix(), key);
        self.repo
            .touch_transient(&full_key, ttl.whole_seconds() as u64)
            .await
            .map_err(ServiceError::Repository)
    }

    // ── Session epoch ────────────────────────────────────────────────────────
    //
    // A per-identity counter stamped into every SSO session and compared at
    // redemption. Bumping it is O(1) session revocation with no per-token index:
    // every session carrying a lower epoch stops validating at once. See
    // `TransientKind::SsoEpoch`.

    fn sso_epoch_key(tenant_id: Uuid, identity_id: Uuid) -> String {
        format!("{}:{}", tenant_id, identity_id)
    }

    /// The identity's current session epoch. Absent (never revoked) reads as 0,
    /// which is exactly the value carried by sessions minted before any bump —
    /// so a never-revoked identity's sessions always match.
    #[instrument(skip(self))]
    pub async fn current_sso_epoch(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<u64, ServiceError> {
        let key = Self::sso_epoch_key(tenant_id, identity_id);
        let epoch: Option<u64> = self
            .retrieve_transient_token(TransientKind::SsoEpoch, &key)
            .await?;
        Ok(epoch.unwrap_or(0))
    }

    /// Invalidates every existing session for the identity by advancing the
    /// epoch. `ttl` must exceed the lifetime of the longest-lived session the
    /// old epoch stamped, or an expired counter would read back as 0 and revive
    /// those sessions; the counter is refreshed on the bump for that reason.
    #[instrument(skip(self))]
    pub async fn bump_sso_epoch(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        ttl: Duration,
    ) -> Result<u64, ServiceError> {
        let key = Self::sso_epoch_key(tenant_id, identity_id);
        let next = self
            .increment_transient_counter(TransientKind::SsoEpoch, &key, ttl)
            .await?;
        // INCR sets the TTL only on creation, so refresh it explicitly: the
        // epoch must outlive the sessions still holding the pre-bump value.
        self.touch_transient(TransientKind::SsoEpoch, &key, ttl)
            .await?;
        Ok(next)
    }

    /// Keeps the epoch counter alive while sessions are being minted against it,
    /// so it never lapses back to an implicit 0 under a live session.
    #[instrument(skip(self))]
    pub async fn touch_sso_epoch(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        ttl: Duration,
    ) -> Result<(), ServiceError> {
        let key = Self::sso_epoch_key(tenant_id, identity_id);
        self.touch_transient(TransientKind::SsoEpoch, &key, ttl)
            .await
    }

    #[instrument(skip(self))]
    pub async fn exchange_auth_code(
        &self,
        hashed_code: &str,
    ) -> Result<Option<AuthCodeContext>, ServiceError> {
        self.repo
            .exchange_auth_code(hashed_code)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self, length))]
    pub fn generate_opaque_token(&self, length: usize) -> String {
        let rng = rand::rng();
        rng.sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    #[instrument(skip(token))]
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    #[instrument(skip(self, client, auth))]
    pub async fn mint_access_token(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        subject: String,
        scopes: Vec<String>,
        client: Client,
        pool_kind: PoolKind,
        auth: Option<AuthenticationContext>,
    ) -> Result<String, ServiceError> {
        let (key_meta, decrypted_private_pem) = self.key_service.get_signing_key(tenant_id).await?;

        let encoding_key = EncodingKey::from_rsa_pem(decrypted_private_pem.as_bytes())
            .map_err(|e| ServiceError::Internal(format!("Invalid RSA PEM: {}", e)))?;
        debug!("Using signing key with kid: {}", key_meta.kid);

        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(client.access_token_ttl as i64);

        let claims = JwtClaims {
            iss: issuer.to_string(),
            sub: subject,
            aud: client.id.to_string(),
            exp: exp.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: Uuid::new_v4().to_string(),
            // The identifier the client authenticates with at the token
            // endpoint, which is the name — not the row id in `aud`.
            client_id: Some(client.name.clone()),
            acr: auth.as_ref().map(|a| a.acr().to_string()),
            auth_time: auth.as_ref().map(|a| a.auth_time.unix_timestamp()),
            amr: auth.map(|a| a.amr).unwrap_or_default(),
            tenant_id,
            pool_id: client.pool_id,
            pool_kind,
            scopes,
            token_version: client.token_version,
        };

        self.mint_jwt_internal(
            key_meta.kid.to_string(),
            encoding_key,
            claims,
            ACCESS_TOKEN_TYP,
        )
    }

    /// Mints an OIDC ID token, signed with the tenant's RSA key like the access
    /// token but carrying identity claims rather than authorization scopes and
    /// marked `typ: JWT` so it can never be presented as an access token. The
    /// `access_token` it is issued alongside is hashed into `at_hash`, binding
    /// the two halves of the response together.
    #[instrument(skip(self, input, access_token))]
    pub async fn mint_id_token(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        ttl: Duration,
        input: IdTokenInput,
        access_token: &str,
    ) -> Result<String, ServiceError> {
        let (key_meta, decrypted_private_pem) = self.key_service.get_signing_key(tenant_id).await?;
        let encoding_key = EncodingKey::from_rsa_pem(decrypted_private_pem.as_bytes())
            .map_err(|e| ServiceError::Internal(format!("Invalid RSA PEM: {}", e)))?;

        let now = OffsetDateTime::now_utc();
        let exp = now + ttl;

        // at_hash: left-most 128 bits of SHA-256(access_token), base64url, no pad.
        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        let digest = hasher.finalize();
        let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16]);

        // `email_verified` is only meaningful — and only released — when an email
        // claim is actually present.
        let email_verified = input.email.as_ref().map(|_| input.email_verified);

        let claims = IdTokenClaims {
            iss: issuer.to_string(),
            sub: input.subject,
            aud: input.audience.clone(),
            exp: exp.unix_timestamp(),
            iat: now.unix_timestamp(),
            auth_time: input.auth.as_ref().map(|a| a.auth_time.unix_timestamp()),
            nonce: input.nonce,
            acr: input.auth.as_ref().map(|a| a.acr().to_string()),
            amr: input.auth.map(|a| a.amr).unwrap_or_default(),
            azp: Some(input.audience),
            at_hash: Some(at_hash),
            email: input.email,
            email_verified,
            preferred_username: input.preferred_username,
            name: input.name,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_meta.kid.to_string());
        header.typ = Some("JWT".to_string());
        encode(&header, &claims, &encoding_key)
            .map_err(|e| ServiceError::Internal(format!("ID token minting failed: {}", e)))
    }

    #[instrument(skip(self))]
    fn mint_jwt_internal(
        &self,
        kid: String,
        key: EncodingKey,
        claims: JwtClaims,
        typ: &str,
    ) -> Result<String, ServiceError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid);
        header.typ = Some(typ.to_string());
        encode(&header, &claims, &key)
            .map_err(|e| ServiceError::Internal(format!("JWT minting failed: {}", e)))
    }
    #[instrument(skip(self))]
    pub async fn mint_jwt(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        claims: JwtClaims,
    ) -> Result<String, ServiceError> {
        let (key_meta, decrypted_private_pem) = self.key_service.get_signing_key(tenant_id).await?;
        let mut claims = claims;
        claims.iss = issuer.to_string();
        let encoding_key = EncodingKey::from_rsa_pem(decrypted_private_pem.as_bytes())
            .map_err(|e| ServiceError::Internal(format!("Invalid RSA PEM: {}", e)))?;
        self.mint_jwt_internal(key_meta.kid.to_string(), encoding_key, claims, "JWT")
    }
    #[instrument(skip(self))]
    pub async fn mint_jwt_custom(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        expiry: Duration,
        claims: JwtCustomClaims,
    ) -> Result<String, ServiceError> {
        let (key_meta, decrypted_private_pem) = self.key_service.get_signing_key(tenant_id).await?;
        let encoding_key = EncodingKey::from_rsa_pem(decrypted_private_pem.as_bytes())
            .map_err(|e| ServiceError::Internal(format!("Invalid RSA PEM: {}", e)))?;

        let now = OffsetDateTime::now_utc();
        let exp = now + expiry;
        let claims = JwtClaims {
            iss: issuer.to_string(),
            sub: claims.sub,
            aud: claims.aud,
            exp: exp.unix_timestamp(),
            iat: now.unix_timestamp(),
            jti: Uuid::new_v4().to_string(),
            // Not an access token: no client, and no authentication to describe
            // — the MFA token is minted *before* authentication completes.
            client_id: None,
            amr: Vec::new(),
            acr: None,
            auth_time: None,
            tenant_id,
            pool_id: claims.pool_id,
            // The MFA token is an intermediate credential, not a session: it
            // grants only the right to attempt verification. Its pool is
            // re-checked against the client at the verification step.
            pool_kind: PoolKind::Customer,
            scopes: claims.scopes,
            token_version: 1, // Custom claims (SSO, etc.) don't have client versioning
        };
        // header kid must be the key's public kid (what verify_jwt and JWKS
        // look up), not the row id. `typ` stays generic: this is not an access
        // token, and marking it `at+jwt` would let it be presented as one.
        self.mint_jwt_internal(key_meta.kid.to_string(), encoding_key, claims, "JWT")
    }

    #[instrument(skip(self, token))]
    pub async fn verify_jwt(
        &self,
        tenant_id: Uuid,
        expected_issuer: &str,
        token: &str,
        expected_audience: Option<&str>,
    ) -> Result<JwtClaims, ServiceError> {
        let header = decode_header(token)
            .map_err(|_| ServiceError::Validation("Malformed JWT header".into()))?;

        if header.alg != Algorithm::RS256 {
            return Err(ServiceError::Validation(
                "Unsupported token algorithm".into(),
            ));
        }

        let kid = header
            .kid
            .ok_or_else(|| ServiceError::Validation("Token header is missing 'kid'".into()))?;
        debug!("Verifying JWT with kid: {}", kid);
        let tenant_key = self
            .key_service
            .get_key_by_kid(tenant_id, &kid)
            .await?
            .ok_or_else(|| ServiceError::Validation("Signing key not found".into()))?;

        if tenant_key.state == KeyState::Revoked {
            warn!("Attempted to verify token with a revoked key: {}", kid);
            return Err(ServiceError::Forbidden);
        }

        let decoding_key = DecodingKey::from_rsa_pem(tenant_key.public_key_pem.as_bytes())
            .map_err(|e| ServiceError::Internal(format!("Invalid public key PEM: {}", e)))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[expected_issuer]);
        validation.validate_exp = true;
        if let Some(aud) = expected_audience {
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }

        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
            debug!("JWT verification failed: {}", e);
            ServiceError::InvalidCredentials
        })?;

        // 7. Ultimate safety check: Ensure the verified tenant_id inside the payload matches the context
        if token_data.claims.tenant_id != tenant_id {
            tracing::warn!("Tenant ID mismatch during token verification");
            return Err(ServiceError::InvalidCredentials);
        }

        Ok(token_data.claims)
    }

    /// Validates that the token's version matches the client's current version.
    /// This must be called separately after verify_jwt when the client_id is known.
    /// Returns an error if the token version is outdated (client has rotated).
    #[instrument(skip(self))]
    pub fn validate_token_version(
        &self,
        claims: &JwtClaims,
        client: &Client,
    ) -> Result<(), ServiceError> {
        if claims.token_version < client.token_version {
            warn!(
                "Token version mismatch: token has version {}, client {} requires {}",
                claims.token_version, client.id, client.token_version
            );
            return Err(ServiceError::InvalidCredentials);
        }
        Ok(())
    }

    #[instrument(skip(self, token))]
    pub async fn save_refresh_token(
        &self,
        token: &RefreshToken,
    ) -> Result<RefreshToken, ServiceError> {
        self.repo
            .save_refresh_token(token)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn get_refresh_token(
        &self,
        tenant_id: Uuid,
        hashed_token: &str,
    ) -> Result<Option<RefreshToken>, ServiceError> {
        self.repo
            .get_refresh_token(tenant_id, hashed_token)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn revoke_refresh_token(&self, id: Uuid) -> Result<(), ServiceError> {
        self.repo
            .revoke_refresh_token(id)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn revoke_token_family(&self, family_id: Uuid) -> Result<(), ServiceError> {
        self.repo
            .revoke_token_family(family_id)
            .await
            .map_err(ServiceError::Repository)
    }

    #[instrument(skip(self))]
    pub async fn revoke_all_for_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<(), ServiceError> {
        self.repo
            .revoke_all_for_identity(tenant_id, identity_id)
            .await
            .map_err(ServiceError::Repository)
    }
}
