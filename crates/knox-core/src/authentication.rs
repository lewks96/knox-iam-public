use crate::audit::AuditService;
use crate::identity::IdentityService;
use crate::mfa::MfaService;
use crate::token::{
    AMR_MULTI_FACTOR, AMR_OTP, AMR_PASSWORD, AMR_SMS, AMR_SOFTWARE_KEY, JwtCustomClaims,
    TokenService, TransientKind,
};
use knox_common::audit::{AuditActor, AuditContext, AuditEvent, AuditEventType, AuditOutcome};
use knox_common::authorization::AuthorizationRepository;
use knox_common::error::ServiceError;
use knox_common::identity::{
    Identity, IdentityHandle, IdentityRepository, MfaOption, MfaOptions, MfaRequiredDetails, Status,
};
use knox_common::key::{KeyEncryptionProvider, KeyRepository};
use knox_common::mfa::MfaRepository;
use knox_common::tenant::TenantConfiguration;
use knox_common::token::TokenRepository;
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tracing::{error, instrument, warn};
use uuid::Uuid;

fn handle_display(handle: &IdentityHandle) -> String {
    match handle {
        IdentityHandle::Id(id) => id.to_string(),
        IdentityHandle::Email(e) => e.clone(),
        IdentityHandle::Username(u) => u.clone(),
    }
}

fn method_str(method: MfaOption) -> &'static str {
    match method {
        MfaOption::Totp => "totp",
        MfaOption::WebAuthn => "webauthn",
        MfaOption::Sms => "sms",
        MfaOption::BackupCode => "backup_code",
    }
}

/// Knox's MFA methods as RFC 8176 `amr` values.
///
/// Backup codes map to `otp` alongside authenticator codes: a backup code is a
/// pre-issued one-time password, and the registry offers nothing narrower. The
/// audit log distinguishes them (`method_str`) for anyone who needs to know
/// which was used.
fn amr_for_method(method: MfaOption) -> &'static str {
    match method {
        MfaOption::Totp | MfaOption::BackupCode => AMR_OTP,
        MfaOption::WebAuthn => AMR_SOFTWARE_KEY,
        MfaOption::Sms => AMR_SMS,
    }
}

/// Scope carried by the short-lived JWT issued after the password step of an
/// MFA login. Grants nothing except the right to attempt MFA verification.
pub const MFA_SCOPE: &str = "knox:mfa";

/// Scope for the MFA challenge issued mid password-reset. Distinct from
/// `MFA_SCOPE` on purpose: a challenge minted to complete a login must not be
/// redeemable to reset a password, nor the reverse. `consume_mfa_challenge`
/// rejects any token whose scope is not the one the caller expects — the same
/// guard that already refuses a token with no MFA scope at all.
pub const PWD_RESET_MFA_SCOPE: &str = "knox:pwd_reset_mfa";

/// How many self-service reset requests are allowed per handle within one token
/// lifetime before further requests are silently dropped. Small on purpose: a
/// legitimate user needs one link, so anything above a handful is abuse.
const MAX_RESET_REQUESTS_PER_WINDOW: u64 = 5;

#[derive(Clone)]
pub struct AuthenticationService<
    I: IdentityRepository,
    A: AuthorizationRepository,
    //C: ClientRepository,
    R: TokenRepository,
    KR: KeyRepository,
    KP: KeyEncryptionProvider,
    M: MfaRepository,
> {
    identity_service: IdentityService<I, A>,
    //client_service: ClientService<C>,
    token_service: TokenService<R, KR, KP>,
    mfa_service: MfaService<M, KP>,
    audit: AuditService,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SsoSessionContext {
    pub tenant_id: Uuid,
    /// The pool the credentials were checked against.
    ///
    /// The SSO cookie is scoped to the tenant host and `path=/`, so without this
    /// a single login would be redeemable at *every* client of that tenant —
    /// including the console's. Stamping the pool at mint time and asserting it
    /// at redemption is what keeps a session confined to the directory that
    /// issued it.
    pub pool_id: Uuid,
    pub identity_id: Uuid,
    /// Methods presented at this login (RFC 8176), stamped here because it is
    /// the only point that knows them: by the time an access token is minted,
    /// the password and the second factor are several hops behind.
    ///
    /// Defaulted for sessions established before this field existed — they
    /// simply carry no `amr`, which is the honest answer for a session whose
    /// methods were never recorded.
    #[serde(default)]
    pub amr: Vec<String>,
    /// The identity's session epoch at mint time. Redemption refuses the session
    /// once the identity's epoch has moved past this — how a password change
    /// revokes live cookies. Defaulted to 0 so sessions minted before this field
    /// existed match a never-revoked identity and keep working across the deploy.
    #[serde(default)]
    pub epoch: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A redeemed SSO session: who it belongs to, and how they proved it.
pub struct SsoSession {
    pub identity: Identity,
    pub amr: Vec<String>,
    /// When the credentials were presented — `auth_time` for every token that
    /// descends from this session.
    pub authenticated_at: OffsetDateTime,
}

pub type SsoToken = String;

/// The payload behind a password-reset token, held in Redis under the token's
/// hash. Naming the pool as well as the identity keeps the reset scoped to the
/// directory the link was issued for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetContext {
    pub tenant_id: Uuid,
    pub pool_id: Uuid,
    pub identity_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Outcome of a self-service password change.
#[derive(Debug)]
pub enum ChangePasswordOutcome {
    /// Password changed; every session revoked.
    Completed,
    /// A verified second factor is enrolled and no code was supplied — the
    /// caller must resubmit with one of these methods.
    MfaRequired(MfaOptions),
}

/// Outcome of presenting a valid reset token.
#[derive(Debug)]
pub enum PasswordResetOutcome {
    /// No second factor stood in the way; the password was set and sessions
    /// revoked.
    Completed,
    /// A second factor is required. The reset token is already spent; this
    /// challenge must be redeemed to finish the reset.
    MfaRequired(MfaRequiredDetails),
}

impl<
    I: IdentityRepository,
    A: AuthorizationRepository,
    R: TokenRepository,
    KR: KeyRepository,
    KP: KeyEncryptionProvider,
    M: MfaRepository,
> AuthenticationService<I, A, R, KR, KP, M>
{
    pub fn new(
        identity_service: IdentityService<I, A>,
        //client_service: ClientService<C>,
        token_service: TokenService<R, KR, KP>,
        mfa_service: MfaService<M, KP>,
        audit: AuditService,
    ) -> Self {
        Self {
            identity_service,
            //client_service,
            token_service,
            mfa_service,
            audit,
        }
    }

    /// Whether this identity has a second factor that actually protects a login.
    ///
    /// Equivalent to "was this session necessarily MFA-verified": login demands
    /// a challenge exactly when `get_available_options` is non-empty, and there
    /// is no path around it, so a verified method existing at token-minting time
    /// means the session behind it was established with one.
    ///
    /// Unverified enrollments deliberately do not count — a half-finished TOTP
    /// setup grants nothing at login and must not satisfy a policy either.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn has_verified_mfa(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<bool, ServiceError> {
        let options = self
            .mfa_service
            .get_available_options(tenant_id, identity_id)
            .await?;
        Ok(!options.is_empty())
    }

    #[instrument(skip_all, fields(tenant_id = %tenant_id))]
    pub async fn authenticate_user_sso(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        issuer: &str,
        handle: IdentityHandle,
        password: &str,
        config: TenantConfiguration,
        ctx: &AuditContext,
    ) -> Result<SsoToken, ServiceError> {
        let identity = match self
            .identity_service
            .authenticate(pool_id, handle.clone(), password)
            .await
        {
            Ok(identity) => identity,
            Err(e) => {
                // Audit auth failures, not infrastructure errors.
                let outcome = match &e {
                    ServiceError::InvalidCredentials => Some(AuditOutcome::Failure),
                    ServiceError::Forbidden => Some(AuditOutcome::Denied),
                    _ => None,
                };
                if let Some(outcome) = outcome {
                    self.audit.record(
                        AuditEvent::new(
                            tenant_id,
                            AuditEventType::AuthLogin,
                            AuditActor::Anonymous,
                            outcome,
                            ctx.clone(),
                        )
                        .with_details(json!({"username": handle_display(&handle)})),
                    );
                }
                return Err(e);
            }
        };
        debug!(
            "Password verified for tenant {} and handle {:?}",
            tenant_id, handle
        );

        let options = self
            .mfa_service
            .get_available_options(tenant_id, identity.id)
            .await?;
        if options.is_empty() {
            self.audit.record(
                AuditEvent::new(
                    tenant_id,
                    AuditEventType::AuthLogin,
                    AuditActor::Identity(identity.id),
                    AuditOutcome::Success,
                    ctx.clone(),
                )
                .with_details(json!({"mfa": false})),
            );
            return self
                .establish_sso_session(
                    tenant_id,
                    pool_id,
                    identity.id,
                    vec![AMR_PASSWORD.to_string()],
                    &config,
                )
                .await;
        }

        debug!(
            "Authentication requires MFA for tenant {} and identity {}",
            tenant_id, identity.id
        );
        let details = self
            .mint_mfa_challenge(
                tenant_id,
                pool_id,
                issuer,
                identity.id,
                MFA_SCOPE,
                options,
                &config,
            )
            .await?;
        self.audit.record(AuditEvent::new(
            tenant_id,
            AuditEventType::AuthMfaChallenge,
            AuditActor::Identity(identity.id),
            AuditOutcome::Success,
            ctx.clone(),
        ));
        Err(ServiceError::MfaRequired(details))
    }

    /// Mints the short-lived JWT that gates a second-factor step, for either a
    /// login (`MFA_SCOPE`) or a password reset (`PWD_RESET_MFA_SCOPE`). The token
    /// grants nothing but the right to attempt verification against `scope`; its
    /// `pool_id` is re-checked at redemption so it cannot cross a pool boundary.
    #[instrument(skip(self, options, config), fields(tenant_id = %tenant_id, pool_id = %pool_id, identity_id = %identity_id, scope = %scope))]
    pub async fn mint_mfa_challenge(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        issuer: &str,
        identity_id: Uuid,
        scope: &str,
        options: MfaOptions,
        config: &TenantConfiguration,
    ) -> Result<MfaRequiredDetails, ServiceError> {
        let expiry = config
            .authentication_configuration
            .mfa_token_lifetime_seconds;
        let user_id = identity_id.to_string();
        let claims = JwtCustomClaims {
            sub: user_id.clone(),
            aud: user_id,
            tenant_id,
            // Carried so the verification step re-reads the identity from the
            // same directory the first factor was checked against.
            pool_id,
            scopes: vec![scope.to_string()],
        };
        let token = self
            .token_service
            .mint_jwt_custom(tenant_id, issuer, expiry, claims)
            .await?;
        Ok(MfaRequiredDetails {
            user_id: identity_id,
            token,
            options,
        })
    }

    /// Validates a second-factor challenge token and the verification code
    /// against it, returning the verified identity id. Shared by login and
    /// password reset; the two differ only in `expected_scope` and in what the
    /// caller does with the result.
    ///
    /// Enforces, in order: token authenticity, that its scope is exactly the one
    /// the caller expects (a login challenge cannot complete a reset, or the
    /// reverse), pool binding, single use, a bounded attempt count, that the
    /// account is still active, and finally the code itself. Records the MFA
    /// verification audit events; the *domain* event (login vs. password change)
    /// belongs to the caller.
    /// `expected_pool` anchors the token to a pool derived from something outside
    /// it — the OAuth client at login. Password reset has no such anchor (no
    /// client is involved), so it passes `None`: the token is signed, single-use
    /// and scope-bound, which already fixes the identity and pool it names.
    ///
    /// Returns the verified identity and the pool it belongs to (from the token),
    /// so a caller with no pool of its own still knows where the identity lives.
    #[instrument(skip(self, mfa_token, code), fields(tenant_id = %tenant_id, expected_scope = %expected_scope))]
    pub async fn consume_mfa_challenge(
        &self,
        tenant_id: Uuid,
        expected_pool: Option<Uuid>,
        issuer: &str,
        mfa_token: &str,
        method: MfaOption,
        code: &str,
        expected_scope: &str,
        config: &TenantConfiguration,
        ctx: &AuditContext,
    ) -> Result<(Uuid, Uuid), ServiceError> {
        let claims = match self
            .token_service
            .verify_jwt(tenant_id, issuer, mfa_token, None)
            .await
        {
            Ok(claims) => claims,
            Err(e) => {
                warn!("MFA token verification failed: {}", e);
                self.audit.record(
                    AuditEvent::new(
                        tenant_id,
                        AuditEventType::AuthMfaVerify,
                        AuditActor::Anonymous,
                        AuditOutcome::Failure,
                        ctx.clone(),
                    )
                    .with_details(json!({"reason": "invalid_mfa_token"})),
                );
                return Err(ServiceError::InvalidMfaToken);
            }
        };

        // Scope must match exactly. This is what keeps the login and reset
        // challenges from being interchangeable: a token carrying `knox:mfa`
        // cannot be spent to reset a password, and one carrying
        // `knox:pwd_reset_mfa` cannot mint a session.
        if !claims.scopes.iter().any(|s| s == expected_scope) {
            warn!(
                "MFA token with wrong scope at verification for tenant {}: expected {}",
                tenant_id, expected_scope
            );
            return Err(ServiceError::InvalidMfaToken);
        }

        // The MFA token was minted against the pool the first factor was checked
        // in. Redeeming it at a client bound to a different pool would launder a
        // half-completed end-user flow into a staff one — enforced only when the
        // caller supplies an external pool to check against (login).
        if let Some(expected) = expected_pool {
            if claims.pool_id != expected {
                warn!(
                    "MFA token pool mismatch for tenant {}: token pool {}, request pool {}",
                    tenant_id, claims.pool_id, expected
                );
                return Err(ServiceError::InvalidMfaToken);
            }
        }
        // The identity lives in the pool the token names; a supplied
        // `expected_pool` has just been proven equal to it.
        let pool_id = claims.pool_id;

        // The JWT is verified beyond this point: its sub is trustworthy.
        let identity_id =
            Uuid::parse_str(&claims.sub).map_err(|_| ServiceError::InvalidMfaToken)?;
        let actor = AuditActor::Identity(identity_id);

        let used: Option<bool> = self
            .token_service
            .retrieve_transient_token(TransientKind::MfaUsed, &claims.jti)
            .await?;
        if used.is_some() {
            warn!(
                "Replay of consumed MFA token {} for tenant {}",
                claims.jti, tenant_id
            );
            self.audit.record(
                AuditEvent::new(
                    tenant_id,
                    AuditEventType::AuthMfaVerify,
                    actor,
                    AuditOutcome::Failure,
                    ctx.clone(),
                )
                .with_details(json!({"reason": "mfa_token_reused"})),
            );
            return Err(ServiceError::InvalidMfaToken);
        }

        let lifetime = config
            .authentication_configuration
            .mfa_token_lifetime_seconds;
        let attempts = self
            .token_service
            .increment_transient_counter(TransientKind::MfaAttempts, &claims.jti, lifetime)
            .await?;
        if attempts
            > config
                .authentication_configuration
                .mfa_max_verification_attempts as u64
        {
            warn!(
                "Too many MFA attempts for token {} in tenant {}",
                claims.jti, tenant_id
            );
            self.audit.record(
                AuditEvent::new(
                    tenant_id,
                    AuditEventType::AuthMfaLockout,
                    actor,
                    AuditOutcome::Denied,
                    ctx.clone(),
                )
                .with_details(json!({"attempts": attempts})),
            );
            return Err(ServiceError::MfaTooManyAttempts);
        }

        // The account could have been disabled during the MFA window.
        let identity = self
            .identity_service
            .get_identity(pool_id, identity_id)
            .await?;
        if identity.status != Status::Active {
            warn!(
                "MFA verification for non-active identity {} in tenant {}",
                identity_id, tenant_id
            );
            return Err(ServiceError::Forbidden);
        }

        if let Err(e) = self
            .mfa_service
            .verify(tenant_id, identity_id, method, code)
            .await
        {
            if matches!(
                e,
                ServiceError::InvalidMfaCode | ServiceError::MfaNotEnrolled
            ) {
                self.audit.record(
                    AuditEvent::new(
                        tenant_id,
                        AuditEventType::AuthMfaVerify,
                        actor,
                        AuditOutcome::Failure,
                        ctx.clone(),
                    )
                    .with_details(json!({"method": method_str(method), "reason": "invalid_code"})),
                );
            }
            return Err(e);
        }

        // Mark consumed only after a successful verification; failed attempts
        // are bounded by the counter above.
        self.token_service
            .store_transient_token(TransientKind::MfaUsed, &claims.jti, &true, lifetime)
            .await?;

        self.audit.record(
            AuditEvent::new(
                tenant_id,
                AuditEventType::AuthMfaVerify,
                actor,
                AuditOutcome::Success,
                ctx.clone(),
            )
            .with_details(json!({"method": method_str(method)})),
        );

        Ok((identity_id, pool_id))
    }

    /// Completes an MFA login: validates the short-lived MFA token, checks
    /// the verification code, and exchanges them for an SSO session. MFA
    /// tokens are single-use and allow a limited number of attempts.
    #[instrument(skip(self, mfa_token, code), fields(tenant_id = %tenant_id))]
    pub async fn authenticate_user_mfa(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        issuer: &str,
        mfa_token: &str,
        method: MfaOption,
        code: &str,
        config: &TenantConfiguration,
        ctx: &AuditContext,
    ) -> Result<SsoToken, ServiceError> {
        let (identity_id, _pool_id) = self
            .consume_mfa_challenge(
                tenant_id,
                Some(pool_id),
                issuer,
                mfa_token,
                method,
                code,
                MFA_SCOPE,
                config,
                ctx,
            )
            .await?;
        let actor = AuditActor::Identity(identity_id);

        // The completed login, so `auth.login` alone captures every login outcome.
        self.audit.record(
            AuditEvent::new(
                tenant_id,
                AuditEventType::AuthLogin,
                actor,
                AuditOutcome::Success,
                ctx.clone(),
            )
            .with_details(json!({"mfa": true, "method": method_str(method)})),
        );

        self.establish_sso_session(
            tenant_id,
            pool_id,
            identity_id,
            // Both factors, plus the `mfa` marker so a resource server can test
            // for multi-factor without enumerating the methods Knox supports.
            vec![
                AMR_PASSWORD.to_string(),
                amr_for_method(method).to_string(),
                AMR_MULTI_FACTOR.to_string(),
            ],
            config,
        )
        .await
    }

    /// How long the session-epoch counter is kept alive. It must outlive the
    /// longest-lived session it stamps — otherwise an expired counter would read
    /// back as 0 and a still-valid session would validate against the wrong
    /// epoch. Refreshed on every mint (and every bump), so it survives as long
    /// as sessions are being issued. Floored at 24h so a tenant with a short
    /// cookie lifetime still gets a comfortable margin; the only failure
    /// direction is a spurious logout, never a resurrected session.
    fn sso_epoch_ttl(config: &TenantConfiguration) -> Duration {
        let cookie = config
            .authentication_configuration
            .sso_cookie_lifetime_seconds;
        Duration::seconds(cookie.whole_seconds() * 2).max(Duration::hours(24))
    }

    /// `amr` is what was presented to get here — see `SsoSessionContext::amr`.
    #[instrument(skip(self, config, amr), fields(tenant_id = %tenant_id, pool_id = %pool_id, identity_id = %identity_id))]
    pub async fn establish_sso_session(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        identity_id: Uuid,
        amr: Vec<String>,
        config: &TenantConfiguration,
    ) -> Result<SsoToken, ServiceError> {
        // Stamp the identity's current epoch into the session and keep the
        // counter alive. Redemption compares against this; a later bump (e.g. a
        // password change) leaves this session behind.
        let epoch = self
            .token_service
            .current_sso_epoch(tenant_id, identity_id)
            .await?;
        let epoch_ttl = Self::sso_epoch_ttl(config);
        self.token_service
            .touch_sso_epoch(tenant_id, identity_id, epoch_ttl)
            .await?;

        let context = SsoSessionContext {
            tenant_id,
            pool_id,
            identity_id,
            amr,
            epoch,
            created_at: OffsetDateTime::now_utc(),
        };
        let token = self.token_service.generate_opaque_token(32);
        debug!(
            "Generated SSO token for tenant {} and identity {}",
            tenant_id, identity_id
        );
        self.token_service
            .store_transient_token(
                TransientKind::SsoToken,
                &token,
                &context,
                config
                    .authentication_configuration
                    .sso_cookie_lifetime_seconds,
            )
            .await?;
        debug!(
            "Stored transient token for tenant {} and identity {}",
            tenant_id, identity_id
        );
        Ok(token)
    }

    /// Revokes every active credential for an identity: refresh-token families
    /// *and* SSO sessions. The epoch bump is what reaches the sessions — they
    /// live in Redis keyed by their opaque token with no by-identity index, so
    /// advancing the counter every live session was stamped against is the only
    /// O(1) way to invalidate them all, including ones this process never saw.
    ///
    /// Every password-set path funnels through here so no caller can revoke the
    /// refresh tokens while leaving a live cookie able to mint fresh ones.
    #[instrument(skip(self, config), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn revoke_all_sessions(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        config: &TenantConfiguration,
    ) -> Result<(), ServiceError> {
        self.token_service
            .revoke_all_for_identity(tenant_id, identity_id)
            .await?;
        let epoch_ttl = Self::sso_epoch_ttl(config);
        let epoch = self
            .token_service
            .bump_sso_epoch(tenant_id, identity_id, epoch_ttl)
            .await?;
        debug!(
            "Revoked all sessions for identity {} in tenant {} (epoch now {})",
            identity_id, tenant_id, epoch
        );
        Ok(())
    }

    #[instrument(skip(self, token))]
    pub async fn validate_sso_code(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        token: &str,
        max_age: Option<u32>,
    ) -> Result<SsoSession, ServiceError> {
        let stored: Option<SsoSessionContext> = self
            .token_service
            .retrieve_transient_token(TransientKind::SsoToken, token)
            .await?;
        match stored {
            Some(session) if session.tenant_id == tenant_id && session.pool_id == pool_id => {
                // A session minted before the identity's epoch last moved has
                // been revoked — a password change advances the epoch, so a
                // cookie predating the change no longer redeems even though it
                // has not yet expired.
                let epoch = self
                    .token_service
                    .current_sso_epoch(tenant_id, session.identity_id)
                    .await?;
                if session.epoch < epoch {
                    warn!(
                        "SSO token for identity {} in tenant {} is stale: session epoch {} < current {}",
                        session.identity_id, tenant_id, session.epoch, epoch
                    );
                    return Err(ServiceError::InvalidSsoToken);
                }
                if let Some(max_age) = max_age {
                    let age = OffsetDateTime::now_utc() - session.created_at;
                    if age > Duration::seconds(max_age as i64) {
                        error!(
                            "SSO token {} for tenant {} is too old: age {} seconds, max_age {} seconds",
                            token,
                            tenant_id,
                            age.whole_seconds(),
                            max_age
                        );
                        return Err(ServiceError::SsoTokenExpired);
                    }
                }
                let identity = self
                    .identity_service
                    .get_identity(pool_id, session.identity_id)
                    .await?;
                if identity.status != Status::Active {
                    return Err(ServiceError::InvalidSsoToken);
                }
                Ok(SsoSession {
                    identity,
                    amr: session.amr,
                    authenticated_at: session.created_at,
                })
            }
            Some(s) => {
                error!(
                    "SSO token scope mismatch: expected tenant {} pool {}, got tenant {} pool {}",
                    tenant_id, pool_id, s.tenant_id, s.pool_id
                );
                Err(ServiceError::InvalidSsoToken)
            }
            None => Err(ServiceError::InvalidSsoToken),
        }
    }

    // ── Password change & reset ──────────────────────────────────────────────

    /// Self-service password change for a signed-in identity.
    ///
    /// The current password is checked *first*, before any second-factor code is
    /// spent — a wrong password on this path must not burn a one-time backup
    /// code. When a verified factor is enrolled it is then required, bounded by
    /// the same attempt ceiling as login. On success every session is revoked,
    /// the caller's own included, so the change actually signs stale cookies out.
    #[instrument(skip(self, current_password, new_password, mfa, config, ctx), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn change_own_password(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        identity_id: Uuid,
        current_password: &str,
        new_password: &str,
        mfa: Option<(MfaOption, String)>,
        config: &TenantConfiguration,
        ctx: &AuditContext,
    ) -> Result<ChangePasswordOutcome, ServiceError> {
        self.identity_service
            .authenticate(pool_id, IdentityHandle::Id(identity_id), current_password)
            .await?;

        let enrolled = self.has_verified_mfa(tenant_id, identity_id).await?;
        if enrolled {
            let Some((method, code)) = mfa else {
                let options = self
                    .mfa_service
                    .get_available_options(tenant_id, identity_id)
                    .await?;
                return Ok(ChangePasswordOutcome::MfaRequired(options));
            };
            // No challenge token exists on this path, so the attempt counter is
            // keyed by identity rather than a jti. Same ceiling as login.
            let lifetime = config
                .authentication_configuration
                .mfa_token_lifetime_seconds;
            let attempts = self
                .token_service
                .increment_transient_counter(
                    TransientKind::MfaAttempts,
                    &format!("self:{}", identity_id),
                    lifetime,
                )
                .await?;
            if attempts
                > config
                    .authentication_configuration
                    .mfa_max_verification_attempts as u64
            {
                self.audit.record(
                    AuditEvent::new(
                        tenant_id,
                        AuditEventType::AuthMfaLockout,
                        AuditActor::Identity(identity_id),
                        AuditOutcome::Denied,
                        ctx.clone(),
                    )
                    .with_details(json!({"context": "password_change"})),
                );
                return Err(ServiceError::MfaTooManyAttempts);
            }
            self.mfa_service
                .verify(tenant_id, identity_id, method, &code)
                .await?;
        }

        self.identity_service
            .set_password(pool_id, identity_id, new_password)
            .await?;
        self.revoke_all_sessions(tenant_id, identity_id, config)
            .await?;

        self.audit.record(
            AuditEvent::new(
                tenant_id,
                AuditEventType::PasswordChanged,
                AuditActor::Identity(identity_id),
                AuditOutcome::Success,
                ctx.clone(),
            )
            .with_target("identity", identity_id.to_string())
            .with_details(json!({"via": "self", "mfa": enrolled})),
        );
        Ok(ChangePasswordOutcome::Completed)
    }

    /// Mints a single-use, short-lived password-reset token and stores its
    /// *hash* against the identity. Shared by the admin-initiated and (gated)
    /// self-service flows; the caller decides how the resulting token reaches
    /// the user and records its own audit event, since the actor differs.
    #[instrument(skip(self, config), fields(tenant_id = %tenant_id, identity_id = %identity_id))]
    pub async fn request_password_reset(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        identity_id: Uuid,
        config: &TenantConfiguration,
    ) -> Result<(String, OffsetDateTime), ServiceError> {
        let token = self.token_service.generate_opaque_token(32);
        let ttl = config
            .authentication_configuration
            .password_reset_token_lifetime_seconds;
        let context = PasswordResetContext {
            tenant_id,
            pool_id,
            identity_id,
            created_at: OffsetDateTime::now_utc(),
        };
        // Store the hash, never the token: a Redis dump then yields nothing a
        // caller could present.
        let key = TokenService::<R, KR, KP>::hash_token(&token);
        self.token_service
            .store_transient_token(TransientKind::PasswordReset, &key, &context, ttl)
            .await?;
        Ok((token, OffsetDateTime::now_utc() + ttl))
    }

    /// Self-service reset request, resolved from a username. Safe to call for a
    /// handle that does not exist — it returns `None` rather than revealing that
    /// — and throttled per pool+handle so it cannot enumerate accounts or spam
    /// links. Audits the request itself (actor = the identity) when one is
    /// issued; the caller only decides how the link is delivered.
    ///
    /// The `None` results (throttled, unknown handle, inactive account) are
    /// deliberately indistinguishable to the caller, which answers `200` either
    /// way.
    #[instrument(skip(self, config, ctx), fields(tenant_id = %tenant_id, pool_id = %pool_id))]
    pub async fn request_password_reset_by_username(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
        username: &str,
        config: &TenantConfiguration,
        ctx: &AuditContext,
    ) -> Result<Option<(String, OffsetDateTime, Uuid)>, ServiceError> {
        let ttl = config
            .authentication_configuration
            .password_reset_token_lifetime_seconds;

        // Throttle before the lookup so the response cannot be timed to reveal
        // whether the handle exists.
        let throttle_key = format!("{}:{}", pool_id, username.to_lowercase());
        let attempts = self
            .token_service
            .increment_transient_counter(TransientKind::PasswordResetThrottle, &throttle_key, ttl)
            .await?;
        if attempts > MAX_RESET_REQUESTS_PER_WINDOW {
            warn!(
                "Password reset throttled for pool {} handle {}",
                pool_id, username
            );
            return Ok(None);
        }

        let identity = self
            .identity_service
            .find_by_handle(pool_id, IdentityHandle::Username(username.to_string()))
            .await?;
        let Some(identity) = identity else {
            debug!(
                "Password reset requested for unknown handle in pool {}",
                pool_id
            );
            return Ok(None);
        };
        if identity.status != Status::Active {
            debug!(
                "Password reset requested for inactive identity {}",
                identity.id
            );
            return Ok(None);
        }

        let (token, expires_at) = self
            .request_password_reset(tenant_id, pool_id, identity.id, config)
            .await?;
        self.audit.record(
            AuditEvent::new(
                tenant_id,
                AuditEventType::PasswordResetRequested,
                AuditActor::Identity(identity.id),
                AuditOutcome::Success,
                ctx.clone(),
            )
            .with_target("identity", identity.id.to_string())
            .with_details(json!({"via": "self_service"})),
        );
        Ok(Some((token, expires_at, identity.id)))
    }

    /// Step one of redeeming a reset token. Presenting the token consumes it in
    /// either case. With no verified factor the password is set immediately and
    /// sessions revoked; otherwise the password is left untouched and a reset-
    /// scoped MFA challenge is returned — the new password is never written or
    /// signed anywhere at this step, it is resubmitted to
    /// `complete_password_reset_mfa`.
    #[instrument(skip(self, token, new_password, config, ctx), fields(tenant_id = %tenant_id))]
    pub async fn reset_password_with_token(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        token: &str,
        new_password: &str,
        config: &TenantConfiguration,
        ctx: &AuditContext,
    ) -> Result<PasswordResetOutcome, ServiceError> {
        let key = TokenService::<R, KR, KP>::hash_token(token);
        let context: PasswordResetContext = self
            .token_service
            .take_transient_token(TransientKind::PasswordReset, &key)
            .await?
            .ok_or(ServiceError::InvalidResetToken)?;

        // The token host fixes the tenant; a token minted elsewhere is not
        // spendable here even if it is otherwise valid.
        if context.tenant_id != tenant_id {
            warn!(
                "Reset token tenant mismatch: token {}, request {}",
                context.tenant_id, tenant_id
            );
            return Err(ServiceError::InvalidResetToken);
        }

        let options = self
            .mfa_service
            .get_available_options(tenant_id, context.identity_id)
            .await?;
        if options.is_empty() {
            self.identity_service
                .set_password(context.pool_id, context.identity_id, new_password)
                .await?;
            self.revoke_all_sessions(tenant_id, context.identity_id, config)
                .await?;
            self.audit.record(
                AuditEvent::new(
                    tenant_id,
                    AuditEventType::PasswordChanged,
                    AuditActor::Identity(context.identity_id),
                    AuditOutcome::Success,
                    ctx.clone(),
                )
                .with_target("identity", context.identity_id.to_string())
                .with_details(json!({"via": "reset", "mfa": false})),
            );
            Ok(PasswordResetOutcome::Completed)
        } else {
            let details = self
                .mint_mfa_challenge(
                    tenant_id,
                    context.pool_id,
                    issuer,
                    context.identity_id,
                    PWD_RESET_MFA_SCOPE,
                    options,
                    config,
                )
                .await?;
            Ok(PasswordResetOutcome::MfaRequired(details))
        }
    }

    /// Step two: the second factor for a reset. Validates the reset-scoped
    /// challenge (which a login challenge can never satisfy — see
    /// `consume_mfa_challenge`), sets the password, and revokes every session.
    #[instrument(skip(self, mfa_token, code, new_password, config, ctx), fields(tenant_id = %tenant_id))]
    pub async fn complete_password_reset_mfa(
        &self,
        tenant_id: Uuid,
        issuer: &str,
        mfa_token: &str,
        method: MfaOption,
        code: &str,
        new_password: &str,
        config: &TenantConfiguration,
        ctx: &AuditContext,
    ) -> Result<(), ServiceError> {
        let (identity_id, pool_id) = self
            .consume_mfa_challenge(
                tenant_id,
                None,
                issuer,
                mfa_token,
                method,
                code,
                PWD_RESET_MFA_SCOPE,
                config,
                ctx,
            )
            .await?;
        self.identity_service
            .set_password(pool_id, identity_id, new_password)
            .await?;
        self.revoke_all_sessions(tenant_id, identity_id, config)
            .await?;
        self.audit.record(
            AuditEvent::new(
                tenant_id,
                AuditEventType::PasswordChanged,
                AuditActor::Identity(identity_id),
                AuditOutcome::Success,
                ctx.clone(),
            )
            .with_target("identity", identity_id.to_string())
            .with_details(json!({"via": "reset", "method": method_str(method)})),
        );
        Ok(())
    }
}
