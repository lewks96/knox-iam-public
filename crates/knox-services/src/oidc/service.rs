use crate::oidc::models::AuthorizeResult::{InvalidPrincipalType, RedirectUriMismatch, Success};
use crate::oidc::models::{
    AuthorizeRequest, AuthorizeResponse, AuthorizeResult, MintingContext, TokenGrantRequest,
    TokenResponse,
};
use base64::Engine;
use knox_common::audit::{AuditActor, AuditContext, AuditEvent, AuditEventType, AuditOutcome};
use knox_common::authorization::AuthorizationRepository;
use knox_common::identity::IdentityKind::Machine;
use knox_common::identity::IdentityRepository;
use knox_common::identity::Status;
use knox_common::pool::{PoolKind, PoolRepository};
use knox_common::tenant::AuthorizationConfiguration;
use knox_common::token::{AuthCodeContext, RefreshToken};
use knox_common::{
    client::ClientRepository,
    error::ServiceError,
    key::{KeyEncryptionProvider, KeyRepository},
    mfa::MfaRepository,
    token::TokenRepository,
};
use knox_core::audit::AuditService;
use knox_core::authentication::AuthenticationService;
use knox_core::identity::IdentityService;
use knox_core::roles::{is_oidc_scope, is_platform_scope, is_self_service_scope};
use knox_core::token::{AuthenticationContext, IdTokenInput, TransientKind};
use knox_core::{client::ClientService, token::TokenService};
use serde_json::json;
use std::collections::HashSet;
use time::Duration;
use tracing::{debug, error, instrument, warn};
use uuid::Uuid;

/// The OIDC `name` claim assembled from an identity's parts, or `None` when it
/// has neither — so a missing name is an absent claim, not an empty string.
fn oidc_display_name(first: &Option<String>, last: &Option<String>) -> Option<String> {
    match (first, last) {
        (Some(f), Some(l)) => Some(format!("{f} {l}")),
        (Some(f), None) => Some(f.clone()),
        (None, Some(l)) => Some(l.clone()),
        (None, None) => None,
    }
}

#[derive(Clone)]
pub struct OIDCService<
    I: IdentityRepository,
    AR: AuthorizationRepository,
    CR: ClientRepository,
    TR: TokenRepository,
    KR: KeyRepository,
    KP: KeyEncryptionProvider,
    M: MfaRepository,
    PL: PoolRepository,
> {
    identity_service: IdentityService<I, AR>,
    client_service: ClientService<CR>,
    token_service: TokenService<TR, KR, KP>,
    authentication_service: AuthenticationService<I, AR, TR, KR, KP, M>,
    pool_repo: PL,
    audit: AuditService,
}

impl<
    I: IdentityRepository,
    AR: AuthorizationRepository,
    CR: ClientRepository,
    TR: TokenRepository,
    KR: KeyRepository,
    KP: KeyEncryptionProvider,
    M: MfaRepository,
    PL: PoolRepository,
> OIDCService<I, AR, CR, TR, KR, KP, M, PL>
{
    pub fn new(
        client_service: ClientService<CR>,
        token_service: TokenService<TR, KR, KP>,
        authentication_service: AuthenticationService<I, AR, TR, KR, KP, M>,
        identity_service: IdentityService<I, AR>,
        pool_repo: PL,
        audit: AuditService,
    ) -> Self {
        Self {
            client_service,
            token_service,
            authentication_service,
            identity_service,
            pool_repo,
            audit,
        }
    }

    /// The kind of the pool a client authenticates against. Minted into every
    /// access token so `RequireAuth` can tell a staff token from an end-user one
    /// without a per-request lookup.
    async fn pool_kind_for(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
    ) -> Result<PoolKind, ServiceError> {
        self.pool_repo
            .get_in_tenant(tenant_id, pool_id)
            .await
            .map_err(ServiceError::Repository)?
            .map(|p| p.kind)
            .ok_or_else(|| ServiceError::Internal("Client references a missing pool".into()))
    }

    #[instrument(skip(self))]
    pub async fn handle_authorize_request(
        &self,
        tenant_id: Uuid,
        req: AuthorizeRequest,
        config: &AuthorizationConfiguration,
    ) -> Result<AuthorizeResult, ServiceError> {
        let client = self
            .client_service
            .get_active_client_by_name(tenant_id, &req.client_id)
            .await?;
        if !client.redirect_uris.contains(&req.redirect_uri) {
            return Ok(RedirectUriMismatch);
        }

        // Validate PKCE challenge format
        if req.code_challenge.is_empty() {
            debug!("Missing PKCE code challenge for client {}", req.client_id);
            return Ok(AuthorizeResult::InvalidRequest);
        }

        // Validate code challenge format based on method
        match req.code_challenge_method {
            crate::oidc::models::CodeChallengeMethod::Plain => {
                if !config.allow_plain_pkce {
                    debug!(
                        "Plain PKCE not allowed for tenant {} client {}",
                        tenant_id, req.client_id
                    );
                    return Ok(AuthorizeResult::InvalidRequest);
                }
                if req.code_challenge.len() < 43 || req.code_challenge.len() > 128 {
                    debug!(
                        "Invalid code challenge length for plain PKCE: {}",
                        req.code_challenge.len()
                    );
                    return Ok(AuthorizeResult::InvalidRequest);
                }
            }
            crate::oidc::models::CodeChallengeMethod::S256 => {
                if req.code_challenge.len() != 43 {
                    debug!(
                        "Invalid code challenge length for S256: expected 43, got {}",
                        req.code_challenge.len()
                    );
                    return Ok(AuthorizeResult::InvalidRequest);
                }
                // Validate base64url format (no padding, URL-safe alphabet)
                if !req
                    .code_challenge
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    debug!("Invalid code challenge format for S256");
                    return Ok(AuthorizeResult::InvalidRequest);
                }
            }
        }

        // `prompt=login` (OIDC Core §3.1.2.1) means the relying party wants the
        // user re-authenticated regardless of how good the current session is,
        // so it is decided before the session is even looked at.
        //
        // This does not loop: the URL the login page is sent back to is rebuilt
        // without `prompt`, so the second pass consults the freshly minted
        // session normally. See `login_redirect` in the oidc handler.
        if req.prompt.as_deref() == Some("login") {
            debug!("prompt=login requested for client {}", req.client_id);
            return Ok(AuthorizeResult::ReAuthRequired);
        }

        // The session must have been established against the same directory this
        // client authenticates. A session minted at an end-user client is not a
        // session at the console, even on the same tenant host — the SSO cookie
        // is path=/ and shared across every client of the tenant.
        let session = match self
            .authentication_service
            .validate_sso_code(tenant_id, client.pool_id, &req.sso_token, req.max_age)
            .await
        {
            Ok(session) => session,
            Err(ServiceError::SsoTokenExpired) => return Ok(AuthorizeResult::ReAuthRequired),
            Err(_) => return Ok(AuthorizeResult::SessionInvalid),
        };

        let identity = &session.identity;
        if identity.kind == Machine {
            return Ok(InvalidPrincipalType(Machine));
        }

        // Validate scopes
        if req.scope.is_empty() {
            debug!("Empty scope requested for client {}", req.client_id);
            return Ok(AuthorizeResult::InvalidRequest);
        }

        let allowed: HashSet<&str> = client.allowed_scopes.iter().map(String::as_str).collect();
        let requested: HashSet<&str> = req.scope.iter().map(String::as_str).collect();

        debug!(
            "Client {} allowed scopes: {:?}",
            req.client_id, client.allowed_scopes
        );
        debug!("Client {} requested scopes: {:?}", req.client_id, req.scope);

        let unauthorized: Vec<&str> = requested.difference(&allowed).copied().collect();
        if !unauthorized.is_empty() {
            debug!(
                "Client {} requested unauthorized scopes: {:?}",
                req.client_id, unauthorized
            );
            return Ok(AuthorizeResult::UnauthorizedScope);
        }

        let ctx = AuthCodeContext {
            tenant_id,
            client_id: client.id,
            identity_id: identity.id,
            scopes: req.scope.clone(),
            redirect_uri: req.redirect_uri.clone(),
            pkce_code_challenge: req.code_challenge,
            pkce_code_challenge_method: req.code_challenge_method.into(),
            nonce: req.nonce,
            // Snapshot of the login, taken here because the token endpoint sees
            // only the code — the SSO session is not in scope by then.
            amr: session.amr.clone(),
            auth_time: Some(session.authenticated_at),
            created_at: time::OffsetDateTime::now_utc(),
        };

        let code = self.token_service.generate_opaque_token(32);
        self.token_service
            .store_transient_token(
                TransientKind::AuthCode,
                &code,
                &ctx,
                Duration::seconds(client.auth_code_ttl as i64),
            )
            .await?;

        Ok(Success(AuthorizeResponse {
            code,
            redirect_uri: req.redirect_uri,
            state: req.state,
        }))
    }

    /// Narrows requested scopes to what the identity's roles actually permit.
    ///
    /// Without this, a token's scopes are whatever the *client* allows, so any
    /// identity able to authenticate through an admin client could mint an admin
    /// token — the RBAC roles would be decorative. Scopes are the intersection of
    /// what was asked for and what the identity holds.
    ///
    /// Applied on refresh as well as on first issue, so removing a role takes
    /// effect at the next refresh rather than whenever the token happens to expire.
    ///
    /// Narrowing rather than rejecting follows OAuth 2.0 §3.3, which lets the
    /// authorization server issue a smaller scope than requested. An empty result
    /// is an error: a token granting nothing is not a useful thing to hand back.
    #[instrument(skip(self, requested))]
    async fn permitted_scopes(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        requested: Vec<String>,
        config: &AuthorizationConfiguration,
    ) -> Result<Vec<String>, ServiceError> {
        let held = self.identity_service.get_permissions(identity_id).await?;
        // Standard OIDC scopes pass through untouched — they are not RBAC
        // permissions and were already authorised against the client's
        // `allowed_scopes` at `/authorize`. Only permission scopes are
        // intersected with what the identity actually holds.
        let mut granted: Vec<String> = requested
            .iter()
            .filter(|s| is_oidc_scope(s) || held.contains(s))
            .cloned()
            .collect();

        if granted.len() != requested.len() {
            let denied: Vec<&String> = requested
                .iter()
                .filter(|s| !is_oidc_scope(s) && !held.contains(s))
                .collect();
            debug!(
                %identity_id,
                ?denied,
                "Narrowed requested scopes to the identity's permissions"
            );
        }

        // A second narrowing, on the same principle: hold the authority only if
        // you have proven the second factor. Everything past self-service is
        // authority over someone else, so an unenrolled identity keeps only the
        // scopes that let it act on itself — including the `IdentityUpdate` that
        // MFA enrollment needs, which is what stops this being a lockout.
        //
        // Applied on refresh as well as first issue, so turning the policy on
        // takes hold at the next refresh rather than whenever tokens expire.
        // Standard OIDC scopes are never withheld here: MFA gates authority over
        // others, not the right to prove who you are, so a `require_admin_mfa`
        // tenant must still let an unenrolled end user complete an `openid` login.
        let is_kept_without_mfa = |s: &str| is_self_service_scope(s) || is_oidc_scope(s);
        if config.require_admin_mfa && granted.iter().any(|s| !is_kept_without_mfa(s)) {
            let enrolled = self
                .authentication_service
                .has_verified_mfa(tenant_id, identity_id)
                .await?;
            if !enrolled {
                let withheld: Vec<&String> =
                    granted.iter().filter(|s| !is_kept_without_mfa(s)).collect();
                warn!(
                    %identity_id,
                    ?withheld,
                    "require_admin_mfa: withholding scopes from an identity with no verified MFA method"
                );
                granted.retain(|s| is_kept_without_mfa(s));

                // Held admin scopes but nothing self-service: there is no scope
                // left to hand back, and no route to enrollment either, because
                // /api/mfa/* gates on IdentityUpdate. Failing closed is correct,
                // but the operator needs to know the fix is granting IdentitySelf
                // rather than anything about the token request.
                if granted.is_empty() {
                    error!(
                        %identity_id,
                        "require_admin_mfa left no scopes: identity has admin permissions but no \
                         self-service ones, so it cannot enroll. Grant it the IdentitySelf role."
                    );
                    return Err(ServiceError::Forbidden);
                }
            }
        }

        if granted.is_empty() {
            error!(%identity_id, ?requested, "Identity holds none of the requested scopes");
            return Err(ServiceError::Forbidden);
        }

        Ok(granted)
    }

    #[instrument(skip(self, req, ctx))]
    pub async fn handle_token_request(
        &self,
        tenant_id: Uuid,
        tenant_is_platform: bool,
        issuer: &str,
        req: TokenGrantRequest,
        config: &AuthorizationConfiguration,
        ctx: &AuditContext,
    ) -> Result<TokenResponse, ServiceError> {
        let (grant_type, requesting_client) = match &req {
            TokenGrantRequest::ClientCredentials { client_id, .. } => {
                ("client_credentials", client_id.clone())
            }
            TokenGrantRequest::AuthorizationCode { client_id, .. } => {
                ("authorization_code", client_id.clone())
            }
            TokenGrantRequest::RefreshToken { client_id, .. } => {
                ("refresh_token", client_id.clone())
            }
        };

        let context = match req {
            TokenGrantRequest::ClientCredentials {
                client_id,
                client_secret,
                scope,
            } => {
                self.validate_client_credentials(tenant_id, client_id, client_secret, scope)
                    .await
            }
            TokenGrantRequest::AuthorizationCode {
                client_id,
                client_secret,
                code,
                redirect_uri,
                code_verifier,
            } => {
                self.validate_authorization_code(
                    tenant_id,
                    client_id,
                    client_secret,
                    code,
                    redirect_uri,
                    code_verifier,
                    config,
                )
                .await
            }
            TokenGrantRequest::RefreshToken {
                client_id,
                client_secret,
                refresh_token,
            } => {
                self.validate_refresh_token(
                    tenant_id,
                    client_id,
                    client_secret,
                    refresh_token,
                    config,
                    ctx,
                )
                .await
            }
        };

        let context = match context {
            Ok(context) => context,
            Err(e) => {
                // Audit rejected grants, not infrastructure errors.
                if !matches!(e, ServiceError::Repository(_) | ServiceError::Internal(_)) {
                    self.audit.record(
                        AuditEvent::new(
                            tenant_id,
                            AuditEventType::TokenIssued,
                            AuditActor::Anonymous,
                            AuditOutcome::Failure,
                            ctx.clone(),
                        )
                        .with_target("client", requesting_client.clone())
                        .with_details(json!({"grant_type": grant_type, "reason": e.to_string()})),
                    );
                }
                return Err(e);
            }
        };

        // Cross-tenant scopes are only ever mintable for the platform tenant.
        //
        // The identity-bearing grants are already covered by `permitted_scopes`
        // — a non-platform tenant has no role granting these. `client_credentials`
        // is not: it has no identity and so no RBAC narrowing, checking only
        // `client.allowed_scopes`, which every management client sets wide so the
        // single console build can request an identical scope list on every
        // tenant. Enforcing it here covers all three grants in one place rather
        // than trusting per-client configuration.
        let mut context = context;
        if !tenant_is_platform {
            let before = context.scopes.len();
            context.scopes.retain(|s| !is_platform_scope(s));
            if context.scopes.len() != before {
                debug!(
                    "Stripped platform scopes from a non-platform tenant's token (tenant {})",
                    tenant_id
                );
            }
        }

        let access_token = self
            .token_service
            .mint_access_token(
                tenant_id,
                issuer,
                context.subject.clone(),
                context.scopes.clone(),
                context.client.clone(),
                self.pool_kind_for(tenant_id, context.client.pool_id)
                    .await?,
                context.auth.clone(),
            )
            .await?;

        let refresh_token = if context.client.allow_refresh_tokens {
            if let Some(identity_id) = context.identity_id {
                let raw_token = self.token_service.generate_opaque_token(64);
                let token_hash = TokenService::<TR, KR, KP>::hash_token(&raw_token);
                let now = time::OffsetDateTime::now_utc();
                let record = RefreshToken {
                    id: Uuid::new_v4(),
                    tenant_id,
                    client_id: context.client.id,
                    identity_id,
                    token_hash,
                    scopes: context.scopes.clone(),
                    // Rotation must not launder away how the user authenticated:
                    // the next access token in this family reads these back.
                    amr: context
                        .auth
                        .as_ref()
                        .map(|a| a.amr.clone())
                        .unwrap_or_default(),
                    auth_time: context.auth.as_ref().map(|a| a.auth_time),
                    expires_at: now + Duration::seconds(context.client.refresh_token_ttl as i64),
                    revoked_at: None,
                    family_id: context.refresh_token_family_id.unwrap_or_else(Uuid::new_v4),
                    created_at: now,
                    updated_at: now,
                };
                self.token_service.save_refresh_token(&record).await?;
                Some(raw_token)
            } else {
                None
            }
        } else {
            None
        };

        let actor = match context.identity_id {
            Some(identity_id) => AuditActor::Identity(identity_id),
            None => AuditActor::Client(context.client.id),
        };
        self.audit.record(
            AuditEvent::new(
                tenant_id,
                AuditEventType::TokenIssued,
                actor,
                AuditOutcome::Success,
                ctx.clone(),
            )
            .with_target("client", context.client.name.clone())
            .with_details(json!({
                "grant_type": grant_type,
                "scopes": context.scopes,
                "refresh_token_issued": refresh_token.is_some(),
            })),
        );

        // ID token: minted for an OpenID Connect request — the `openid` scope —
        // that carries a user. `client_credentials` has no identity to assert,
        // and a plain-OAuth request without `openid` gets an access token only.
        // Standard claims follow the granted scopes: `email` releases the email
        // claims, `profile` the name ones.
        let id_token =
            if context.identity_id.is_some() && context.scopes.iter().any(|s| s == "openid") {
                let email_scoped = context.scopes.iter().any(|s| s == "email");
                let profile_scoped = context.scopes.iter().any(|s| s == "profile");
                let input = IdTokenInput {
                    subject: context.subject.clone(),
                    // The RP knows the client by its name, so that is the audience.
                    audience: context.client.name.clone(),
                    auth: context.auth.clone(),
                    nonce: context.nonce.clone(),
                    email: if email_scoped {
                        context.email.clone()
                    } else {
                        None
                    },
                    email_verified: context.email_verified,
                    preferred_username: if profile_scoped {
                        context.preferred_username.clone()
                    } else {
                        None
                    },
                    name: if profile_scoped {
                        context.name.clone()
                    } else {
                        None
                    },
                };
                Some(
                    self.token_service
                        .mint_id_token(
                            tenant_id,
                            issuer,
                            Duration::seconds(context.client.id_token_ttl as i64),
                            input,
                            &access_token,
                        )
                        .await?,
                )
            } else {
                None
            };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: context.client.access_token_ttl as u64,
            refresh_token,
            id_token,
            scope: Some(context.scopes.join(" ")),
        })
    }

    #[instrument(skip(self, client_secret))]
    async fn validate_client_credentials(
        &self,
        tenant_id: Uuid,
        client_id: String,
        client_secret: String,
        scope: Option<String>,
    ) -> Result<MintingContext, ServiceError> {
        debug!("Validating client credentials for client_id: {}", client_id);
        let client = self
            .client_service
            .authenticate_client_by_name(tenant_id, &client_id, &client_secret)
            .await?;

        debug!(
            "Client authentication successful for client_id: {}",
            client_id
        );

        if !client
            .grant_types
            .contains(&"client_credentials".to_string())
        {
            debug!(
                "Client {} does not have client_credentials grant type",
                client_id
            );
            return Err(ServiceError::Validation(
                "Unauthorized grant type for client".into(),
            ));
        }

        debug!(
            "Client {} is authorized for client_credentials grant type",
            client_id
        );

        let scopes = if let Some(requested_scope) = scope {
            let requested_scopes: Vec<String> = requested_scope
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            if !requested_scopes
                .iter()
                .all(|s| client.allowed_scopes.contains(s))
            {
                debug!(
                    "Client {} requested invalid scopes: {:?}. Allowed scopes: {:?}",
                    client_id, requested_scopes, client.allowed_scopes
                );
                return Err(ServiceError::Validation("Invalid scopes requested".into()));
            }
            requested_scopes
        } else {
            client.allowed_scopes.clone() // Default to all client scopes if none requested
        };
        debug!("Client {} requested scopes: {:?}", client_id, scopes);

        Ok(MintingContext {
            tenant_id,
            subject: client.name.clone(),
            client,
            scopes,
            nonce: None,
            identity_id: None,
            refresh_token_family_id: None,
            // No user authenticated, so there is nothing for `amr`/`acr` to
            // describe. RFC 9068 §5 wants `sub` to be the client here, which
            // `subject` above already is.
            auth: None,
            // No identity: `client_credentials` never yields an ID token.
            email: None,
            email_verified: false,
            preferred_username: None,
            name: None,
        })
    }

    #[instrument(skip(self, client_secret, code_verifier))]
    async fn validate_authorization_code(
        &self,
        tenant_id: Uuid,
        client_id: String,
        client_secret: Option<String>,
        code: String,
        redirect_uri: Option<String>,
        code_verifier: String,
        config: &AuthorizationConfiguration,
    ) -> Result<MintingContext, ServiceError> {
        let ctx: Option<AuthCodeContext> = self.token_service.exchange_auth_code(&code).await?;

        let ctx = ctx.ok_or_else(|| {
            debug!("Auth code not found or already consumed");
            ServiceError::InvalidAuthCode
        })?;

        if ctx.tenant_id != tenant_id {
            debug!(
                "Auth code tenant mismatch: expected {}, got {}",
                tenant_id, ctx.tenant_id
            );
            return Err(ServiceError::InvalidAuthCode);
        }

        // Resolve client name → UUID for comparison with stored auth code context
        let client = if let Some(secret) = client_secret {
            self.client_service
                .authenticate_client_by_name(tenant_id, &client_id, &secret)
                .await?
        } else {
            self.client_service
                .get_active_client_by_name(tenant_id, &client_id)
                .await?
        };

        if ctx.client_id != client.id {
            debug!(
                "Auth code client mismatch: expected {}, got {}",
                ctx.client_id, client.id
            );
            return Err(ServiceError::InvalidAuthCode);
        }

        // Check if auth code is still valid (within TTL window)
        let age = time::OffsetDateTime::now_utc() - ctx.created_at;
        if age > time::Duration::seconds(config.auth_code_ttl_seconds as i64) {
            debug!(
                "Auth code expired: age {}s, max {}s",
                age.whole_seconds(),
                config.auth_code_ttl_seconds
            );
            return Err(ServiceError::InvalidAuthCode);
        }

        if let Some(ref uri) = redirect_uri {
            if uri != &ctx.redirect_uri {
                debug!("Redirect URI mismatch on token exchange");
                return Err(ServiceError::RedirectUriMismatch);
            }
        }

        if !client
            .grant_types
            .contains(&"authorization_code".to_string())
        {
            debug!(
                "Client {} does not have authorization_code grant type",
                client_id
            );
            return Err(ServiceError::Validation(
                "Unauthorized grant type for client".into(),
            ));
        }

        // Validate code verifier format
        if code_verifier.len() < 43 || code_verifier.len() > 128 {
            debug!("Invalid code verifier length: {}", code_verifier.len());
            return Err(ServiceError::InvalidAuthCode);
        }
        if !code_verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
        {
            debug!("Invalid code verifier format");
            return Err(ServiceError::InvalidAuthCode);
        }

        // Validate PKCE
        match ctx.pkce_code_challenge_method.as_str() {
            "S256" => {
                let computed_challenge = self.compute_s256_challenge(&code_verifier);
                if computed_challenge != ctx.pkce_code_challenge {
                    error!("PKCE S256 verification failed for client {}", client_id);
                    return Err(ServiceError::InvalidAuthCode);
                }
            }
            "plain" => {
                if !config.allow_plain_pkce {
                    error!(
                        "Plain PKCE not allowed for tenant {} client {}",
                        tenant_id, client_id
                    );
                    return Err(ServiceError::InvalidAuthCode);
                }
                if code_verifier != ctx.pkce_code_challenge {
                    error!("PKCE plain verification failed for client {}", client_id);
                    return Err(ServiceError::InvalidAuthCode);
                }
            }
            _ => {
                error!(
                    "Unsupported PKCE method: {} for client {}",
                    ctx.pkce_code_challenge_method, client_id
                );
                return Err(ServiceError::InvalidAuthCode);
            }
        }

        // Fetch the identity
        let identity = self
            .identity_service
            .get_identity(client.pool_id, ctx.identity_id)
            .await?;
        if identity.status != Status::Active {
            return Err(ServiceError::InvalidCredentials);
        }

        let scopes = self
            .permitted_scopes(tenant_id, identity.id, ctx.scopes, config)
            .await?;

        Ok(MintingContext {
            tenant_id,
            subject: identity.id.to_string(),
            scopes,
            nonce: ctx.nonce,
            identity_id: Some(identity.id),
            refresh_token_family_id: None,
            auth: ctx
                .auth_time
                .map(|at| AuthenticationContext::new(ctx.amr.clone(), at)),
            email: identity.email.clone(),
            email_verified: identity.email_verified,
            preferred_username: Some(identity.username.clone()),
            name: oidc_display_name(&identity.first_name, &identity.last_name),
            client,
        })
    }

    #[instrument(skip(self, client_secret, refresh_token, ctx))]
    async fn validate_refresh_token(
        &self,
        tenant_id: Uuid,
        client_id: String,
        client_secret: Option<String>,
        refresh_token: String,
        config: &AuthorizationConfiguration,
        ctx: &AuditContext,
    ) -> Result<MintingContext, ServiceError> {
        let token_hash = TokenService::<TR, KR, KP>::hash_token(&refresh_token);

        let record = self
            .token_service
            .get_refresh_token(tenant_id, &token_hash)
            .await?
            .ok_or_else(|| {
                debug!("Refresh token not found");
                ServiceError::InvalidCredentials
            })?;

        // Resolve client name → UUID for comparison with stored record
        let client = if let Some(secret) = client_secret {
            self.client_service
                .authenticate_client_by_name(tenant_id, &client_id, &secret)
                .await?
        } else {
            self.client_service
                .get_active_client_by_name(tenant_id, &client_id)
                .await?
        };

        if record.client_id != client.id {
            debug!("Refresh token client mismatch");
            // Detect reuse of a stolen token: revoke the whole family
            self.token_service
                .revoke_token_family(record.family_id)
                .await?;
            self.audit.record(
                AuditEvent::new(
                    tenant_id,
                    AuditEventType::TokenRefreshReuseDetected,
                    AuditActor::Identity(record.identity_id),
                    AuditOutcome::Denied,
                    ctx.clone(),
                )
                .with_target("client", client.name.clone())
                .with_details(json!({"family_id": record.family_id, "reason": "client_mismatch"})),
            );
            return Err(ServiceError::InvalidCredentials);
        }

        if record.revoked_at.is_some() {
            debug!("Refresh token has been revoked — revoking family");
            self.token_service
                .revoke_token_family(record.family_id)
                .await?;
            self.audit.record(
                AuditEvent::new(
                    tenant_id,
                    AuditEventType::TokenRefreshReuseDetected,
                    AuditActor::Identity(record.identity_id),
                    AuditOutcome::Denied,
                    ctx.clone(),
                )
                .with_target("client", client.name.clone())
                .with_details(
                    json!({"family_id": record.family_id, "reason": "revoked_token_reused"}),
                ),
            );
            return Err(ServiceError::InvalidCredentials);
        }

        if record.expires_at < time::OffsetDateTime::now_utc() {
            debug!("Refresh token expired");
            return Err(ServiceError::InvalidCredentials);
        }

        if !client.grant_types.contains(&"refresh_token".to_string()) {
            debug!(
                "Client {} does not have refresh_token grant type",
                client_id
            );
            return Err(ServiceError::Validation(
                "Unauthorized grant type for client".into(),
            ));
        }

        // Rotate: revoke the consumed token before issuing the new one
        self.token_service.revoke_refresh_token(record.id).await?;

        let identity = self
            .identity_service
            .get_identity(client.pool_id, record.identity_id)
            .await?;
        if identity.status != Status::Active {
            self.token_service
                .revoke_token_family(record.family_id)
                .await?;
            return Err(ServiceError::InvalidCredentials);
        }

        let scopes = self
            .permitted_scopes(tenant_id, identity.id, record.scopes, config)
            .await?;

        Ok(MintingContext {
            tenant_id,
            subject: identity.id.to_string(),
            scopes,
            // No original nonce survives rotation; a refreshed ID token carries
            // none rather than a stale one.
            nonce: None,
            identity_id: Some(identity.id),
            refresh_token_family_id: Some(record.family_id),
            // Read back rather than re-derived: these describe the login this
            // family began with, which no longer exists to be asked.
            auth: record
                .auth_time
                .map(|at| AuthenticationContext::new(record.amr.clone(), at)),
            email: identity.email.clone(),
            email_verified: identity.email_verified,
            preferred_username: Some(identity.username.clone()),
            name: oidc_display_name(&identity.first_name, &identity.last_name),
            client,
        })
    }

    fn compute_s256_challenge(&self, verifier: &str) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }
}
