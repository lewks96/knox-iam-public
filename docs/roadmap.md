# Roadmap

What is **not** built yet, kept honest so the gaps in the [README](../README.md)'s warning
are specific. The implemented surface is documented in
[`api-reference.md`](api-reference.md) — don't duplicate it here.

Nothing here is a commitment; this is a hobby project and items may sit untouched
indefinitely.

## Identity

- [ ] Query routes (find by email / username / custom attribute)
- [ ] Email verification flow (`identities.email_verified` is only settable by an admin PATCH — there's no verification round-trip)
- [x] Password change (self-service, MFA-aware) — `POST /api/identity/me/password`
- [x] Password reset (admin-issued one-time link) — `POST /api/identity/{id}/password/reset`, redeemed at `POST /api/authenticate/password/reset[/mfa]`
- [x] MFA break-glass (admin clears an identity's second factor) — `DELETE /api/identity/{id}/mfa`
- [ ] Password reset **email delivery** — `POST /api/authenticate/password/forgot` mints the token but only logs the link; it is gated behind `self_service_password_reset` (off by default) until a mailer exists
- [ ] Pagination + filtering on `GET /api/identity`

## Sessions

Password changes now revoke every session via a per-identity epoch
(`revoke_all_sessions`), so these are one call each away:

- [ ] "Sign out of all devices" (self-service) — call `revoke_all_sessions` for the caller
- [ ] Admin force-logout of an identity — call `revoke_all_sessions` for the target
- [ ] Active-session listing / per-device sign-out — needs a `sso_by_identity` index; the epoch alone is all-or-nothing

## OIDC

Grant types on `POST /oauth2/token`:

- [x] Client credentials
- [x] Authorization code + PKCE
- [x] Refresh token (rotating, with family reuse detection)
- [ ] Device code

Endpoints:

- [x] `/.well-known/openid-configuration`
- [x] `/.well-known/jwks.json`
- [ ] `/oauth2/userinfo`
- [ ] `/oauth2/revoke`, `/oauth2/introspect`
- [ ] RP-initiated logout (`post_logout_redirect_uris` is stored but unused)

## Pools

- [ ] Update / delete a customer pool (create, get and list exist)
