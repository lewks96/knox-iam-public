import { apiRequest, formPost } from "../api-client";

/// The token endpoint is at the root of the tenant host, not under API_BASE:
/// the issuer is `https://{tenant}.{base}` with no path, so OIDC endpoints must
/// resolve directly beneath it.
const OAUTH2_TOKEN_URL = "/oauth2/token";

/**
 * A verification option Knox offers at the MFA step. Mirrors `MfaOption` in
 * `knox-common`, which serialises lowercase. It is a superset of the
 * *enrollable* methods: backup codes can be redeemed but not enrolled in.
 */
export type MfaOption = "totp" | "webauthn" | "sms" | "backup_code";

/**
 * Either a completed login (`sso`) or an MFA challenge (`mfa_token` + the
 * `methods` the identity can verify with). Knox returns both shapes as 200 —
 * the challenge is not an error — so the caller discriminates on `mfa_token`.
 */
export interface AuthenticateResponse {
  sso?: string;
  mfa_token?: string;
  user_id?: string;
  methods?: MfaOption[];
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

/**
 * Authenticate with username/password. Knox sets httpOnly ssotoken cookie.
 *
 * `client_id` is required: it tells Knox which identity pool to check the
 * credentials against. The console's management client is bound to the tenant's
 * staff pool, so a tenant's end users are not merely refused here — their
 * credentials are checked against a directory they are not in.
 */
export async function authenticate(
  tenantId: string,
  username: string,
  password: string,
  clientId: string = process.env.NEXT_PUBLIC_MANAGEMENT_CLIENT_ID!
): Promise<AuthenticateResponse> {
  return apiRequest<AuthenticateResponse>(`/authenticate`, {
    method: "POST",
    body: { username, password, client_id: clientId },
    skipAuth: true,
    // A wrong password is a 401 here, and it is an answer, not a dead session.
    noSessionRedirect: true,
  });
}

/**
 * Complete an MFA login by redeeming the challenge token with a verification
 * code. On success Knox sets the same httpOnly SSO cookie the password path
 * would have set, so the caller resumes exactly as if MFA had not been needed.
 *
 * `client_id` must be the client the challenge was issued for: the MFA token
 * carries the pool the password was checked against, and Knox rejects
 * redeeming it at a client bound to a different pool.
 *
 * The token is single-use and allows a limited number of attempts before
 * lockout, so a failure here is not always retryable — see `MfaChallenge`
 * handling in the login form.
 */
export async function verifyMfa(
  mfaToken: string,
  method: MfaOption,
  code: string,
  clientId: string = process.env.NEXT_PUBLIC_MANAGEMENT_CLIENT_ID!
): Promise<AuthenticateResponse> {
  return apiRequest<AuthenticateResponse>(`/authenticate/mfa`, {
    method: "POST",
    body: { mfa_token: mfaToken, method, code, client_id: clientId },
    skipAuth: true,
    // A wrong code is a 401 here; redirecting would destroy the challenge.
    noSessionRedirect: true,
  });
}

/**
 * Exchange a PKCE authorization code for tokens.
 */
export async function exchangeCodeForTokens(
  tenantId: string,
  code: string,
  codeVerifier: string,
  redirectUri: string
): Promise<TokenResponse> {
  const clientId = process.env.NEXT_PUBLIC_MANAGEMENT_CLIENT_ID!;

  return formPost<TokenResponse>(OAUTH2_TOKEN_URL, {
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });
}

/**
 * Refresh the access token using a refresh token.
 */
export async function refreshTokens(
  tenantId: string,
  refreshToken: string
): Promise<TokenResponse> {
  const clientId = process.env.NEXT_PUBLIC_MANAGEMENT_CLIENT_ID!;

  return formPost<TokenResponse>(OAUTH2_TOKEN_URL, {
    grant_type: "refresh_token",
    client_id: clientId,
    refresh_token: refreshToken,
  });
}
