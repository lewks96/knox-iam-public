import { apiRequest } from "../api-client";
import { type MfaOption } from "./auth";

/**
 * A `{ method, code }` pair, sent when a flow's second-factor step is required.
 */
export interface MfaVerification {
  method: MfaOption;
  code: string;
}

/**
 * The two shapes a password mutation can answer with. `mfa_required: true`
 * means the password was *not* changed — resubmit with a code. The `methods`
 * list is present only in that case.
 */
export interface PasswordMutationResult {
  mfa_required: boolean;
  methods?: MfaOption[];
}

/**
 * Change your own password. Authenticated; the server reads the identity from
 * the access token. When the account has a verified second factor and `mfa` is
 * omitted, the server answers `{ mfa_required: true, methods }` and nothing
 * changes — resubmit with a code.
 *
 * On success every session is revoked, including this one, so the caller must
 * send the user back to sign in rather than treat the following 401 as an
 * error — hence `noSessionRedirect`, which keeps that 401 out of the automatic
 * bounce so the caller can show a deliberate message.
 */
export async function changePassword(
  currentPassword: string,
  newPassword: string,
  mfa?: MfaVerification
): Promise<PasswordMutationResult> {
  return apiRequest<PasswordMutationResult>("/identity/me/password", {
    method: "POST",
    body: {
      current_password: currentPassword,
      new_password: newPassword,
      mfa,
    },
    // A wrong current password or MFA code is a 401/4xx answer, not a dead
    // session; and success revokes the session deliberately.
    noSessionRedirect: true,
  });
}

export interface AdminResetLinkResponse {
  reset_url: string;
  /** RFC 3339 timestamp. */
  expires_at: string;
}

/**
 * Issue a one-time reset link for another identity (admin action). Returns the
 * link for the administrator to deliver out of band; no password is ever
 * exposed, and nothing changes until the link is redeemed.
 */
export async function adminCreateResetLink(
  identityId: string,
  poolId?: string
): Promise<AdminResetLinkResponse> {
  return apiRequest<AdminResetLinkResponse>(
    `/identity/${identityId}/password/reset`,
    { method: "POST", params: { pool_id: poolId } }
  );
}

/**
 * Clear an identity's MFA enrolment (admin break-glass). Separate from a
 * password reset on purpose, so recovering an account never silently strips its
 * second factor.
 */
export async function adminResetMfa(
  identityId: string,
  poolId?: string
): Promise<void> {
  await apiRequest(`/identity/${identityId}/mfa`, {
    method: "DELETE",
    params: { pool_id: poolId },
  });
}

/**
 * Redeem a reset link. The endpoints below are unauthenticated (the user has no
 * session — that is the point), so they skip the Authorization header and never
 * treat a 401 as an expired session: a 401 here means a bad token or code.
 */
export async function requestPasswordReset(
  username: string,
  clientId: string = process.env.NEXT_PUBLIC_MANAGEMENT_CLIENT_ID!
): Promise<void> {
  await apiRequest("/authenticate/password/forgot", {
    method: "POST",
    body: { username, client_id: clientId },
    skipAuth: true,
    noSessionRedirect: true,
  });
}

/**
 * Step one of redeeming a reset link. When the account has a second factor the
 * password is left untouched and a challenge is returned; otherwise the password
 * is set outright (`mfa_required: false`).
 */
export async function completePasswordReset(
  token: string,
  newPassword: string
): Promise<PasswordMutationResult & { mfa_token?: string }> {
  return apiRequest<PasswordMutationResult & { mfa_token?: string }>(
    "/authenticate/password/reset",
    {
      method: "POST",
      body: { token, new_password: newPassword },
      skipAuth: true,
      noSessionRedirect: true,
    }
  );
}

/**
 * Step two: the second factor for a reset. The new password is resubmitted
 * here, so nothing password-shaped is stored between the two steps.
 */
export async function completePasswordResetMfa(
  mfaToken: string,
  method: MfaOption,
  code: string,
  newPassword: string
): Promise<void> {
  await apiRequest("/authenticate/password/reset/mfa", {
    method: "POST",
    body: {
      mfa_token: mfaToken,
      method,
      code,
      new_password: newPassword,
    },
    skipAuth: true,
    noSessionRedirect: true,
  });
}
