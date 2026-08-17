import { apiRequest } from "../api-client";

/**
 * An enrollable factor. Narrower than `MfaOption` in auth.ts, which also
 * carries `backup_code` — those are redeemable at login but are issued
 * alongside a factor rather than enrolled in on their own.
 */
export type MfaMethodKind = "totp" | "webauthn" | "sms";

export interface MfaMethodSummary {
  id: string;
  method: MfaMethodKind;
  /**
   * Null while an enrollment is started but not yet confirmed. Such a method
   * grants nothing at login. Starting a fresh enrollment replaces it — only a
   * *verified* method of the same kind blocks re-enrollment (409).
   */
  verified_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface StartTotpEnrollmentResponse {
  method_id: string;
  /** Base32 secret, shown exactly once. Offered for manual entry. */
  secret: string;
  /** otpauth:// provisioning URI, rendered as the QR code. */
  otpauth_uri: string;
}

/**
 * Every endpoint here is self-service: the server reads the identity from the
 * access token's `sub` and never accepts one from the caller, so there is no
 * identity id to pass. They require the `IdentityUpdate` scope, which the
 * built-in `IdentitySelf` role grants.
 */
export async function listMfaMethods(): Promise<MfaMethodSummary[]> {
  return apiRequest<MfaMethodSummary[]>("/mfa/methods");
}

export async function startTotpEnrollment(): Promise<StartTotpEnrollmentResponse> {
  return apiRequest<StartTotpEnrollmentResponse>("/mfa/totp/enroll", {
    method: "POST",
  });
}

/** Returns the backup codes, which are shown once and never retrievable again. */
export async function confirmTotpEnrollment(code: string): Promise<string[]> {
  const res = await apiRequest<{ backup_codes: string[] }>("/mfa/totp/confirm", {
    method: "POST",
    body: { code },
    // A wrong confirmation code is a 401; bouncing to /login would discard the
    // enrollment the user is halfway through.
    noSessionRedirect: true,
  });
  return res.backup_codes;
}

export async function removeMfaMethod(methodId: string): Promise<void> {
  await apiRequest(`/mfa/methods/${methodId}`, { method: "DELETE" });
}

/** Invalidates all previous codes. Returns the new set, again shown once. */
export async function regenerateBackupCodes(): Promise<string[]> {
  const res = await apiRequest<{ backup_codes: string[] }>(
    "/mfa/backup-codes/regenerate",
    { method: "POST" }
  );
  return res.backup_codes;
}
