"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { type MfaOption } from "@/lib/api/auth";
import { ApiError } from "@/lib/api-client";

/**
 * The methods this form can actually complete.
 *
 * Knox advertises whatever the identity has enrolled, but the server only
 * implements TOTP and backup codes — `webauthn` and `sms` are rejected as
 * unsupported. Offering them would render a code box that cannot succeed, so
 * the challenge is filtered to what will work.
 */
export const VERIFIABLE: readonly MfaOption[] = ["totp", "backup_code"];

export const METHOD_LABEL: Record<MfaOption, string> = {
  totp: "Authenticator app",
  backup_code: "Backup code",
  webauthn: "Security key",
  sms: "Text message",
};

/**
 * Whether a failed verification has killed the challenge outright.
 *
 * A wrong code is retryable — the same MFA token survives, bounded by the
 * server's attempt counter. An expired/replayed token or a lockout is not: the
 * token is gone and only a fresh start (a new login, or a new reset link) can
 * mint another. Keeping the code box open in that case would let the user burn
 * attempts against a token that can never succeed.
 */
export function isChallengeDead(err: unknown): boolean {
  if (!(err instanceof ApiError)) return false;
  if (err.status === 429) return true; // MfaTooManyAttempts
  return err.body?.error === "Invalid MFA token";
}

interface MfaChallengeProps {
  /** Methods the server offered; filtered here to the ones we can verify. */
  offeredMethods: MfaOption[];
  /** Performs the verification. Throws `ApiError` on a bad code or dead token. */
  verify: (method: MfaOption, code: string) => Promise<void>;
  /** Called once `verify` resolves. */
  onVerified: () => void;
  /**
   * Called when the challenge can no longer succeed (expired, replayed, or
   * locked out). The caller decides where to send the user — back to the
   * password step, or to a "request a new link" message.
   */
  onDead: (message: string) => void;
  /** Abandon the challenge (e.g. return to the password step). */
  onCancel: () => void;
  /** Verb on the submit button. Defaults to "Verify". */
  verifyLabel?: string;
}

/**
 * The second-factor step, shared by every flow that needs one: login, password
 * reset, and the self-service password change. Owns its own code/method/error
 * state; the caller supplies the verification call and decides what a success
 * or a dead challenge means for its flow.
 */
export function MfaChallenge({
  offeredMethods,
  verify,
  onVerified,
  onDead,
  onCancel,
  verifyLabel = "Verify",
}: MfaChallengeProps) {
  const methods = offeredMethods.filter((m) => VERIFIABLE.includes(m));
  const [method, setMethod] = useState<MfaOption>(methods[0] ?? "totp");
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Enrolled only in a factor this form cannot verify (WebAuthn/SMS). Better to
  // say so than to present a code box that is guaranteed to fail.
  if (methods.length === 0) {
    return (
      <Alert variant="destructive">
        <AlertDescription>
          This account requires a verification method that is not yet supported
          here. Please contact your administrator.
        </AlertDescription>
      </Alert>
    );
  }

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await verify(method, code);
      onVerified();
    } catch (err: unknown) {
      if (isChallengeDead(err)) {
        onDead(
          err instanceof ApiError && err.status === 429
            ? "Too many incorrect codes. Please start again to get a new challenge."
            : "That attempt expired. Please start again."
        );
        return;
      }
      setLoading(false);
      setCode("");
      setError(err instanceof Error ? err.message : "An unexpected error occurred.");
    }
  }

  return (
    <form onSubmit={handleVerify} className="space-y-4">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-1">
        <Label htmlFor="mfa-code">
          {method === "backup_code" ? "Backup code" : "Verification code"}
        </Label>
        <Input
          id="mfa-code"
          // Backup codes are alphanumeric, so this cannot be type="number".
          inputMode={method === "totp" ? "numeric" : "text"}
          autoComplete={method === "totp" ? "one-time-code" : "off"}
          autoFocus
          required
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder={method === "totp" ? "123456" : "ABCD-EFGH-JK"}
          disabled={loading}
        />
        <p className="text-xs text-muted-foreground">
          {method === "totp"
            ? "Enter the 6-digit code from your authenticator app."
            : "Enter one of the backup codes you saved. Each works once."}
        </p>
      </div>

      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? "Verifying…" : verifyLabel}
      </Button>

      <div className="flex items-center justify-between text-xs">
        {methods
          .filter((m) => m !== method)
          .map((m) => (
            <button
              key={m}
              type="button"
              className="text-muted-foreground underline-offset-4 hover:underline"
              onClick={() => {
                setMethod(m);
                setCode("");
                setError(null);
              }}
              disabled={loading}
            >
              Use {METHOD_LABEL[m].toLowerCase()} instead
            </button>
          ))}
        <button
          type="button"
          className="ml-auto text-muted-foreground underline-offset-4 hover:underline"
          onClick={onCancel}
          disabled={loading}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
