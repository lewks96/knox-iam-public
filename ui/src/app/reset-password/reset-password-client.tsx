"use client";

import { useState } from "react";
import Link from "next/link";
import { CheckCircle2 } from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { MfaChallenge } from "@/components/auth/mfa-challenge";
import {
  completePasswordReset,
  completePasswordResetMfa,
} from "@/lib/api/password";
import { type MfaOption } from "@/lib/api/auth";

type Phase =
  | { kind: "form" }
  | { kind: "mfa"; mfaToken: string; methods: MfaOption[] }
  | { kind: "done" };

const MIN_LENGTH = 8;

export function ResetPasswordClient({ token }: { token: string | null }) {
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [phase, setPhase] = useState<Phase>({ kind: "form" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // No token means the link was malformed or truncated — there is nothing to
  // redeem, so say so rather than render a form that cannot succeed.
  if (!token) {
    return (
      <div className="space-y-4">
        <Alert variant="destructive">
          <AlertDescription>
            This reset link is invalid. Ask your administrator for a new one.
          </AlertDescription>
        </Alert>
        <Link href="/login" className={buttonVariants({ variant: "outline", className: "w-full" })}>
          Back to sign in
        </Link>
      </div>
    );
  }

  if (phase.kind === "done") {
    return (
      <div className="space-y-4 text-center">
        <div className="flex justify-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="h-5 w-5" />
          </div>
        </div>
        <div>
          <h2 className="text-sm font-semibold">Password updated</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            Your password has been changed and you have been signed out
            everywhere. Sign in with your new password.
          </p>
        </div>
        <Link href="/login" className={buttonVariants({ className: "w-full" })}>
          Sign in
        </Link>
      </div>
    );
  }

  if (phase.kind === "mfa") {
    return (
      <div className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold">Confirm it&apos;s you</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            This account has two-factor authentication. Enter a code to finish
            resetting your password.
          </p>
        </div>
        <MfaChallenge
          offeredMethods={phase.methods}
          verify={(method, code) =>
            completePasswordResetMfa(phase.mfaToken, method, code, newPassword)
          }
          onVerified={() => setPhase({ kind: "done" })}
          onDead={(message) => {
            // The challenge (and the reset token behind it) is spent — a code
            // box would only burn attempts. Send the user back for a new link.
            setPhase({ kind: "form" });
            setError(`${message} Ask your administrator for a new reset link.`);
          }}
          onCancel={() => {
            setPhase({ kind: "form" });
            setError(null);
          }}
          verifyLabel="Reset password"
        />
      </div>
    );
  }

  function validate(): string | null {
    if (newPassword.length < MIN_LENGTH) {
      return `Password must be at least ${MIN_LENGTH} characters.`;
    }
    if (newPassword !== confirm) {
      return "Passwords do not match.";
    }
    return null;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const result = await completePasswordReset(token!, newPassword);
      if (result.mfa_required && result.mfa_token) {
        setPhase({
          kind: "mfa",
          mfaToken: result.mfa_token,
          methods: result.methods ?? [],
        });
        setLoading(false);
        return;
      }
      setPhase({ kind: "done" });
    } catch (err: unknown) {
      setLoading(false);
      setError(
        err instanceof Error
          ? err.message
          : "This reset link is invalid or has expired."
      );
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-1">
        <Label htmlFor="new-password">New password</Label>
        <Input
          id="new-password"
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_LENGTH}
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder="Min. 8 characters"
          disabled={loading}
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="confirm-password">Confirm new password</Label>
        <Input
          id="confirm-password"
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder="Re-enter your password"
          disabled={loading}
        />
      </div>

      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? "Saving…" : "Reset password"}
      </Button>
    </form>
  );
}
