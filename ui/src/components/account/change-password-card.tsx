"use client";

import { useState } from "react";
import { KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { MfaChallenge } from "@/components/auth/mfa-challenge";
import { changePassword } from "@/lib/api/password";
import { useAuthStore } from "@/lib/auth-store";
import { type MfaOption } from "@/lib/api/auth";

type Phase = { kind: "form" } | { kind: "mfa"; methods: MfaOption[] };

const MIN_LENGTH = 8;

/**
 * Self-service password change. Mirrors the MFA card's look. When the account
 * has a verified second factor the same `<MfaChallenge>` used at login is shown
 * inline in the dialog.
 *
 * A successful change revokes every session, this one included, so on success
 * the store is cleared and the user is sent to sign in with an explicit reason —
 * rather than letting the next background request 401 into the generic
 * "session expired" path.
 */
export function ChangePasswordCard() {
  const [open, setOpen] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [phase, setPhase] = useState<Phase>({ kind: "form" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setCurrent("");
    setNext("");
    setConfirm("");
    setPhase({ kind: "form" });
    setLoading(false);
    setError(null);
  }

  function onSuccess() {
    // Session is gone server-side; make the sign-out deliberate.
    useAuthStore.getState().clearTokens();
    window.location.href = "/login?reason=password_changed";
  }

  function validate(): string | null {
    if (next.length < MIN_LENGTH) {
      return `New password must be at least ${MIN_LENGTH} characters.`;
    }
    if (next !== confirm) return "New passwords do not match.";
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
      const result = await changePassword(current, next);
      if (result.mfa_required) {
        setPhase({ kind: "mfa", methods: result.methods ?? [] });
        setLoading(false);
        return;
      }
      onSuccess();
    } catch (err: unknown) {
      setLoading(false);
      setError(err instanceof Error ? err.message : "Could not change password.");
    }
  }

  return (
    <div className="rounded-xl border bg-card">
      <div className="flex items-start justify-between gap-4 p-6">
        <div className="flex gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
            <KeyRound className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold">Password</h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Change the password you use to sign in. You&apos;ll be signed out
              of every device afterwards.
            </p>
          </div>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="gap-2 shrink-0"
          onClick={() => setOpen(true)}
        >
          Change
        </Button>
      </div>

      <Dialog
        open={open}
        onOpenChange={(o) => {
          setOpen(o);
          if (!o) reset();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change password</DialogTitle>
            <DialogDescription>
              {phase.kind === "mfa"
                ? "Enter a verification code to confirm this change."
                : "Enter your current password and choose a new one."}
            </DialogDescription>
          </DialogHeader>

          {phase.kind === "mfa" ? (
            <MfaChallenge
              offeredMethods={phase.methods}
              verify={(method, code) =>
                changePassword(current, next, { method, code }).then(() => {})
              }
              onVerified={onSuccess}
              onDead={(message) => {
                setPhase({ kind: "form" });
                setError(message);
              }}
              onCancel={() => {
                setPhase({ kind: "form" });
                setError(null);
              }}
              verifyLabel="Change password"
            />
          ) : (
            <form onSubmit={handleSubmit} className="space-y-3">
              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              <div className="space-y-1">
                <Label htmlFor="cp-current">Current password</Label>
                <Input
                  id="cp-current"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  disabled={loading}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="cp-new">New password</Label>
                <Input
                  id="cp-new"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={MIN_LENGTH}
                  value={next}
                  onChange={(e) => setNext(e.target.value)}
                  placeholder="Min. 8 characters"
                  disabled={loading}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="cp-confirm">Confirm new password</Label>
                <Input
                  id="cp-confirm"
                  type="password"
                  autoComplete="new-password"
                  required
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  disabled={loading}
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? "Saving…" : "Change password"}
              </Button>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
