"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ShieldCheck,
  ShieldOff,
  Smartphone,
  RefreshCw,
  Trash2,
} from "lucide-react";
import {
  listMfaMethods,
  startTotpEnrollment,
  removeMfaMethod,
  regenerateBackupCodes,
  type MfaMethodSummary,
  type StartTotpEnrollmentResponse,
} from "@/lib/api/mfa";
import { BackupCodes } from "@/components/mfa/backup-codes";
import { TotpEnrollmentPanel } from "@/components/mfa/totp-enrollment-panel";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

function formatDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

export function SecurityClient() {
  const queryClient = useQueryClient();

  const [enrollment, setEnrollment] =
    useState<StartTotpEnrollmentResponse | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [removing, setRemoving] = useState<MfaMethodSummary | null>(null);

  const { data: methods, isLoading } = useQuery({
    queryKey: ["mfa-methods"],
    queryFn: listMfaMethods,
  });

  const totp = methods?.find((m) => m.method === "totp");
  const isEnrolled = Boolean(totp?.verified_at);
  // Started but never confirmed. It grants nothing, yet holds the one-TOTP
  // unique index — so enrolling again would 409 until it is cleared.
  const isPending = Boolean(totp && !totp.verified_at);

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ["mfa-methods"] });
  }

  const startMutation = useMutation({
    // An abandoned attempt needs no cleanup: create_method drops any unverified
    // enrollment of the same kind before inserting, precisely so enrollment can
    // be restarted. Deleting it here first would be redundant, and would fail
    // outright whenever our cached list is stale and the row is already gone.
    mutationFn: startTotpEnrollment,
    onSuccess: (data) => {
      setEnrollment(data);
      invalidate();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Could not start setup"),
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => removeMfaMethod(id),
    onSuccess: () => {
      setRemoving(null);
      invalidate();
      toast.success("Two-factor authentication removed");
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Could not remove method"),
  });

  const regenerateMutation = useMutation({
    mutationFn: regenerateBackupCodes,
    onSuccess: (codes) => {
      setBackupCodes(codes);
      invalidate();
      toast.success("New backup codes generated");
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Could not regenerate codes"),
  });

  if (isLoading) {
    return (
      <div className="rounded-xl border bg-card p-6 text-sm text-muted-foreground">
        Loading…
      </div>
    );
  }

  return (
    <>
      <div className="rounded-xl border bg-card">
        <div className="flex items-start justify-between gap-4 p-6">
          <div className="flex gap-3">
            <div
              className={
                "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg " +
                (isEnrolled
                  ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  : "bg-muted text-muted-foreground")
              }
            >
              {isEnrolled ? (
                <ShieldCheck className="h-5 w-5" />
              ) : (
                <ShieldOff className="h-5 w-5" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold">Authenticator app</h2>
                {isEnrolled ? (
                  <Badge variant="secondary">Enabled</Badge>
                ) : isPending ? (
                  <Badge variant="outline">Setup incomplete</Badge>
                ) : (
                  <Badge variant="outline">Not enabled</Badge>
                )}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                Time-based codes from an app like 1Password, Authy, or Google
                Authenticator.
              </p>
              {isEnrolled && totp && (
                <dl className="mt-3 space-y-1 text-xs text-muted-foreground">
                  <div className="flex gap-2">
                    <dt>Added</dt>
                    <dd className="text-foreground/80">
                      {formatDate(totp.created_at)}
                    </dd>
                  </div>
                  <div className="flex gap-2">
                    <dt>Last used</dt>
                    <dd className="text-foreground/80">
                      {formatDate(totp.last_used_at)}
                    </dd>
                  </div>
                </dl>
              )}
            </div>
          </div>

          {isEnrolled && totp ? (
            <Button
              variant="outline"
              size="sm"
              className="gap-2 shrink-0"
              onClick={() => setRemoving(totp)}
            >
              <Trash2 className="h-4 w-4" />
              Remove
            </Button>
          ) : (
            <Button
              size="sm"
              className="gap-2 shrink-0"
              onClick={() => startMutation.mutate()}
              disabled={startMutation.isPending}
            >
              <Smartphone className="h-4 w-4" />
              {startMutation.isPending
                ? "Starting…"
                : isPending
                  ? "Start over"
                  : "Set up"}
            </Button>
          )}
        </div>

        {isEnrolled && (
          <>
            <Separator />
            <div className="flex items-start justify-between gap-4 p-6">
              <div>
                <h3 className="text-sm font-semibold">Backup codes</h3>
                <p className="mt-1 text-xs text-muted-foreground">
                  Single-use codes for when you cannot reach your authenticator.
                  Generating a new set invalidates the old one.
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="gap-2 shrink-0"
                onClick={() => regenerateMutation.mutate()}
                disabled={regenerateMutation.isPending}
              >
                <RefreshCw className="h-4 w-4" />
                {regenerateMutation.isPending ? "Generating…" : "Regenerate"}
              </Button>
            </div>
          </>
        )}
      </div>

      {/* ── Enrollment ─────────────────────────────────────────────────── */}
      <Dialog
        open={Boolean(enrollment)}
        onOpenChange={(open) => {
          if (!open) {
            // The unverified method stays behind deliberately; "Start over"
            // clears it. Silently deleting here would race the confirm call.
            setEnrollment(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Set up authenticator app</DialogTitle>
            <DialogDescription>
              Scan the code with your authenticator, then enter the 6-digit code
              it shows to confirm.
            </DialogDescription>
          </DialogHeader>

          {enrollment && (
            <TotpEnrollmentPanel
              enrollment={enrollment}
              onConfirmed={(codes) => {
                setEnrollment(null);
                setBackupCodes(codes);
                invalidate();
                toast.success("Two-factor authentication enabled");
              }}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* ── Backup codes (shown once) ──────────────────────────────────── */}
      <Dialog open={Boolean(backupCodes)} onOpenChange={() => {}}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Your backup codes</DialogTitle>
          </DialogHeader>
          {backupCodes && (
            <BackupCodes
              codes={backupCodes}
              onDone={() => setBackupCodes(null)}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* ── Remove confirmation ────────────────────────────────────────── */}
      <Dialog
        open={Boolean(removing)}
        onOpenChange={(open) => !open && setRemoving(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove two-factor authentication?</DialogTitle>
            <DialogDescription>
              Your account will be protected by password alone, and your backup
              codes will be discarded along with it.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRemoving(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => removing && removeMutation.mutate(removing.id)}
              disabled={removeMutation.isPending}
            >
              {removeMutation.isPending ? "Removing…" : "Remove"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
