"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import {
  confirmTotpEnrollment,
  type StartTotpEnrollmentResponse,
} from "@/lib/api/mfa";
import { ApiError } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";

interface TotpEnrollmentPanelProps {
  enrollment: StartTotpEnrollmentResponse;
  /** Receives the backup codes, which are returned exactly once. */
  onConfirmed: (backupCodes: string[]) => void;
}

/**
 * The QR-plus-confirm half of TOTP enrollment, shared by the account security
 * dialog and the first-run setup screen so the two cannot drift.
 */
export function TotpEnrollmentPanel({
  enrollment,
  onConfirmed,
}: TotpEnrollmentPanelProps) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [secretShown, setSecretShown] = useState(false);

  const confirmMutation = useMutation({
    mutationFn: (c: string) => confirmTotpEnrollment(c),
    onSuccess: (codes) => {
      setCode("");
      onConfirmed(codes);
    },
    onError: (e: unknown) => {
      setCode("");
      setError(
        e instanceof ApiError && e.status === 401
          ? "That code was not accepted. Codes rotate every 30 seconds — try the current one."
          : e instanceof Error
            ? e.message
            : "Could not confirm the code"
      );
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex justify-center rounded-lg bg-white p-4">
        <QRCodeSVG value={enrollment.otpauth_uri} size={176} />
      </div>

      <div className="text-center">
        {secretShown ? (
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">
              Enter this key manually:
            </p>
            <code className="block break-all rounded bg-muted px-2 py-1.5 font-mono text-xs">
              {enrollment.secret}
            </code>
          </div>
        ) : (
          <button
            type="button"
            className="text-xs text-muted-foreground underline-offset-4 hover:underline"
            onClick={() => setSecretShown(true)}
          >
            Can&apos;t scan? Enter the key manually
          </button>
        )}
      </div>

      <Separator />

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          confirmMutation.mutate(code);
        }}
        className="space-y-3"
      >
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <div className="space-y-1">
          <Label htmlFor="totp-code">Verification code</Label>
          <Input
            id="totp-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoFocus
            required
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            disabled={confirmMutation.isPending}
          />
        </div>
        <Button type="submit" className="w-full" disabled={confirmMutation.isPending}>
          {confirmMutation.isPending ? "Verifying…" : "Confirm"}
        </Button>
      </form>
    </div>
  );
}
