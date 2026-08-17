"use client";

import { useState } from "react";
import { AlertTriangle, CheckCheck, Copy, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";

/**
 * Backup codes exist only in the response that produced them — the server
 * stores hashes, so there is no endpoint that can show them again. Everything
 * here is built around that: the user must acknowledge before moving on.
 */
export function BackupCodes({
  codes,
  onDone,
  doneLabel = "Done",
}: {
  codes: string[];
  onDone: () => void;
  doneLabel?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);

  const asText = codes.join("\n");

  function copy() {
    navigator.clipboard.writeText(asText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function download() {
    const blob = new Blob(
      [`Knox IAM backup codes\n\nEach code works once.\n\n${asText}\n`],
      { type: "text/plain" }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "knox-backup-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-4">
      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          Save these now — they are shown once and cannot be retrieved again.
          Each code works a single time, and they are your way back in if you
          lose your authenticator.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-2 gap-2 rounded-lg border bg-muted/40 p-4 font-mono text-sm">
        {codes.map((c) => (
          <span key={c} className="tracking-wider">
            {c}
          </span>
        ))}
      </div>

      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={copy} className="gap-2">
          {copied ? (
            <CheckCheck className="h-4 w-4" />
          ) : (
            <Copy className="h-4 w-4" />
          )}
          {copied ? "Copied" : "Copy"}
        </Button>
        <Button variant="outline" size="sm" onClick={download} className="gap-2">
          <Download className="h-4 w-4" />
          Download
        </Button>
      </div>

      <Separator />

      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={acknowledged}
          onChange={(e) => setAcknowledged(e.target.checked)}
        />
        <span>I have saved these codes somewhere safe.</span>
      </label>

      <Button onClick={onDone} disabled={!acknowledged} className="w-full">
        {doneLabel}
      </Button>
    </div>
  );
}
