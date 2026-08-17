"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { createPool, type IdentityPool } from "@/lib/api/pools";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";

/** Server-side rule: lowercase alphanumeric and hyphens, and immutable once set. */
function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

interface CreatePoolDialogProps {
  open: boolean;
  onClose: () => void;
  /** Receives the new pool, e.g. to select it immediately. */
  onCreated?: (pool: IdentityPool) => void;
}

/**
 * Creates a customer directory. Staff pools cannot be made here — the tenant's
 * one is provisioned with the tenant and capped at one by the schema — so every
 * pool this produces holds end users.
 */
export function CreatePoolDialog({ open, onClose, onCreated }: CreatePoolDialogProps) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  const effectiveSlug = slugTouched ? slug : slugify(name);

  function reset() {
    setName("");
    setSlug("");
    setSlugTouched(false);
    setDescription("");
    setError(null);
  }

  const mut = useMutation({
    mutationFn: () =>
      createPool({
        slug: effectiveSlug,
        name,
        description: description || undefined,
      }),
    onSuccess: (pool) => {
      qc.invalidateQueries({ queryKey: ["pools"] });
      toast.success(`Directory “${pool.name}” created`);
      onCreated?.(pool);
      onClose();
      reset();
    },
    onError: (err: Error) => setError(err.message),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New customer directory</DialogTitle>
          <DialogDescription>
            A directory holds the end users of one of your applications. Sign-in
            is scoped to it, so the same email can exist in two directories
            without collision.
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            mut.mutate();
          }}
          className="space-y-3"
        >
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <div className="space-y-1">
            <Label htmlFor="pool-name">Name *</Label>
            <Input
              id="pool-name"
              required
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Storefront users"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="pool-slug">Slug *</Label>
            <Input
              id="pool-slug"
              required
              pattern="[a-z0-9\-]+"
              value={effectiveSlug}
              onChange={(e) => {
                setSlugTouched(true);
                setSlug(e.target.value);
              }}
              placeholder="storefront-users"
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">
              Lowercase letters, numbers and hyphens. Cannot be changed later.
            </p>
          </div>
          <div className="space-y-1">
            <Label htmlFor="pool-description">Description</Label>
            <Input
              id="pool-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional"
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={mut.isPending || !effectiveSlug}>
              {mut.isPending ? "Creating…" : "Create directory"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
