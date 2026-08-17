"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Copy, Check } from "lucide-react";
import {
  createIdentity,
  updateIdentity,
  deleteIdentity,
  type Identity,
  type CreateIdentityRequest,
  type UpdateIdentityRequest,
} from "@/lib/api/identity";
import {
  adminCreateResetLink,
  adminResetMfa,
  type AdminResetLinkResponse,
} from "@/lib/api/password";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { RolePicker } from "./role-picker";

// ── Create Identity Dialog ────────────────────────────────────────────

interface CreateIdentityDialogProps {
  tenantId: string;
  open: boolean;
  onClose: () => void;
  /**
   * Directory to create in. Omitting it means the caller's own pool — the staff
   * directory for a console session — so customer screens must always pass one.
   */
  poolId?: string;
  /**
   * Offer role assignment. Only true for administrators: roles carry console
   * permissions, and an end user has no console to use them in.
   */
  withRoles?: boolean;
  title?: string;
  description?: string;
}

export function CreateIdentityDialog({
  tenantId,
  open,
  onClose,
  poolId,
  withRoles = false,
  title = "Create Identity",
  description,
}: CreateIdentityDialogProps) {
  const qc = useQueryClient();
  const [form, setForm] = useState<CreateIdentityRequest>({
    email: "",
    password: "",
    first_name: "",
    last_name: "",
  });
  const [roles, setRoles] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: (data: CreateIdentityRequest) => createIdentity(tenantId, data),
    onSuccess: (identity) => {
      qc.invalidateQueries({ queryKey: ["identities", tenantId] });
      qc.invalidateQueries({ queryKey: ["identity-roles", identity.id] });
      toast.success(
        roles.length > 0
          ? `Identity created with ${roles.length} role${roles.length === 1 ? "" : "s"}`
          : "Identity created"
      );
      onClose();
      setForm({ email: "", password: "", first_name: "", last_name: "" });
      setRoles([]);
    },
    onError: (err: Error) => setError(err.message),
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    mut.mutate({
      email: form.email,
      password: form.password,
      first_name: form.first_name || undefined,
      last_name: form.last_name || undefined,
      pool_id: poolId,
      // Roles are validated server-side before the identity row is written, so
      // a refused grant cannot leave a half-provisioned account behind.
      roles: withRoles && roles.length > 0 ? roles : undefined,
    });
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-h-[90vh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-3">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="c-first">First Name</Label>
              <Input id="c-first" value={form.first_name} onChange={(e) => setForm((f) => ({ ...f, first_name: e.target.value }))} placeholder="Jane" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="c-last">Last Name</Label>
              <Input id="c-last" value={form.last_name} onChange={(e) => setForm((f) => ({ ...f, last_name: e.target.value }))} placeholder="Doe" />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="c-email">Email *</Label>
            <Input id="c-email" type="email" required value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} placeholder="jane@example.com" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="c-pass">Password *</Label>
            <Input id="c-pass" type="password" required minLength={8} value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} placeholder="Min. 8 characters" />
          </div>

          {withRoles && (
            <>
              <Separator />
              <div className="space-y-2">
                <Label>Roles</Label>
                <RolePicker selected={roles} onChange={setRoles} idPrefix="create" />
              </div>
            </>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={mut.isPending}>
              {mut.isPending ? "Creating…" : withRoles && roles.length > 0 ? "Create with roles" : "Create"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ── Edit Identity Dialog ──────────────────────────────────────────────

interface EditIdentityDialogProps {
  tenantId: string;
  identity: Identity;
  open: boolean;
  onClose: () => void;
  /** The directory the identity lives in; omitted for staff. */
  poolId?: string;
}

export function EditIdentityDialog({ tenantId, identity, open, onClose, poolId }: EditIdentityDialogProps) {
  const qc = useQueryClient();
  const [form, setForm] = useState<UpdateIdentityRequest>({
    first_name: identity.first_name ?? "",
    last_name: identity.last_name ?? "",
    email: identity.email,
    status: identity.status.toLowerCase() as "active" | "inactive",
  });
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: (data: UpdateIdentityRequest) =>
      updateIdentity(tenantId, identity.id, data, poolId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["identities", tenantId] });
      qc.invalidateQueries({ queryKey: ["identity", tenantId, identity.id] });
      toast.success("Identity updated");
      onClose();
    },
    onError: (err: Error) => setError(err.message),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Edit Identity</DialogTitle></DialogHeader>
        <form onSubmit={(e) => { e.preventDefault(); setError(null); mut.mutate(form); }} className="space-y-3">
          {error && <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>}
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="e-first">First Name</Label>
              <Input id="e-first" value={form.first_name ?? ""} onChange={(e) => setForm((f) => ({ ...f, first_name: e.target.value }))} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="e-last">Last Name</Label>
              <Input id="e-last" value={form.last_name ?? ""} onChange={(e) => setForm((f) => ({ ...f, last_name: e.target.value }))} />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="e-email">Email</Label>
            <Input id="e-email" type="email" value={form.email ?? ""} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="e-status">Status</Label>
            <Select value={form.status} onValueChange={(v) => setForm((f) => ({ ...f, status: v as "active" | "inactive" }))}>
              <SelectTrigger id="e-status"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={mut.isPending}>{mut.isPending ? "Saving…" : "Save"}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ── Delete Identity Dialog ────────────────────────────────────────────

interface DeleteIdentityDialogProps {
  tenantId: string;
  identity: Identity;
  open: boolean;
  onClose: () => void;
  /** The directory the identity lives in; omitted for staff. */
  poolId?: string;
  /** Called after a successful delete (e.g. navigate away from a detail page). */
  onDeleted?: () => void;
}

export function DeleteIdentityDialog({ tenantId, identity, open, onClose, poolId, onDeleted }: DeleteIdentityDialogProps) {
  const qc = useQueryClient();
  const mut = useMutation({
    mutationFn: () => deleteIdentity(tenantId, identity.id, poolId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["identities", tenantId] });
      toast.success("Identity deleted");
      onClose();
      onDeleted?.();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Delete Identity</DialogTitle></DialogHeader>
        <p className="text-sm text-muted-foreground">
          Are you sure you want to permanently delete{" "}
          <span className="font-medium text-foreground">{identity.email}</span>?
          This action cannot be undone.
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="destructive" onClick={() => mut.mutate()} disabled={mut.isPending}>
            {mut.isPending ? "Deleting…" : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Reset Password Dialog ─────────────────────────────────────────────
//
// Mints a one-time link the administrator delivers out of band. No password is
// ever shown, and nothing changes for the user until they redeem it — at which
// point their own second factor is still demanded.

interface ResetPasswordDialogProps {
  identity: Identity;
  open: boolean;
  onClose: () => void;
  /** The directory the identity lives in; omitted for staff. */
  poolId?: string;
}

export function ResetPasswordDialog({ identity, open, onClose, poolId }: ResetPasswordDialogProps) {
  const [link, setLink] = useState<AdminResetLinkResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () => adminCreateResetLink(identity.id, poolId),
    onSuccess: (data) => {
      setLink(data);
      setError(null);
    },
    onError: (err: Error) => setError(err.message),
  });

  function close() {
    onClose();
    // Clear after close so the link is not left on screen for the next target.
    setLink(null);
    setCopied(false);
    setError(null);
  }

  async function copy() {
    if (!link) return;
    await navigator.clipboard.writeText(link.reset_url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) close(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset password</DialogTitle>
          <DialogDescription>
            Generate a one-time link for{" "}
            <span className="font-medium text-foreground">{identity.email}</span>.
          </DialogDescription>
        </DialogHeader>

        {error && <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>}

        {link ? (
          <div className="space-y-3">
            <div className="flex gap-2">
              <Input readOnly value={link.reset_url} className="font-mono text-xs" onFocus={(e) => e.currentTarget.select()} />
              <Button type="button" variant="outline" size="icon" className="shrink-0" onClick={copy}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Share this securely — it can be used once, sets a new password, and
              expires {new Date(link.expires_at).toLocaleString()}. If the account
              has two-factor authentication, that is still required to complete
              the reset.
            </p>
            <DialogFooter>
              <Button onClick={close}>Done</Button>
            </DialogFooter>
          </div>
        ) : (
          <>
            <p className="text-sm text-muted-foreground">
              The user receives a link to set a new password themselves. You will
              not see or set the password.
            </p>
            <DialogFooter>
              <Button variant="outline" onClick={close}>Cancel</Button>
              <Button onClick={() => mut.mutate()} disabled={mut.isPending}>
                {mut.isPending ? "Generating…" : "Generate link"}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ── Reset MFA Dialog ──────────────────────────────────────────────────
//
// Break-glass for a user locked out of their second factor. Separate from a
// password reset on purpose: recovering an account must never silently strip
// its MFA.

interface ResetMfaDialogProps {
  identity: Identity;
  open: boolean;
  onClose: () => void;
  poolId?: string;
}

export function ResetMfaDialog({ identity, open, onClose, poolId }: ResetMfaDialogProps) {
  const mut = useMutation({
    mutationFn: () => adminResetMfa(identity.id, poolId),
    onSuccess: () => {
      toast.success("Two-factor authentication cleared");
      onClose();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader><DialogTitle>Reset two-factor authentication?</DialogTitle></DialogHeader>
        <p className="text-sm text-muted-foreground">
          This removes every second factor and backup code for{" "}
          <span className="font-medium text-foreground">{identity.email}</span>.
          They will sign in with their password alone until they enrol again. Use
          this only when they have lost access to their authenticator.
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="destructive" onClick={() => mut.mutate()} disabled={mut.isPending}>
            {mut.isPending ? "Clearing…" : "Clear MFA"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
