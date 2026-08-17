"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Copy, CheckCheck, Trash2, Lock } from "lucide-react";
import {
  listTenants,
  createTenant,
  deleteTenant,
  type Tenant,
  type CreateTenantRequest,
  type CreateTenantResponse,
} from "@/lib/api/tenants";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * The origin a tenant is served on. Mirrors the server's IssuerConfig, so the
 * redirect URI registered here matches the host the tenant actually uses.
 */
function tenantOrigin(slug: string): string {
  const base = process.env.NEXT_PUBLIC_BASE_DOMAIN ?? "lvh.me";
  const { protocol, port } = window.location;
  return `${protocol}//${slug}.${base}${port ? `:${port}` : ""}`;
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

// ── Copy button ──────────────────────────────────────────────────────────────

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy}>
      {copied ? (
        <CheckCheck className="h-3 w-3 text-green-500" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
    </Button>
  );
}

// ── Tenant Created Result Dialog ──────────────────────────────────────────────

interface TenantCreatedDialogProps {
  result: CreateTenantResponse;
  open: boolean;
  onClose: () => void;
}

function TenantCreatedDialog({ result, open, onClose }: TenantCreatedDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Tenant Created</DialogTitle>
          <DialogDescription>
            Save these credentials immediately — secrets will not be shown again.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="rounded-md border p-3 space-y-1">
            <p className="text-xs text-muted-foreground">Tenant ID</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 font-mono text-sm">{result.tenant.id}</code>
              <CopyButton value={result.tenant.id} />
            </div>
          </div>

          <div className="rounded-md border p-3 space-y-1">
            <p className="text-xs text-muted-foreground">Management Client ID</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 font-mono text-sm">{result.admin_client_id}</code>
              <CopyButton value={result.admin_client_id} />
            </div>
          </div>

          <div className="rounded-md border bg-amber-50 dark:bg-amber-950/20 p-3 space-y-1">
            <p className="text-xs font-medium text-amber-700 dark:text-amber-400">
              ⚠ Management Client Secret (shown once)
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all font-mono text-xs">
                {result.admin_client_secret}
              </code>
              <CopyButton value={result.admin_client_secret} />
            </div>
          </div>

          {result.admin_identity && (
            <div className="rounded-md border p-3 space-y-1">
              <p className="text-xs text-muted-foreground">Admin Identity</p>
              <p className="text-sm">
                {result.admin_identity.email}
                {result.admin_identity.first_name &&
                  ` — ${result.admin_identity.first_name} ${result.admin_identity.last_name ?? ""}`}
              </p>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button onClick={onClose}>I have saved these credentials</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Create Tenant Dialog ──────────────────────────────────────────────────────

interface CreateTenantDialogProps {
  open: boolean;
  onClose: () => void;
}

function CreateTenantDialog({ open, onClose }: CreateTenantDialogProps) {
  const qc = useQueryClient();

  const [form, setForm] = useState({
    name: "",
    slug: "",
    description: "",
    create_admin: false,
    admin_email: "",
    admin_password: "",
    admin_first: "",
    admin_last: "",
  });
  const [slugTouched, setSlugTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdResult, setCreatedResult] = useState<CreateTenantResponse | null>(null);

  const mut = useMutation({
    mutationFn: (data: CreateTenantRequest) => createTenant(data),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["tenants"] });
      toast.success(`Tenant "${res.tenant.name}" created`);
      onClose();
      setCreatedResult(res);
      setForm({
        name: "",
        slug: "",
        description: "",
        create_admin: false,
        admin_email: "",
        admin_password: "",
        admin_first: "",
        admin_last: "",
      });
      setSlugTouched(false);
    },
    onError: (err: Error) => setError(err.message),
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const slug = form.slug.trim();

    const body: CreateTenantRequest = {
      name: form.name,
      slug,
      description: form.description || undefined,
      // Derived, not asked for: the management client's redirect URI is
      // The new tenant gets its own host, so its callback lives at the root
      // of that host — not on this one. Same convention as bootstrap. Enables
      // authorization_code so the tenant is immediately signable-into at
      // https://<slug>.<base>/login.
      management_redirect_uris: [`${tenantOrigin(slug)}/callback`],
    };

    if (form.create_admin) {
      body.admin_user = {
        email: form.admin_email,
        password: form.admin_password,
        first_name: form.admin_first || undefined,
        last_name: form.admin_last || undefined,
      };
    }

    mut.mutate(body);
  }

  return (
    <>
      <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Tenant</DialogTitle>
            <DialogDescription>
              Creates a new tenant with a management client and signing key pair.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <div className="space-y-1">
              <Label htmlFor="ct-name">Tenant Name *</Label>
              <Input
                id="ct-name"
                required
                minLength={3}
                maxLength={100}
                value={form.name}
                onChange={(e) => {
                  const name = e.target.value;
                  setForm((f) => ({
                    ...f,
                    name,
                    slug: slugTouched ? f.slug : slugify(name),
                  }));
                }}
                placeholder="Acme Corp"
              />
              <p className="text-xs text-muted-foreground">
                3–100 characters. "admin" and "knox" are reserved.
              </p>
            </div>

            <div className="space-y-1">
              <Label htmlFor="ct-slug">Slug *</Label>
              <Input
                id="ct-slug"
                required
                minLength={3}
                maxLength={63}
                pattern="[a-z0-9]+(-[a-z0-9]+)*"
                value={form.slug}
                onChange={(e) => {
                  setSlugTouched(true);
                  setForm((f) => ({ ...f, slug: e.target.value }));
                }}
                placeholder="acme-corp"
              />
              <p className="text-xs text-muted-foreground">
                URL-safe identifier — lowercase letters, digits, and hyphens. Immutable after creation.
              </p>
            </div>

            <div className="space-y-1">
              <Label htmlFor="ct-desc">Description</Label>
              <Input
                id="ct-desc"
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                placeholder="Optional description"
              />
            </div>

            <div className="space-y-1">
              <Label>Management Redirect URI</Label>
              <p className="rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs text-foreground/80">
                {typeof window !== "undefined" && form.slug
                  ? `${tenantOrigin(form.slug)}/callback`
                  : "https://<slug>.<domain>/callback"}
              </p>
              <p className="text-xs text-muted-foreground">
                Each tenant is served on its own subdomain, so the new tenant
                signs in at its own host.
              </p>
            </div>

            <Separator />

            {/* Admin user */}
            <div className="flex items-center gap-2">
              <Checkbox
                id="ct-admin"
                checked={form.create_admin}
                onCheckedChange={(c) =>
                  setForm((f) => ({ ...f, create_admin: !!c }))
                }
              />
              <Label htmlFor="ct-admin" className="font-normal">
                Create admin user
              </Label>
            </div>

            {form.create_admin && (
              <div className="space-y-3 pl-6">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <Label htmlFor="ct-first">First Name</Label>
                    <Input
                      id="ct-first"
                      value={form.admin_first}
                      onChange={(e) =>
                        setForm((f) => ({ ...f, admin_first: e.target.value }))
                      }
                      placeholder="Admin"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="ct-last">Last Name</Label>
                    <Input
                      id="ct-last"
                      value={form.admin_last}
                      onChange={(e) =>
                        setForm((f) => ({ ...f, admin_last: e.target.value }))
                      }
                      placeholder="User"
                    />
                  </div>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="ct-email">Email *</Label>
                  <Input
                    id="ct-email"
                    type="email"
                    required={form.create_admin}
                    value={form.admin_email}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, admin_email: e.target.value }))
                    }
                    placeholder="admin@acme.com"
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="ct-pass">Password *</Label>
                  <Input
                    id="ct-pass"
                    type="password"
                    required={form.create_admin}
                    minLength={8}
                    value={form.admin_password}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, admin_password: e.target.value }))
                    }
                    placeholder="Min. 8 characters"
                  />
                </div>
              </div>
            )}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={mut.isPending}>
                {mut.isPending ? "Creating…" : "Create Tenant"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {createdResult && (
        <TenantCreatedDialog
          result={createdResult}
          open={!!createdResult}
          onClose={() => setCreatedResult(null)}
        />
      )}
    </>
  );
}


// ── Delete Tenant Dialog ──────────────────────────────────────────────────────

interface DeleteTenantDialogProps {
  tenant: Tenant;
  open: boolean;
  onClose: () => void;
}

/**
 * Deleting a tenant cascades to every identity, pool, client, signing key and
 * audit row it owned, and the slug is its permanent OIDC issuer — so anything
 * still trusting that issuer breaks. Typing the slug is the confirmation
 * because there is no undo and no partial form of this.
 */
function DeleteTenantDialog({ tenant, open, onClose }: DeleteTenantDialogProps) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () => deleteTenant(tenant.slug),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["tenants"] });
      toast.success(res.message);
      onClose();
      setConfirm("");
    },
    onError: (err: Error) => setError(err.message),
  });

  const matches = confirm === tenant.slug;

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          onClose();
          setConfirm("");
          setError(null);
        }
      }}
    >
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Delete tenant</DialogTitle>
          <DialogDescription>
            This cannot be undone.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <Alert variant="destructive">
            <AlertDescription className="space-y-2">
              <p>
                Deleting{" "}
                <span className="font-medium">{tenant.name}</span> permanently
                removes:
              </p>
              <ul className="list-disc space-y-0.5 pl-4 text-xs">
                <li>every identity in every pool, staff and end user alike</li>
                <li>all OAuth clients and their secrets</li>
                <li>the tenant&apos;s signing keys — issued tokens stop verifying</li>
                <li>its entire audit history</li>
              </ul>
              <p className="text-xs">
                The slug{" "}
                <code className="font-mono">{tenant.slug}</code> is this
                tenant&apos;s OIDC issuer. Anything still trusting{" "}
                <code className="font-mono">{tenantOrigin(tenant.slug)}</code>{" "}
                will break.
              </p>
            </AlertDescription>
          </Alert>

          <div className="space-y-1">
            <Label htmlFor="dt-confirm">
              Type <code className="font-mono">{tenant.slug}</code> to confirm
            </Label>
            <Input
              id="dt-confirm"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder={tenant.slug}
              autoComplete="off"
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={!matches || mut.isPending}
            onClick={() => {
              setError(null);
              mut.mutate();
            }}
          >
            {mut.isPending ? "Deleting…" : "Delete tenant"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Main Tenants Page ─────────────────────────────────────────────────────────

export function TenantsPageClient() {
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<Tenant | null>(null);

  const { data: tenants, isLoading, isError } = useQuery({
    queryKey: ["tenants"],
    queryFn: listTenants,
  });

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between border-b pb-6">
        <div>
          <h1 className="text-xl font-bold">Tenants</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Platform-level tenant management. Creating and deleting tenants
            requires PlatformTenantCreate / PlatformTenantDelete.
          </p>
        </div>
        <Button onClick={() => setCreating(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New Tenant
        </Button>
      </div>

      {isLoading && (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-12 animate-pulse rounded-md bg-muted" />
          ))}
        </div>
      )}

      {isError && (
        <Alert variant="destructive">
          <AlertDescription>
            Failed to load tenants. Ensure your token has TenantRead scope.
          </AlertDescription>
        </Alert>
      )}

      {tenants && (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Slug</TableHead>
                <TableHead>ID</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {tenants.map((tenant) => (
                <TableRow key={tenant.id}>
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      {tenant.name}
                      {tenant.is_platform && (
                        <Badge variant="outline" className="text-[10px]">
                          platform
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <code className="font-mono text-xs">{tenant.slug}</code>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <code className="font-mono text-xs text-muted-foreground">
                        {tenant.id}
                      </code>
                      <CopyButton value={tenant.id} />
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={tenant.status.toLowerCase() === "active" ? "success" : "warning"}
                    >
                      {tenant.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {new Date(tenant.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    {tenant.is_platform ? (
                      // The server refuses this too; disabling it here explains why
                      // rather than letting the click fail.
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        disabled
                        title="The platform tenant cannot be deleted"
                      >
                        <Lock className="h-3.5 w-3.5" />
                      </Button>
                    ) : (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-muted-foreground hover:text-destructive"
                        title={`Delete ${tenant.slug}`}
                        onClick={() => setDeleting(tenant)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}

              {tenants.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No tenants found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      )}

      <CreateTenantDialog open={creating} onClose={() => setCreating(false)} />

      {deleting && (
        <DeleteTenantDialog
          tenant={deleting}
          open={!!deleting}
          onClose={() => setDeleting(null)}
        />
      )}
    </div>
  );
}
