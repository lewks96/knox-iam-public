"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Trash2, Pencil, RefreshCw, ShieldOff, Copy, CheckCheck, X } from "lucide-react";
import {
  listClients,
  getClient,
  createClient,
  updateClient,
  deleteClient,
  rotateClientSecret,
  rotateTokenVersion,
  type OAuthClient,
  type CreateClientRequest,
  type UpdateClientRequest,
} from "@/lib/api/clients";
import {
  listPools,
  staffPool,
  customerPools,
  type IdentityPool,
} from "@/lib/api/pools";
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
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";

const ALL_GRANT_TYPES = [
  "authorization_code",
  "client_credentials",
  "refresh_token",
] as const;

// ── Pagination ──────────────────────────────────────────────────────────────

interface PaginationProps {
  page: number;
  total: number;
  pageSize: number;
  onPageChange: (p: number) => void;
}

function Pagination({ page, total, pageSize, onPageChange }: PaginationProps) {
  const totalPages = Math.ceil(total / pageSize);
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between text-sm text-muted-foreground">
      <span>
        Page {page} of {totalPages} ({total} total)
      </span>
      <div className="flex gap-1">
        <Button
          variant="outline"
          size="sm"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
        >
          Next
        </Button>
      </div>
    </div>
  );
}

// ── Copy button ─────────────────────────────────────────────────────────────

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

// ── Secret Shown Once Dialog ─────────────────────────────────────────────────

interface SecretDialogProps {
  secret: string;
  clientName: string;
  open: boolean;
  onClose: () => void;
}

function SecretDialog({ secret, clientName, open, onClose }: SecretDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Client Secret</DialogTitle>
          <DialogDescription>
            Save this secret immediately — it will not be shown again.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground">
            Client: <span className="font-medium text-foreground">{clientName}</span>
          </p>
          <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2">
            <code className="flex-1 break-all text-xs font-mono">{secret}</code>
            <CopyButton value={secret} />
          </div>
        </div>
        <DialogFooter>
          <Button onClick={onClose}>I have saved the secret</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Scope Tag Input ──────────────────────────────────────────────────────────

interface ScopeTagInputProps {
  id: string;
  scopes: string[];
  onChange: (scopes: string[]) => void;
  placeholder?: string;
}

/// Free-form scope editor: type a scope and press Enter or comma to add it,
/// Backspace on an empty field removes the last. Shared by the create and edit
/// dialogs so both allow any scope the client should hold — the scope set is
/// open-ended (tenant roles define custom scopes), so a fixed checklist can't
/// represent it. Pending text is committed on blur, so clicking Save/Create
/// captures a half-typed scope too.
function ScopeTagInput({ id, scopes, onChange, placeholder }: ScopeTagInputProps) {
  const [input, setInput] = useState("");

  function addScope(raw: string) {
    const scope = raw.trim();
    if (scope && !scopes.includes(scope)) onChange([...scopes, scope]);
    setInput("");
  }

  function removeScope(scope: string) {
    onChange(scopes.filter((s) => s !== scope));
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      addScope(input);
    } else if (e.key === "Backspace" && !input && scopes.length > 0) {
      removeScope(scopes[scopes.length - 1]);
    }
  }

  return (
    <div
      className="flex min-h-10 flex-wrap gap-1.5 rounded-md border bg-background px-3 py-2 text-sm
                 focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-0 cursor-text"
      onClick={() => document.getElementById(id)?.focus()}
    >
      {scopes.map((scope) => (
        <span
          key={scope}
          className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 text-xs font-medium text-secondary-foreground"
        >
          {scope}
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); removeScope(scope); }}
            className="ml-0.5 rounded-sm opacity-60 hover:opacity-100 focus:outline-none"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </span>
      ))}
      <input
        id={id}
        className="flex-1 min-w-[120px] bg-transparent outline-none placeholder:text-muted-foreground text-sm"
        placeholder={scopes.length === 0 ? placeholder : ""}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={() => addScope(input)}
      />
    </div>
  );
}

// ── Create Client Dialog ─────────────────────────────────────────────────────

interface CreateClientDialogProps {
  tenantId: string;
  open: boolean;
  onClose: () => void;
}

function CreateClientDialog({ tenantId, open, onClose }: CreateClientDialogProps) {
  const qc = useQueryClient();
  const [form, setForm] = useState<{
    name: string;
    pool_id: string;
    description: string;
    client_type: "confidential" | "public";
    grant_types: string[];
    allowed_scopes: string[];
    redirect_uris: string;
    post_logout_redirect_uris: string;
    allow_refresh_tokens: boolean;
    access_token_ttl: number;
    refresh_token_ttl: number;
  }>({
    name: "",
    pool_id: "",
    description: "",
    client_type: "confidential",
    grant_types: ["authorization_code"],
    allowed_scopes: [],
    redirect_uris: "",
    post_logout_redirect_uris: "",
    allow_refresh_tokens: false,
    access_token_ttl: 3600,
    refresh_token_ttl: 86400,
  });

  // Loading pools needs TenantRead; a ClientCreate-only session may be denied.
  // When it is, we simply omit the field and the server binds the client to the
  // creator's own (staff) pool — the prior behaviour.
  const { data: pools, isLoading: poolsLoading, isError: poolsError } =
    useQuery({ queryKey: ["pools"], queryFn: listPools });

  // Present the staff pool first, then customer directories. Seed the selection
  // to the staff pool so the default matches the server's, making the binding a
  // visible, deliberate choice rather than an inherited surprise.
  const orderedPools: IdentityPool[] = pools
    ? [...(staffPool(pools) ? [staffPool(pools)!] : []), ...customerPools(pools)]
    : [];

  useEffect(() => {
    if (!form.pool_id && pools) {
      const seed = staffPool(pools)?.id ?? orderedPools[0]?.id;
      if (seed) setForm((f) => ({ ...f, pool_id: seed }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pools]);
  const [error, setError] = useState<string | null>(null);
  const [createdSecret, setCreatedSecret] = useState<{ name: string; secret: string } | null>(null);

  const hasRefreshGrant = form.grant_types.includes("refresh_token");

  const mut = useMutation({
    mutationFn: (data: CreateClientRequest) => createClient(tenantId, data),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["clients", tenantId] });
      toast.success("Client created");
      onClose();
      if (res.client_secret) {
        setCreatedSecret({ name: res.client.name, secret: res.client_secret });
      }
    },
    onError: (err: Error) => setError(err.message),
  });

  function toggleGrant(grant: string) {
    setForm((f) => {
      const next = f.grant_types.includes(grant)
        ? f.grant_types.filter((g) => g !== grant)
        : [...f.grant_types, grant];

      // When refresh_token grant is removed, also clear allow_refresh_tokens
      const allow_refresh_tokens =
        next.includes("refresh_token") ? f.allow_refresh_tokens : false;

      return { ...f, grant_types: next, allow_refresh_tokens };
    });
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    // ScopeTagInput commits any half-typed scope on blur, so submitting from a
    // focused field still captures it before this runs.
    if (form.allowed_scopes.length === 0) {
      setError("At least one scope is required.");
      return;
    }

    const redirect_uris = form.redirect_uris
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);

    const post_logout_redirect_uris = form.post_logout_redirect_uris
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);

    mut.mutate({
      name: form.name,
      pool_id: form.pool_id || undefined,
      description: form.description || null,
      client_type: form.client_type,
      grant_types: form.grant_types as CreateClientRequest["grant_types"],
      allowed_scopes: form.allowed_scopes,
      redirect_uris,
      post_logout_redirect_uris,
      allow_refresh_tokens: form.allow_refresh_tokens,
      access_token_ttl: form.access_token_ttl,
      refresh_token_ttl: hasRefreshGrant ? form.refresh_token_ttl : undefined,
      response_types: form.grant_types.includes("authorization_code")
        ? ["code"]
        : [],
    });
  }

  return (
    <>
      <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create OAuth2 Client</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {/* Basic */}
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="cc-name">Name *</Label>
                <Input
                  id="cc-name"
                  required
                  minLength={3}
                  maxLength={100}
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="My Web App"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="cc-pool">Identity Directory *</Label>
                {poolsError ? (
                  <p className="text-xs text-muted-foreground">
                    Couldn&apos;t load directories — this client will be bound to
                    the staff pool.
                  </p>
                ) : (
                  <Select
                    value={form.pool_id || undefined}
                    onValueChange={(v) => setForm((f) => ({ ...f, pool_id: v ?? "" }))}
                    disabled={poolsLoading}
                    items={Object.fromEntries(orderedPools.map((p) => [p.id, p.name]))}
                  >
                    <SelectTrigger id="cc-pool">
                      <SelectValue placeholder={poolsLoading ? "Loading…" : "Select a directory"} />
                    </SelectTrigger>
                    <SelectContent>
                      {orderedPools.map((p) => (
                        <SelectItem key={p.id} value={p.id}>
                          {p.name}
                          <span className="ml-2 text-xs text-muted-foreground">
                            {p.kind === "staff" ? "staff · console admins" : "customer"}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
                <p className="text-xs text-muted-foreground">
                  Whose credentials can log in at this client. Staff is the
                  console admin directory; pick a customer directory for an
                  end-user app.
                </p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="cc-desc">Description</Label>
                <Input
                  id="cc-desc"
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  placeholder="Optional"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="cc-type">Client Type *</Label>
                <Select
                  value={form.client_type}
                  onValueChange={(v) =>
                    setForm((f) => ({ ...f, client_type: v as "confidential" | "public" }))
                  }
                >
                  <SelectTrigger id="cc-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="confidential">Confidential</SelectItem>
                    <SelectItem value="public">Public (PKCE enforced)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <Separator />

            {/* Grant types */}
            <div className="space-y-2">
              <Label>Grant Types *</Label>
              <div className="grid grid-cols-2 gap-2">
                {ALL_GRANT_TYPES.map((grant) => (
                  <div key={grant} className="flex items-center gap-2">
                    <Checkbox
                      id={`grant-${grant}`}
                      checked={form.grant_types.includes(grant)}
                      onCheckedChange={() => toggleGrant(grant)}
                    />
                    <Label htmlFor={`grant-${grant}`} className="font-normal text-sm">
                      {grant}
                    </Label>
                  </div>
                ))}
              </div>

              {/* Refresh token options — only visible when refresh_token grant is selected */}
              {hasRefreshGrant && (
                <div className="mt-3 rounded-lg border bg-muted/40 p-3 space-y-3">
                  <div className="flex items-center gap-2">
                    <Checkbox
                      id="cc-refresh"
                      checked={form.allow_refresh_tokens}
                      onCheckedChange={(c) =>
                        setForm((f) => ({ ...f, allow_refresh_tokens: !!c }))
                      }
                    />
                    <Label htmlFor="cc-refresh" className="font-normal text-sm">
                      Allow Refresh Tokens
                    </Label>
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="cc-rtt" className="text-sm">Refresh Token TTL (seconds)</Label>
                    <Input
                      id="cc-rtt"
                      type="number"
                      min={60}
                      value={form.refresh_token_ttl}
                      onChange={(e) =>
                        setForm((f) => ({ ...f, refresh_token_ttl: Number(e.target.value) }))
                      }
                    />
                  </div>
                </div>
              )}
            </div>

            <Separator />

            {/* Scopes — tag input */}
            <div className="space-y-2">
              <Label htmlFor="cc-scope-input">
                Allowed Scopes *
                <span className="ml-2 font-normal text-muted-foreground text-xs">
                  Press Enter or comma to add
                </span>
              </Label>
              <ScopeTagInput
                id="cc-scope-input"
                scopes={form.allowed_scopes}
                onChange={(allowed_scopes) => setForm((f) => ({ ...f, allowed_scopes }))}
                placeholder="e.g. IdentityRead, ClientRead…"
              />
            </div>

            <Separator />

            {/* URIs */}
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="cc-redirect">Redirect URIs (one per line)</Label>
                <Textarea
                  id="cc-redirect"
                  rows={3}
                  value={form.redirect_uris}
                  onChange={(e) => setForm((f) => ({ ...f, redirect_uris: e.target.value }))}
                  placeholder="https://myapp.com/callback"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="cc-logout">Post-Logout Redirect URIs (one per line)</Label>
                <Textarea
                  id="cc-logout"
                  rows={2}
                  value={form.post_logout_redirect_uris}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, post_logout_redirect_uris: e.target.value }))
                  }
                  placeholder="https://myapp.com/logout"
                />
              </div>
            </div>

            <Separator />

            {/* Access Token TTL */}
            <div className="space-y-1">
              <Label htmlFor="cc-att">Access Token TTL (seconds)</Label>
              <Input
                id="cc-att"
                type="number"
                min={60}
                value={form.access_token_ttl}
                onChange={(e) =>
                  setForm((f) => ({ ...f, access_token_ttl: Number(e.target.value) }))
                }
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={mut.isPending || form.grant_types.length === 0}>
                {mut.isPending ? "Creating…" : "Create"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {createdSecret && (
        <SecretDialog
          secret={createdSecret.secret}
          clientName={createdSecret.name}
          open={!!createdSecret}
          onClose={() => setCreatedSecret(null)}
        />
      )}
    </>
  );
}

// ── URI List Field ──────────────────────────────────────────────────────────

interface UriListFieldProps {
  id: string;
  label: string;
  uris: string[];
  onChange: (uris: string[]) => void;
  placeholder?: string;
}

function UriListField({ id, label, uris, onChange, placeholder }: UriListFieldProps) {
  return (
    <div className="space-y-2">
      <Label htmlFor={uris.length > 0 ? `${id}-0` : undefined}>{label}</Label>
      {uris.map((uri, i) => (
        <div key={i} className="flex items-center gap-2">
          <Input
            id={`${id}-${i}`}
            value={uri}
            onChange={(e) =>
              onChange(uris.map((u, j) => (j === i ? e.target.value : u)))
            }
            placeholder={placeholder}
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0 text-muted-foreground hover:text-destructive"
            title="Remove URI"
            onClick={() => onChange(uris.filter((_, j) => j !== i))}
          >
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => onChange([...uris, ""])}
      >
        <Plus className="mr-1.5 h-3.5 w-3.5" />
        Add URI
      </Button>
    </div>
  );
}

// ── Edit Client Dialog ──────────────────────────────────────────────────────

interface EditClientDialogProps {
  tenantId: string;
  client: OAuthClient;
  open: boolean;
  onClose: () => void;
}

function EditClientDialog({ tenantId, client, open, onClose }: EditClientDialogProps) {
  const qc = useQueryClient();
  const [form, setForm] = useState({
    description: client.description ?? "",
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    allow_refresh_tokens: client.allow_refresh_tokens,
    grant_types: client.grant_types as string[],
    require_pkce: client.require_pkce,
    allowed_scopes: client.allowed_scopes,
    status: client.status,
    access_token_ttl: client.access_token_ttl,
    refresh_token_ttl: client.refresh_token_ttl,
    id_token_ttl: client.id_token_ttl,
    auth_code_ttl: client.auth_code_ttl,
  });
  const [redirectUris, setRedirectUris] = useState<string[]>(client.redirect_uris);
  const [logoutUris, setLogoutUris] = useState<string[]>(
    client.post_logout_redirect_uris
  );
  const [error, setError] = useState<string | null>(null);

  const hasRefreshGrant = form.grant_types.includes("refresh_token");
  const hasAuthCodeGrant = form.grant_types.includes("authorization_code");

  const mut = useMutation({
    mutationFn: (data: UpdateClientRequest) =>
      updateClient(tenantId, client.id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients", tenantId] });
      toast.success("Client updated");
      onClose();
    },
    onError: (err: Error) => setError(err.message),
  });

  function toggleGrant(grant: string) {
    setForm((f) => {
      const next = f.grant_types.includes(grant)
        ? f.grant_types.filter((g) => g !== grant)
        : [...f.grant_types, grant];
      const allow_refresh_tokens = next.includes("refresh_token")
        ? f.allow_refresh_tokens
        : false;
      return { ...f, grant_types: next, allow_refresh_tokens };
    });
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    mut.mutate({
      description: form.description || null,
      token_endpoint_auth_method: form.token_endpoint_auth_method,
      allow_refresh_tokens: form.allow_refresh_tokens,
      grant_types: form.grant_types as UpdateClientRequest["grant_types"],
      response_types: hasAuthCodeGrant ? ["code"] : [],
      require_pkce: form.require_pkce,
      allowed_scopes: form.allowed_scopes,
      status: form.status,
      access_token_ttl: form.access_token_ttl,
      refresh_token_ttl: hasRefreshGrant ? form.refresh_token_ttl : undefined,
      id_token_ttl: form.id_token_ttl,
      auth_code_ttl: hasAuthCodeGrant ? form.auth_code_ttl : undefined,
      redirect_uris: redirectUris.map((s) => s.trim()).filter(Boolean),
      post_logout_redirect_uris: logoutUris.map((s) => s.trim()).filter(Boolean),
    });
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit Client</DialogTitle>
          <DialogDescription>
            Name and client type are immutable — create a new client to change them.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-1">
            <Label>Name</Label>
            <Input value={client.name} disabled />
          </div>
          <div className="space-y-1">
            <Label htmlFor="ec-desc">Description</Label>
            <Input
              id="ec-desc"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="ec-status">Status</Label>
            <Select
              value={form.status}
              onValueChange={(v) =>
                setForm((f) => ({ ...f, status: v as "active" | "inactive" }))
              }
            >
              <SelectTrigger id="ec-status">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Separator />

          {/* Grant types */}
          <div className="space-y-2">
            <Label>Grant Types *</Label>
            <div className="grid grid-cols-2 gap-2">
              {ALL_GRANT_TYPES.map((grant) => (
                <div key={grant} className="flex items-center gap-2">
                  <Checkbox
                    id={`eg-${grant}`}
                    checked={form.grant_types.includes(grant)}
                    onCheckedChange={() => toggleGrant(grant)}
                  />
                  <Label htmlFor={`eg-${grant}`} className="font-normal text-sm">
                    {grant}
                  </Label>
                </div>
              ))}
            </div>

            {hasRefreshGrant && (
              <div className="mt-3 rounded-lg border bg-muted/40 p-3 space-y-3">
                <div className="flex items-center gap-2">
                  <Checkbox
                    id="ec-refresh"
                    checked={form.allow_refresh_tokens}
                    onCheckedChange={(c) =>
                      setForm((f) => ({ ...f, allow_refresh_tokens: !!c }))
                    }
                  />
                  <Label htmlFor="ec-refresh" className="font-normal text-sm">
                    Allow Refresh Tokens
                  </Label>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="ec-rtt" className="text-sm">Refresh Token TTL (seconds)</Label>
                  <Input
                    id="ec-rtt"
                    type="number"
                    min={60}
                    value={form.refresh_token_ttl}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, refresh_token_ttl: Number(e.target.value) }))
                    }
                  />
                </div>
              </div>
            )}
          </div>

          <Separator />

          {/* Auth method + PKCE */}
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="ec-auth-method">Token Endpoint Auth Method</Label>
              <Select
                value={form.token_endpoint_auth_method}
                onValueChange={(v) =>
                  setForm((f) => ({
                    ...f,
                    token_endpoint_auth_method: v as typeof f.token_endpoint_auth_method,
                  }))
                }
              >
                <SelectTrigger id="ec-auth-method">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="client_secret_basic">client_secret_basic</SelectItem>
                  <SelectItem value="none">none</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox
                id="ec-pkce"
                checked={form.require_pkce}
                onCheckedChange={(c) =>
                  setForm((f) => ({ ...f, require_pkce: !!c }))
                }
              />
              <Label htmlFor="ec-pkce" className="font-normal text-sm">
                Require PKCE
              </Label>
            </div>
          </div>

          <Separator />

          <div className="space-y-2">
            <Label htmlFor="ec-scope-input">
              Allowed Scopes
              <span className="ml-2 font-normal text-muted-foreground text-xs">
                Press Enter or comma to add
              </span>
            </Label>
            <ScopeTagInput
              id="ec-scope-input"
              scopes={form.allowed_scopes}
              onChange={(allowed_scopes) => setForm((f) => ({ ...f, allowed_scopes }))}
              placeholder="e.g. IdentityRead, ClientRead…"
            />
          </div>

          <Separator />

          <UriListField
            id="ec-redirect"
            label="Redirect URIs"
            uris={redirectUris}
            onChange={setRedirectUris}
            placeholder="https://myapp.com/callback"
          />
          <UriListField
            id="ec-logout"
            label="Post-Logout Redirect URIs"
            uris={logoutUris}
            onChange={setLogoutUris}
            placeholder="https://myapp.com/logout"
          />

          <Separator />

          {/* TTLs */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="ec-att">Access Token TTL (s)</Label>
              <Input
                id="ec-att"
                type="number"
                min={60}
                value={form.access_token_ttl}
                onChange={(e) =>
                  setForm((f) => ({ ...f, access_token_ttl: Number(e.target.value) }))
                }
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ec-itt">ID Token TTL (s)</Label>
              <Input
                id="ec-itt"
                type="number"
                min={60}
                value={form.id_token_ttl}
                onChange={(e) =>
                  setForm((f) => ({ ...f, id_token_ttl: Number(e.target.value) }))
                }
              />
            </div>
            {hasAuthCodeGrant && (
              <div className="space-y-1">
                <Label htmlFor="ec-act">Auth Code TTL (s)</Label>
                <Input
                  id="ec-act"
                  type="number"
                  min={60}
                  value={form.auth_code_ttl}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, auth_code_ttl: Number(e.target.value) }))
                  }
                />
              </div>
            )}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={mut.isPending || form.grant_types.length === 0}
            >
              {mut.isPending ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ── Delete Client Dialog ─────────────────────────────────────────────────────

interface DeleteClientDialogProps {
  tenantId: string;
  client: OAuthClient;
  open: boolean;
  onClose: () => void;
}

function DeleteClientDialog({ tenantId, client, open, onClose }: DeleteClientDialogProps) {
  const qc = useQueryClient();
  const mut = useMutation({
    mutationFn: () => deleteClient(tenantId, client.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients", tenantId] });
      toast.success("Client deleted");
      onClose();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete Client</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          Permanently delete{" "}
          <span className="font-medium text-foreground">{client.name}</span>?
          All associated refresh tokens will also be deleted. This cannot be
          undone.
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="destructive" disabled={mut.isPending} onClick={() => mut.mutate()}>
            {mut.isPending ? "Deleting…" : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Rotate Secret Dialog ─────────────────────────────────────────────────────

interface RotateSecretDialogProps {
  tenantId: string;
  client: OAuthClient;
  open: boolean;
  onClose: () => void;
}

function RotateSecretDialog({ tenantId, client, open, onClose }: RotateSecretDialogProps) {
  const qc = useQueryClient();
  const [newSecret, setNewSecret] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () => rotateClientSecret(tenantId, client.id),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["clients", tenantId] });
      setNewSecret(res.client_secret);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  function handleClose() {
    setNewSecret(null);
    onClose();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) handleClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rotate Client Secret</DialogTitle>
          <DialogDescription>
            {newSecret
              ? "Save the new secret immediately — it will not be shown again."
              : "This will immediately invalidate all existing access tokens for this client."}
          </DialogDescription>
        </DialogHeader>

        {newSecret ? (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">New secret:</p>
            <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2">
              <code className="flex-1 break-all text-xs font-mono">{newSecret}</code>
              <CopyButton value={newSecret} />
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Rotate the secret for{" "}
            <span className="font-medium text-foreground">{client.name}</span>?
            The old secret stops working immediately.
          </p>
        )}

        <DialogFooter>
          {newSecret ? (
            <Button onClick={handleClose}>I have saved the secret</Button>
          ) : (
            <>
              <Button variant="outline" onClick={handleClose}>Cancel</Button>
              <Button
                variant="destructive"
                disabled={mut.isPending}
                onClick={() => mut.mutate()}
              >
                {mut.isPending ? "Rotating…" : "Rotate Secret"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Rotate Token Version Dialog ───────────────────────────────────────────────

interface RotateTokenVersionDialogProps {
  tenantId: string;
  client: OAuthClient;
  open: boolean;
  onClose: () => void;
}

function RotateTokenVersionDialog({
  tenantId,
  client,
  open,
  onClose,
}: RotateTokenVersionDialogProps) {
  const qc = useQueryClient();
  const mut = useMutation({
    mutationFn: () => rotateTokenVersion(tenantId, client.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["clients", tenantId] });
      toast.success("Token version rotated — all existing tokens invalidated");
      onClose();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rotate Token Version</DialogTitle>
          <DialogDescription>
            Increments the token version, invalidating all currently-issued
            access tokens without changing the client secret.
          </DialogDescription>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          Invalidate all tokens for{" "}
          <span className="font-medium text-foreground">{client.name}</span>?
          Current version: <span className="font-mono font-medium">{client.token_version}</span>.
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            variant="destructive"
            disabled={mut.isPending}
            onClick={() => mut.mutate()}
          >
            {mut.isPending ? "Rotating…" : "Rotate Token Version"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Main Clients Page ─────────────────────────────────────────────────────────

interface ClientsPageClientProps {
  tenantId: string;
}

export function ClientsPageClient({ tenantId }: ClientsPageClientProps) {
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<OAuthClient | null>(null);
  const [deleting, setDeleting] = useState<OAuthClient | null>(null);
  const [rotatingSec, setRotatingSec] = useState<OAuthClient | null>(null);
  const [rotatingVer, setRotatingVer] = useState<OAuthClient | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["clients", tenantId, page],
    queryFn: () => listClients(tenantId, page),
  });

  // Map pool id → name so the table can name each client's directory instead of
  // exposing a bare uuid. Best-effort: needs TenantRead, and the column falls
  // back to the id when unavailable.
  const { data: pools } = useQuery({ queryKey: ["pools"], queryFn: listPools });
  const poolName = (id: string) =>
    pools?.find((p) => p.id === id)?.name ?? `${id.slice(0, 8)}…`;

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between border-b pb-6">
        <div>
          <h1 className="text-xl font-bold">Clients</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage OAuth2 clients for this tenant.
          </p>
        </div>
        <Button onClick={() => setCreating(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New Client
        </Button>
      </div>

      {isLoading && (
        <div className="space-y-2">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-12 animate-pulse rounded-md bg-muted" />
          ))}
        </div>
      )}

      {isError && (
        <Alert variant="destructive">
          <AlertDescription>Failed to load clients.</AlertDescription>
        </Alert>
      )}

      {data && (
        <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Directory</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Grant Types</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Token v</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((client) => (
                  <TableRow key={client.id}>
                    <TableCell>
                      <div>
                        <p className="font-medium">{client.name}</p>
                        <p className="font-mono text-xs text-muted-foreground">{client.id}</p>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm">{poolName(client.pool_id)}</TableCell>
                    <TableCell>
                      <Badge variant={client.client_type === "confidential" ? "default" : "secondary"}>
                        {client.client_type}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {client.grant_types.map((g) => (
                          <Badge key={g} variant="outline" className="text-[10px]">
                            {g}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={client.status === "active" ? "success" : "warning"}>
                        {client.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono">{client.token_version}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(client.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          title="Edit client"
                          onClick={() => setEditing(client)}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        {client.client_type === "confidential" && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            title="Rotate secret"
                            onClick={() => setRotatingSec(client)}
                          >
                            <RefreshCw className="h-3.5 w-3.5" />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          title="Rotate token version"
                          onClick={() => setRotatingVer(client)}
                        >
                          <ShieldOff className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-destructive hover:text-destructive"
                          title="Delete client"
                          onClick={() => setDeleting(client)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <Pagination
            page={page}
            total={data.total}
            pageSize={data.page_size}
            onPageChange={setPage}
          />
        </>
      )}

      <CreateClientDialog
        tenantId={tenantId}
        open={creating}
        onClose={() => setCreating(false)}
      />

      {editing && (
        <EditClientDialog
          tenantId={tenantId}
          client={editing}
          open={!!editing}
          onClose={() => setEditing(null)}
        />
      )}

      {deleting && (
        <DeleteClientDialog
          tenantId={tenantId}
          client={deleting}
          open={!!deleting}
          onClose={() => setDeleting(null)}
        />
      )}

      {rotatingSec && (
        <RotateSecretDialog
          tenantId={tenantId}
          client={rotatingSec}
          open={!!rotatingSec}
          onClose={() => setRotatingSec(null)}
        />
      )}

      {rotatingVer && (
        <RotateTokenVersionDialog
          tenantId={tenantId}
          client={rotatingVer}
          open={!!rotatingVer}
          onClose={() => setRotatingVer(null)}
        />
      )}
    </div>
  );
}
