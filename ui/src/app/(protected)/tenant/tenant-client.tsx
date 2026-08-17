"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Building2,
  Check,
  Copy,
  FolderPlus,
  Lock,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2,
  Users,
} from "lucide-react";
import { toast } from "sonner";
import { getTenant, type Tenant } from "@/lib/api/tenants";
import { listIdentities, type Identity } from "@/lib/api/identity";
import { customerPools, listPools, staffPool } from "@/lib/api/pools";
import { ApiError } from "@/lib/api-client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { CreatePoolDialog } from "@/components/pools/create-pool-dialog";
import {
  CreateIdentityDialog,
  DeleteIdentityDialog,
  EditIdentityDialog,
} from "../identities/identity-dialogs";

// ── Small pieces ────────────────────────────────────────────────────────

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex items-center gap-1 text-muted-foreground transition-colors hover:text-foreground"
      title={`Copy ${label}`}
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
        toast.success(`${label} copied`);
      }}
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/70">
        {label}
      </p>
      <div className="mt-1 text-sm">{children}</div>
    </div>
  );
}

/**
 * One configuration option, rendered read-only.
 *
 * There is no tenant-update endpoint yet, so every option here is displayed
 * rather than edited — the shape a future editor will slot into.
 */
function Setting({
  label,
  value,
  hint,
  emphasis,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  emphasis?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-6 py-3">
      <div className="min-w-0">
        <p className={emphasis ? "text-sm font-medium" : "text-sm"}>{label}</p>
        {hint && (
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
            {hint}
          </p>
        )}
      </div>
      <div className="shrink-0 text-sm">{value}</div>
    </div>
  );
}

function BoolValue({ on }: { on: boolean }) {
  return (
    <Badge variant={on ? "success" : "secondary"}>{on ? "On" : "Off"}</Badge>
  );
}

/**
 * `time::Duration` does not serialise as a plain number — it arrives as a
 * (seconds, nanoseconds) pair — so read whichever shape turns up rather than
 * printing `[object Object]`.
 */
function seconds(value: unknown): number | null {
  if (typeof value === "number") return value;
  if (Array.isArray(value) && typeof value[0] === "number") return value[0];
  if (value && typeof value === "object") {
    const secs = (value as Record<string, unknown>).secs ?? (value as Record<string, unknown>).seconds;
    if (typeof secs === "number") return secs;
  }
  return null;
}

function Duration({ value }: { value: unknown }) {
  const s = seconds(value);
  if (s === null) return <span className="text-muted-foreground">—</span>;
  if (s % 3600 === 0 && s >= 3600) return <span>{s / 3600} h</span>;
  if (s % 60 === 0 && s >= 60) return <span>{s / 60} min</span>;
  return <span>{s} s</span>;
}

// ── Configuration ───────────────────────────────────────────────────────

function ConfigurationCards({ tenant }: { tenant: Tenant }) {
  const auth = tenant.config.authentication_configuration;
  const authz = tenant.config.authorization_configuration;
  const audit = tenant.config.audit_configuration;

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Sign-in policy</CardTitle>
        </CardHeader>
        <CardContent className="divide-y pt-0">
          <Setting
            emphasis
            label="Require MFA for administrators"
            hint="Withholds every scope beyond self-service from an administrator with no verified second factor. The session still signs in — it just cannot use its permissions until enrollment."
            value={<BoolValue on={!!authz?.require_admin_mfa} />}
          />
          <Setting
            label="Authenticator issuer"
            hint="Name shown in authenticator apps. Falls back to the tenant slug."
            value={
              auth?.totp_issuer ? (
                <span className="font-mono text-xs">{auth.totp_issuer}</span>
              ) : (
                <span className="text-muted-foreground">{tenant.slug}</span>
              )
            }
          />
          <Setting
            label="MFA challenge lifetime"
            value={<Duration value={auth?.mfa_token_lifetime_seconds} />}
          />
          <Setting
            label="Max verification attempts"
            hint="Failed codes per challenge before the challenge is locked out."
            value={<span className="tabular-nums">{auth?.mfa_max_verification_attempts ?? "—"}</span>}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Sessions &amp; tokens</CardTitle>
        </CardHeader>
        <CardContent className="divide-y pt-0">
          <Setting
            label="SSO cookie"
            value={<span className="font-mono text-xs">{auth?.sso_cookie_name ?? "—"}</span>}
          />
          <Setting
            label="Secure cookie"
            hint="Off is only viable over plain HTTP, which is a local-development arrangement."
            value={<BoolValue on={!!auth?.sso_cookie_secure} />}
          />
          <Setting
            label="SSO session lifetime"
            value={<Duration value={auth?.sso_cookie_lifetime_seconds} />}
          />
          <Setting
            label="Authorization code lifetime"
            value={
              authz?.auth_code_ttl_seconds !== undefined ? (
                <Duration value={authz.auth_code_ttl_seconds} />
              ) : (
                <span className="text-muted-foreground">—</span>
              )
            }
          />
          <Setting
            label="Allow plain PKCE"
            hint="Permits `code_challenge_method=plain`. Off means S256 only."
            value={<BoolValue on={!!authz?.allow_plain_pkce} />}
          />
          <Setting
            label="Audit retention"
            hint="How long audit events are kept before the daily prune job removes them."
            value={
              audit?.retention_days !== undefined ? (
                <span className="tabular-nums">{audit.retention_days} days</span>
              ) : (
                <span className="text-muted-foreground">—</span>
              )
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}

// ── Administrators ──────────────────────────────────────────────────────

/**
 * The staff directory: the people who can sign in to this console.
 *
 * Deliberately the only place roles can be granted. Requests here carry no
 * `pool_id`, which resolves to the caller's own pool — the staff one — so this
 * list can never accidentally show or create an end user.
 */
function Administrators({ tenantId }: { tenantId: string }) {
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Identity | null>(null);
  const [deleting, setDeleting] = useState<Identity | null>(null);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["identities", tenantId, "staff"],
    queryFn: () => listIdentities(tenantId, { page: 1, page_size: 100 }),
  });

  const forbidden = isError && error instanceof ApiError && error.status === 403;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="text-sm">Administrators</CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">
            Identities in this tenant&apos;s staff directory. Only these can sign
            in to the console, and only these hold roles.
          </p>
        </div>
        <Button size="sm" onClick={() => setCreating(true)} disabled={!!forbidden}>
          <Plus className="mr-2 h-3.5 w-3.5" />
          New administrator
        </Button>
      </CardHeader>
      <CardContent>
        {forbidden ? (
          <p className="text-sm text-muted-foreground">
            Your session doesn&apos;t have the <code>IdentityRead</code> scope, so
            administrators can&apos;t be listed.
          </p>
        ) : isError ? (
          <p className="text-sm text-muted-foreground">
            Failed to load administrators.
          </p>
        ) : isLoading ? (
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-10 animate-pulse rounded-md bg-muted" />
            ))}
          </div>
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.items.length ?? 0) === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-10 text-center text-muted-foreground">
                      No administrators found.
                    </TableCell>
                  </TableRow>
                ) : (
                  data?.items.map((identity) => (
                    <TableRow key={identity.id}>
                      <TableCell className="font-medium">
                        <Link href={`/identities/${identity.id}`} className="hover:underline">
                          {identity.email}
                        </Link>
                      </TableCell>
                      <TableCell>
                        {[identity.first_name, identity.last_name].filter(Boolean).join(" ") || "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant={identity.status.toLowerCase() === "active" ? "success" : "warning"}>
                          {identity.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {new Date(identity.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setEditing(identity)}>
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-destructive hover:text-destructive"
                            onClick={() => setDeleting(identity)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>

      <CreateIdentityDialog
        tenantId={tenantId}
        open={creating}
        onClose={() => setCreating(false)}
        withRoles
        title="Create administrator"
        description="Added to the staff directory, so this account can sign in to the console. Roles decide what it may do there."
      />
      {editing && (
        <EditIdentityDialog
          tenantId={tenantId}
          identity={editing}
          open={!!editing}
          onClose={() => setEditing(null)}
        />
      )}
      {deleting && (
        <DeleteIdentityDialog
          tenantId={tenantId}
          identity={deleting}
          open={!!deleting}
          onClose={() => setDeleting(null)}
        />
      )}
    </Card>
  );
}

// ── Directories ─────────────────────────────────────────────────────────

function Directories() {
  const [creating, setCreating] = useState(false);
  const { data: pools, isLoading, isError, error } = useQuery({
    queryKey: ["pools"],
    queryFn: listPools,
    staleTime: 5 * 60 * 1000,
  });

  const forbidden = isError && error instanceof ApiError && error.status === 403;
  const staff = staffPool(pools ?? []);
  const customers = customerPools(pools ?? []);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="text-sm">Identity directories</CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">
            Identities are unique per directory, so the same email can be an
            administrator here and an unrelated end user of your app.
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => setCreating(true)} disabled={!!forbidden}>
          <FolderPlus className="mr-2 h-3.5 w-3.5" />
          New directory
        </Button>
      </CardHeader>
      <CardContent className="space-y-2">
        {forbidden ? (
          <p className="text-sm text-muted-foreground">
            Your session doesn&apos;t have the <code>TenantRead</code> scope, so
            directories can&apos;t be listed.
          </p>
        ) : isError ? (
          <p className="text-sm text-muted-foreground">Failed to load directories.</p>
        ) : isLoading ? (
          <div className="h-16 animate-pulse rounded-md bg-muted" />
        ) : (
          <>
            {staff && (
              <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
                <div className="flex min-w-0 items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <ShieldCheck className="h-4 w-4" />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{staff.name}</p>
                    <p className="truncate font-mono text-[11px] text-muted-foreground">
                      {staff.slug}
                    </p>
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  <Badge variant="secondary" className="gap-1">
                    <Lock className="h-3 w-3" />
                    Staff
                  </Badge>
                </div>
              </div>
            )}

            {customers.map((pool) => (
              <div key={pool.id} className="flex items-center justify-between gap-4 rounded-lg border p-3">
                <div className="flex min-w-0 items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                    <Users className="h-4 w-4" />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{pool.name}</p>
                    <p className="truncate font-mono text-[11px] text-muted-foreground">
                      {pool.slug}
                    </p>
                  </div>
                </div>
                <Link
                  href={`/identities?pool=${pool.id}`}
                  className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
                >
                  Manage customers
                  <ArrowUpRight className="h-3 w-3" />
                </Link>
              </div>
            ))}

            {customers.length === 0 && (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No customer directories yet.
              </p>
            )}
          </>
        )}
      </CardContent>

      <CreatePoolDialog open={creating} onClose={() => setCreating(false)} />
    </Card>
  );
}

// ── Page ────────────────────────────────────────────────────────────────

export function TenantClient({ tenantId }: { tenantId: string }) {
  const { data: tenant, isLoading, isError, error } = useQuery({
    queryKey: ["tenant", tenantId],
    queryFn: () => getTenant(tenantId),
  });

  const forbidden = isError && error instanceof ApiError && error.status === 403;

  return (
    <div className="space-y-6 p-8">
      <div className="border-b pb-6">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Building2 className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold">
              {tenant?.name ?? tenantId}
              {tenant?.is_platform && (
                <Badge variant="secondary" className="ml-2 align-middle">
                  Platform
                </Badge>
              )}
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Administrators, directories and sign-in policy for this tenant.
            </p>
          </div>
        </div>
      </div>

      {forbidden ? (
        <Alert>
          <AlertDescription>
            Your session doesn&apos;t have the <code>TenantRead</code> scope, so
            this tenant&apos;s settings can&apos;t be shown. Administrators below
            are unaffected.
          </AlertDescription>
        </Alert>
      ) : isError ? (
        <Alert variant="destructive">
          <AlertDescription>Failed to load this tenant.</AlertDescription>
        </Alert>
      ) : isLoading ? (
        <div className="h-40 animate-pulse rounded-xl bg-muted" />
      ) : (
        tenant && (
          <>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Overview</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid gap-x-8 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
                  <Field label="Tenant ID">
                    <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                      <span className="break-all">{tenant.id}</span>
                      <CopyButton value={tenant.id} label="Tenant ID" />
                    </span>
                  </Field>
                  <Field label="Slug">
                    <span className="font-mono text-xs">{tenant.slug}</span>
                  </Field>
                  <Field label="Status">
                    <Badge variant={tenant.status.toLowerCase() === "active" ? "success" : "warning"}>
                      {tenant.status}
                    </Badge>
                  </Field>
                  <Field label="Issuer">
                    <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                      <span className="break-all">{tenant.issuer}</span>
                      <CopyButton value={tenant.issuer} label="Issuer" />
                    </span>
                  </Field>
                  <Field label="Description">
                    {tenant.description ?? <span className="text-muted-foreground">—</span>}
                  </Field>
                  <Field label="Created">
                    <span className="text-muted-foreground" title={tenant.created_at}>
                      {new Date(tenant.created_at).toLocaleString()}
                    </span>
                  </Field>
                </div>
              </CardContent>
            </Card>

            <div className="flex items-center gap-2 pt-2">
              <h2 className="text-sm font-semibold">Configuration</h2>
              <Badge variant="outline" className="gap-1 text-[10px]">
                <Lock className="h-3 w-3" />
                Read-only
              </Badge>
              <p className="text-xs text-muted-foreground">
                Editing arrives with the tenant update API; these are the options
                it will expose.
              </p>
            </div>
            <ConfigurationCards tenant={tenant} />
          </>
        )
      )}

      <Administrators tenantId={tenantId} />
      <Directories />
    </div>
  );
}
