"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  ArrowUpRight,
  Check,
  Copy,
  KeyRound,
  Pencil,
  ShieldCheck,
  ShieldOff,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { updateIdentity } from "@/lib/api/identity";
import { poolsQuery, resolveIdentity } from "@/lib/api/identity-resolve";
import { assignRole, getIdentityRoles, revokeRole } from "@/lib/api/roles";
import { useGrantableRoles } from "../role-picker";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { listAuditEvents } from "@/lib/api/audit";
import { ApiError } from "@/lib/api-client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  EditIdentityDialog,
  DeleteIdentityDialog,
  ResetPasswordDialog,
  ResetMfaDialog,
} from "../identity-dialogs";

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

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
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
 * A JSON object card with in-place editing: the pencil flips the pretty-printed
 * view into a validated textarea, and Save PATCHes just that field.
 */
function EditableJsonCard({
  title,
  field,
  data,
  emptyLabel,
  tenantId,
  identityId,
  poolId,
}: {
  title: string;
  field: "metadata" | "custom_attributes";
  data: Record<string, unknown>;
  emptyLabel: string;
  tenantId: string;
  identityId: string;
  poolId: string;
}) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");

  const isEmpty = !data || Object.keys(data).length === 0;

  const parsed = useMemo((): { value?: Record<string, unknown>; error?: string } => {
    if (!editing) return {};
    try {
      const v = JSON.parse(draft);
      if (v === null || Array.isArray(v) || typeof v !== "object") {
        return { error: 'Must be a JSON object, e.g. {"team": "platform"}' };
      }
      return { value: v as Record<string, unknown> };
    } catch (e) {
      return { error: (e as Error).message };
    }
  }, [editing, draft]);

  const mut = useMutation({
    mutationFn: (value: Record<string, unknown>) =>
      updateIdentity(tenantId, identityId, { [field]: value }, poolId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["identity", tenantId, identityId] });
      toast.success(`${title} updated`);
      setEditing(false);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  function startEditing() {
    setDraft(JSON.stringify(data && !isEmpty ? data : {}, null, 2));
    setEditing(true);
  }

  function save() {
    if (parsed.value) mut.mutate(parsed.value);
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm">{title}</CardTitle>
        {!editing && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-muted-foreground hover:text-foreground"
            onClick={startEditing}
          >
            <Pencil className="mr-1.5 h-3 w-3" />
            Edit
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {editing ? (
          <div className="space-y-2">
            <Textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              spellCheck={false}
              autoFocus
              rows={Math.min(16, Math.max(6, draft.split("\n").length + 1))}
              className="font-mono text-xs leading-relaxed"
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  e.preventDefault();
                  setEditing(false);
                } else if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                  e.preventDefault();
                  save();
                }
              }}
            />
            <div className="flex items-center justify-between gap-3">
              <p
                className={
                  parsed.error
                    ? "text-xs text-destructive"
                    : "text-xs text-muted-foreground"
                }
              >
                {parsed.error ?? "Valid JSON · ⌘↵ to save, Esc to cancel"}
              </p>
              <div className="flex shrink-0 gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setEditing(false)}
                  disabled={mut.isPending}
                >
                  Cancel
                </Button>
                <Button
                  size="sm"
                  onClick={save}
                  disabled={!!parsed.error || mut.isPending}
                >
                  {mut.isPending ? "Saving…" : "Save"}
                </Button>
              </div>
            </div>
          </div>
        ) : isEmpty ? (
          <p className="text-sm text-muted-foreground">{emptyLabel}</p>
        ) : (
          <pre className="overflow-x-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs leading-relaxed">
            {JSON.stringify(data, null, 2)}
          </pre>
        )}
      </CardContent>
    </Card>
  );
}

// ── Recent activity (audit events by this actor) ────────────────────────

function RecentActivity({
  tenantId,
  identityId,
}: {
  tenantId: string;
  identityId: string;
}) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["audit-events", tenantId, "actor", identityId],
    queryFn: () =>
      listAuditEvents(tenantId, { actor_id: identityId, limit: 10 }),
    staleTime: 30_000,
  });

  const forbidden =
    isError && error instanceof ApiError && error.status === 403;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm">Recent activity</CardTitle>
        {!forbidden && (
          <Link
            href={`/audit?actor=${identityId}`}
            className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            View all in Audit Log
            <ArrowUpRight className="h-3 w-3" />
          </Link>
        )}
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-8 animate-pulse rounded-md bg-muted" />
            ))}
          </div>
        ) : forbidden ? (
          <p className="text-sm text-muted-foreground">
            Your session doesn&apos;t have the <code>AuditRead</code> scope, so
            activity can&apos;t be shown.
          </p>
        ) : isError ? (
          <p className="text-sm text-muted-foreground">
            Failed to load activity.
          </p>
        ) : (data?.items.length ?? 0) === 0 ? (
          <p className="text-sm text-muted-foreground">
            No recorded activity for this identity.
          </p>
        ) : (
          <ul className="divide-y">
            {data?.items.map((event) => (
              <li
                key={event.id}
                className="flex items-center justify-between gap-4 py-2 text-xs"
              >
                <span className="font-mono">
                  <span className="text-muted-foreground/70">
                    {event.event_type.includes(".")
                      ? event.event_type.slice(
                          0,
                          event.event_type.indexOf(".") + 1
                        )
                      : ""}
                  </span>
                  <span className="font-medium">
                    {event.event_type.includes(".")
                      ? event.event_type.slice(
                          event.event_type.indexOf(".") + 1
                        )
                      : event.event_type}
                  </span>
                </span>
                <span className="flex shrink-0 items-center gap-3 text-muted-foreground">
                  <span
                    className={
                      event.outcome === "success"
                        ? "text-emerald-700 dark:text-emerald-400"
                        : event.outcome === "denied"
                          ? "text-amber-700 dark:text-amber-400"
                          : "text-destructive"
                    }
                  >
                    {event.outcome}
                  </span>
                  <span
                    className="tabular-nums"
                    title={new Date(event.occurred_at).toLocaleString()}
                  >
                    {new Date(event.occurred_at).toLocaleString(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

// ── Main detail page ────────────────────────────────────────────────────

interface IdentityDetailClientProps {
  tenantId: string;
  identityId: string;
  /**
   * The directory to look in, from `?pool=`. Customer links carry it; links from
   * the audit log and the administrators list do not, because an identity
   * request without a pool resolves against the caller's own — the staff pool —
   * which is exactly where those actors live.
   */
  poolId?: string;
}


/**
 * Role membership for one identity.
 *
 * Roles are tenant-scoped, not pool-scoped: a tenant's `IdentityAdmin` means the
 * same thing whichever directory the holder sits in. Options the signed-in
 * session could not grant are shown disabled with the reason, rather than hidden
 * — an admin should be able to see that a role exists and why it is out of reach.
 */
function RolesCard({ identityId }: { identityId: string }) {
  const qc = useQueryClient();
  const { roles: allRoles, grantable, missing, adminPreset, isError } =
    useGrantableRoles();

  const { data: held, isLoading } = useQuery({
    queryKey: ["identity-roles", identityId],
    queryFn: () => getIdentityRoles(identityId),
  });

  const [pending, setPending] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: ({ role, on }: { role: string; on: boolean }) =>
      on ? assignRole(identityId, role) : revokeRole(identityId, role),
    onMutate: ({ role }) => setPending(role),
    onSettled: () => setPending(null),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["identity-roles", identityId] });
      toast.success(res.message);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const heldSet = new Set(held ?? []);
  const isAdmin =
    adminPreset.length > 0 && adminPreset.every((r) => heldSet.has(r));

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm">Roles</CardTitle>
        {isAdmin && (
          <Badge variant="success" className="gap-1">
            <ShieldCheck className="h-3 w-3" />
            Administrator
          </Badge>
        )}
      </CardHeader>
      <CardContent>
        {isLoading && <div className="h-8 animate-pulse rounded-md bg-muted" />}

        {isError && (
          <p className="text-xs text-muted-foreground">
            Could not load the tenant&apos;s roles.
          </p>
        )}

        {!isLoading && !isError && (
          <div className="space-y-1.5">
            {allRoles.map((role) => {
              const on = heldSet.has(role.name);
              const allowed = grantable(role);
              const busy = pending === role.name;
              return (
                <div key={role.id} className="flex items-start gap-2">
                  <Checkbox
                    id={`detail-${role.name}`}
                    className="mt-0.5"
                    disabled={!allowed || busy || mut.isPending}
                    checked={on}
                    onCheckedChange={(c) =>
                      mut.mutate({ role: role.name, on: !!c })
                    }
                  />
                  <div className="min-w-0 flex-1">
                    <Label
                      htmlFor={`detail-${role.name}`}
                      className={`font-normal ${allowed ? "" : "text-muted-foreground"}`}
                    >
                      {role.name}
                    </Label>
                    <p className="mt-0.5 font-mono text-[10px] leading-relaxed text-muted-foreground">
                      {role.permissions.map((p) => p.key).join(" · ") ||
                        "no permissions"}
                    </p>
                    {!allowed && (
                      <p className="mt-0.5 text-[10px] text-amber-600 dark:text-amber-500">
                        You do not hold {missing(role).join(", ")}.
                      </p>
                    )}
                  </div>
                </div>
              );
            })}

            <p className="pt-2 text-[10px] text-muted-foreground">
              <code className="font-mono">IdentitySelf</code> is granted to every
              identity and cannot be revoked.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function IdentityDetailClient({
  tenantId,
  identityId,
  poolId,
}: IdentityDetailClientProps) {
  const router = useRouter();
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [resettingPw, setResettingPw] = useState(false);
  const [resettingMfa, setResettingMfa] = useState(false);

  const { data: identity, isLoading, isError, error } = useQuery({
    queryKey: ["identity", tenantId, identityId, poolId ?? null],
    queryFn: () =>
      resolveIdentity(tenantId, identityId, poolId, () =>
        qc.fetchQuery(poolsQuery)
      ),
  });

  // Kind of directory this identity sits in. Roles are a console concern, so
  // they are offered for staff only; when pools can't be read (no TenantRead)
  // the absence of a `?pool=` is the same signal, since that means the caller's
  // own — staff — pool answered.
  const { data: pools } = useQuery({ ...poolsQuery, retry: false });
  const pool = pools?.find((p) => p.id === identity?.pool_id);
  const isStaff = pool ? pool.kind === "staff" : !poolId;
  const backHref = isStaff
    ? "/tenant"
    : `/identities${identity ? `?pool=${identity.pool_id}` : ""}`;
  const backLabel = isStaff ? "Tenant" : "Customers";

  const notFound =
    isError && error instanceof ApiError && error.status === 404;

  if (isLoading) {
    return (
      <div className="p-8 space-y-6">
        <div className="h-8 w-48 animate-pulse rounded-md bg-muted" />
        <div className="h-40 animate-pulse rounded-md bg-muted" />
        <div className="h-64 animate-pulse rounded-md bg-muted" />
      </div>
    );
  }

  if (isError || !identity) {
    return (
      <div className="p-8 space-y-6">
        <Link
          href={backHref}
          className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" />
          {backLabel}
        </Link>
        <Alert variant={notFound ? "default" : "destructive"}>
          <AlertDescription>
            {notFound
              ? "This identity doesn't exist — it may have been deleted."
              : "Failed to load identity."}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  const fullName =
    [identity.first_name, identity.last_name].filter(Boolean).join(" ") || null;
  const initials = (fullName ?? identity.email)
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase())
    .join("");
  const isActive = identity.status.toLowerCase() === "active";

  return (
    <div className="p-8 space-y-6">
      {/* Breadcrumb */}
      <Link
        href={backHref}
        className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" />
        {backLabel}
      </Link>

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b pb-6">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">
            {initials}
          </div>
          <div>
            <h1 className="text-xl font-bold">{identity.email}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              {fullName && (
                <span className="text-sm text-muted-foreground">{fullName}</span>
              )}
              <Badge variant="outline">{identity.kind}</Badge>
              <Badge variant={isStaff ? "default" : "outline"}>
                {pool ? pool.name : isStaff ? "Administrator" : "Customer"}
              </Badge>
              <Badge variant={isActive ? "success" : "warning"}>
                {identity.status}
              </Badge>
              {identity.email_verified ? (
                <Badge variant="success">Email verified</Badge>
              ) : (
                <Badge variant="secondary">Email unverified</Badge>
              )}
            </div>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
            <Pencil className="mr-2 h-3.5 w-3.5" />
            Edit
          </Button>
          <Button variant="outline" size="sm" onClick={() => setResettingPw(true)}>
            <KeyRound className="mr-2 h-3.5 w-3.5" />
            Reset password
          </Button>
          <Button variant="outline" size="sm" onClick={() => setResettingMfa(true)}>
            <ShieldOff className="mr-2 h-3.5 w-3.5" />
            Reset MFA
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-destructive hover:text-destructive"
            onClick={() => setDeleting(true)}
          >
            <Trash2 className="mr-2 h-3.5 w-3.5" />
            Delete
          </Button>
        </div>
      </div>

      {/* Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Overview</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-x-8 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Identity ID">
              <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                <span className="break-all">{identity.id}</span>
                <CopyButton value={identity.id} label="Identity ID" />
              </span>
            </Field>
            <Field label="Username">
              <span className="break-all font-mono text-xs">
                {identity.username}
              </span>
            </Field>
            <Field label="Email">
              <span className="inline-flex items-center gap-1.5 break-all">
                {identity.email}
                <CopyButton value={identity.email} label="Email" />
              </span>
            </Field>
            <Field label="First name">
              {identity.first_name ?? (
                <span className="text-muted-foreground">—</span>
              )}
            </Field>
            <Field label="Last name">
              {identity.last_name ?? (
                <span className="text-muted-foreground">—</span>
              )}
            </Field>
            <Field label="Tenant ID">
              <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                <span className="break-all">{identity.tenant_id}</span>
                <CopyButton value={identity.tenant_id} label="Tenant ID" />
              </span>
            </Field>
            <Field label="Created">
              <span
                className="text-muted-foreground"
                title={identity.created_at}
              >
                {new Date(identity.created_at).toLocaleString()}
              </span>
            </Field>
            <Field label="Updated">
              <span
                className="text-muted-foreground"
                title={identity.updated_at}
              >
                {new Date(identity.updated_at).toLocaleString()}
              </span>
            </Field>
          </div>
        </CardContent>
      </Card>

      {/* Roles — administrators only. A customer has no console to use them in,
          and the console must not be a route to granting one. */}
      {isStaff ? (
        <RolesCard identityId={identity.id} />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Console access</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              This identity belongs to{" "}
              <span className="font-medium text-foreground">
                {pool?.name ?? "a customer directory"}
              </span>
              , so it signs in to your applications rather than to this console
              and holds no administrative roles. Administrators are managed under{" "}
              <Link href="/tenant" className="underline underline-offset-4">
                Tenant
              </Link>
              .
            </p>
          </CardContent>
        </Card>
      )}

      {/* Metadata / custom attributes */}
      <div className="grid gap-6 lg:grid-cols-2">
        <EditableJsonCard
          title="Metadata"
          field="metadata"
          data={identity.metadata}
          emptyLabel="No metadata set."
          tenantId={tenantId}
          identityId={identity.id}
          poolId={identity.pool_id}
        />
        <EditableJsonCard
          title="Custom attributes"
          field="custom_attributes"
          data={identity.custom_attributes}
          emptyLabel="No custom attributes set."
          tenantId={tenantId}
          identityId={identity.id}
          poolId={identity.pool_id}
        />
      </div>

      {/* Activity */}
      <RecentActivity tenantId={tenantId} identityId={identity.id} />

      {editing && (
        <EditIdentityDialog
          tenantId={tenantId}
          identity={identity}
          poolId={identity.pool_id}
          open={editing}
          onClose={() => setEditing(false)}
        />
      )}
      {deleting && (
        <DeleteIdentityDialog
          tenantId={tenantId}
          identity={identity}
          poolId={identity.pool_id}
          open={deleting}
          onClose={() => setDeleting(false)}
          onDeleted={() => router.replace(backHref)}
        />
      )}
      {resettingPw && (
        <ResetPasswordDialog
          identity={identity}
          poolId={identity.pool_id}
          open={resettingPw}
          onClose={() => setResettingPw(false)}
        />
      )}
      {resettingMfa && (
        <ResetMfaDialog
          identity={identity}
          poolId={identity.pool_id}
          open={resettingMfa}
          onClose={() => setResettingMfa(false)}
        />
      )}
    </div>
  );
}
