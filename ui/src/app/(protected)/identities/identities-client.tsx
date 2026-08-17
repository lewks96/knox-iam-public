"use client";

import { useState, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  Plus,
  Trash2,
  Pencil,
  Search,
  ChevronLeft,
  ChevronRight,
  X,
  FolderPlus,
  Users,
  KeyRound,
  ShieldOff,
} from "lucide-react";
import { listIdentities, type Identity } from "@/lib/api/identity";
import { listPools, customerPools } from "@/lib/api/pools";
import { ApiError } from "@/lib/api-client";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { CreatePoolDialog } from "@/components/pools/create-pool-dialog";
import {
  CreateIdentityDialog,
  EditIdentityDialog,
  DeleteIdentityDialog,
  ResetPasswordDialog,
  ResetMfaDialog,
} from "./identity-dialogs";

const PAGE_SIZE = 20;

// ── Customers ───────────────────────────────────────────────────────────

interface IdentitiesPageClientProps {
  tenantId: string;
  /** Directory to open, from `?pool=`. Lets links and the back button keep their place. */
  initialPoolId?: string;
}

/**
 * The end users of this tenant's applications.
 *
 * Every call here is explicitly scoped to a customer pool. That is the whole
 * point of the page: an identity request with no `pool_id` acts on the caller's
 * own directory — the staff pool — so leaving it off would quietly turn this
 * into administrator management. Administrators live on the Tenant page, where
 * roles can be granted; nothing on this page can grant one.
 */
export function IdentitiesPageClient({
  tenantId,
  initialPoolId,
}: IdentitiesPageClientProps) {
  const router = useRouter();
  const [page, setPage] = useState(1);
  const [queryInput, setQueryInput] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "inactive">("all");
  const [creating, setCreating] = useState(false);
  const [creatingPool, setCreatingPool] = useState(false);
  const [editing, setEditing] = useState<Identity | null>(null);
  const [deleting, setDeleting] = useState<Identity | null>(null);
  const [resettingPw, setResettingPw] = useState<Identity | null>(null);
  const [resettingMfa, setResettingMfa] = useState<Identity | null>(null);
  const [chosenPoolId, setChosenPoolId] = useState<string | null>(
    initialPoolId ?? null
  );

  const {
    data: pools,
    isLoading: poolsLoading,
    isError: poolsError,
    error: poolsErrorObj,
  } = useQuery({
    queryKey: ["pools"],
    queryFn: listPools,
    staleTime: 5 * 60 * 1000,
  });

  const directories = customerPools(pools ?? []);
  // The chosen directory if it still exists, else the first — a pool id from a
  // stale link should not leave the page pointing at nothing.
  const poolId =
    directories.find((p) => p.id === chosenPoolId)?.id ?? directories[0]?.id ?? null;

  function selectPool(id: string | null) {
    if (!id) return;
    setChosenPoolId(id);
    setPage(1);
    router.replace(`/identities?pool=${id}`, { scroll: false });
  }

  const { data, isLoading, isError } = useQuery({
    queryKey: ["identities", tenantId, poolId, page, query, statusFilter],
    queryFn: () =>
      listIdentities(tenantId, {
        poolId: poolId!,
        page,
        page_size: PAGE_SIZE,
        query: query || undefined,
        status: statusFilter === "all" ? undefined : statusFilter,
      }),
    enabled: !!poolId,
    placeholderData: (prev) => prev,
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  const handleSearch = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      setQuery(queryInput);
      setPage(1);
    },
    [queryInput]
  );

  function clearSearch() {
    setQueryInput("");
    setQuery("");
    setPage(1);
  }

  // Listing directories needs `TenantRead`. Without it there is no safe way to
  // scope the page, so say so rather than falling back to the staff pool.
  const poolsForbidden =
    poolsError && poolsErrorObj instanceof ApiError && poolsErrorObj.status === 403;

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between gap-4 border-b pb-6">
        <div>
          <h1 className="text-xl font-bold">Customers</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            End users of this tenant&apos;s applications. Console administrators
            are managed under{" "}
            <Link href="/tenant" className="underline underline-offset-4">
              Tenant
            </Link>
            .
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button
            variant="outline"
            onClick={() => setCreatingPool(true)}
            disabled={poolsLoading || !!poolsForbidden}
          >
            <FolderPlus className="mr-2 h-4 w-4" />
            New directory
          </Button>
          <Button onClick={() => setCreating(true)} disabled={!poolId}>
            <Plus className="mr-2 h-4 w-4" />
            New customer
          </Button>
        </div>
      </div>

      {poolsForbidden ? (
        <Alert variant="destructive">
          <AlertDescription>
            Your session doesn&apos;t have the <code>TenantRead</code> scope, so
            customer directories can&apos;t be listed.
          </AlertDescription>
        </Alert>
      ) : poolsError ? (
        <Alert variant="destructive">
          <AlertDescription>Failed to load customer directories.</AlertDescription>
        </Alert>
      ) : poolsLoading ? (
        <div className="h-12 animate-pulse rounded-md bg-muted" />
      ) : directories.length === 0 ? (
        <EmptyDirectories onCreate={() => setCreatingPool(true)} />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <Select
              value={poolId ?? undefined}
              onValueChange={selectPool}
              items={Object.fromEntries(directories.map((p) => [p.id, p.name]))}
            >
              <SelectTrigger className="w-64">
                <SelectValue placeholder="Directory" />
              </SelectTrigger>
              <SelectContent>
                {directories.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <form onSubmit={handleSearch} className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  className="w-72 pl-8"
                  placeholder="Search by email or username…"
                  value={queryInput}
                  onChange={(e) => setQueryInput(e.target.value)}
                />
                {queryInput && (
                  <button
                    type="button"
                    onClick={clearSearch}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
              <Button type="submit" variant="secondary" size="sm">
                Search
              </Button>
            </form>

            <Select
              value={statusFilter}
              onValueChange={(v) => {
                setStatusFilter(v as typeof statusFilter);
                setPage(1);
              }}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>

            {data && (
              <span className="ml-auto text-xs text-muted-foreground">
                {data.total} {data.total === 1 ? "customer" : "customers"}
              </span>
            )}
          </div>

          {isError && (
            <Alert variant="destructive">
              <AlertDescription>Failed to load customers.</AlertDescription>
            </Alert>
          )}

          {isLoading ? (
            <div className="space-y-2">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-12 animate-pulse rounded-md bg-muted" />
              ))}
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Email</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Email verified</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data?.items?.length ?? 0) === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="py-12 text-center text-muted-foreground">
                        No customers in this directory yet.
                      </TableCell>
                    </TableRow>
                  ) : (
                    data?.items.map((identity) => (
                      <TableRow key={identity.id}>
                        <TableCell className="font-medium">
                          <Link
                            href={`/identities/${identity.id}?pool=${identity.pool_id}`}
                            className="hover:underline"
                          >
                            {identity.email}
                          </Link>
                        </TableCell>
                        <TableCell>
                          {[identity.first_name, identity.last_name].filter(Boolean).join(" ") || "—"}
                        </TableCell>
                        <TableCell>
                          {identity.email_verified ? (
                            <Badge variant="success">Verified</Badge>
                          ) : (
                            <Badge variant="secondary">Unverified</Badge>
                          )}
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
                            <Button variant="ghost" size="icon" className="h-8 w-8" title="Edit" onClick={() => setEditing(identity)}>
                              <Pencil className="h-3.5 w-3.5" />
                            </Button>
                            <Button variant="ghost" size="icon" className="h-8 w-8" title="Reset password" onClick={() => setResettingPw(identity)}>
                              <KeyRound className="h-3.5 w-3.5" />
                            </Button>
                            <Button variant="ghost" size="icon" className="h-8 w-8" title="Reset two-factor" onClick={() => setResettingMfa(identity)}>
                              <ShieldOff className="h-3.5 w-3.5" />
                            </Button>
                            <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" title="Delete" onClick={() => setDeleting(identity)}>
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

          {data && data.total > PAGE_SIZE && (
            <div className="flex items-center justify-end gap-3">
              <span className="text-xs text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <Button variant="outline" size="icon" className="h-8 w-8" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="icon" className="h-8 w-8" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          )}
        </>
      )}

      {poolId && (
        <CreateIdentityDialog
          tenantId={tenantId}
          poolId={poolId}
          open={creating}
          onClose={() => setCreating(false)}
          title="Create customer"
          description={`Added to ${directories.find((p) => p.id === poolId)?.name}. Customers sign in to your applications, never to this console, so they hold no roles.`}
        />
      )}

      <CreatePoolDialog
        open={creatingPool}
        onClose={() => setCreatingPool(false)}
        onCreated={(pool) => selectPool(pool.id)}
      />

      {editing && (
        <EditIdentityDialog
          tenantId={tenantId}
          identity={editing}
          poolId={editing.pool_id}
          open={!!editing}
          onClose={() => setEditing(null)}
        />
      )}

      {deleting && (
        <DeleteIdentityDialog
          tenantId={tenantId}
          identity={deleting}
          poolId={deleting.pool_id}
          open={!!deleting}
          onClose={() => setDeleting(null)}
        />
      )}

      {resettingPw && (
        <ResetPasswordDialog
          identity={resettingPw}
          poolId={resettingPw.pool_id}
          open={!!resettingPw}
          onClose={() => setResettingPw(null)}
        />
      )}

      {resettingMfa && (
        <ResetMfaDialog
          identity={resettingMfa}
          poolId={resettingMfa.pool_id}
          open={!!resettingMfa}
          onClose={() => setResettingMfa(null)}
        />
      )}
    </div>
  );
}

function EmptyDirectories({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="flex flex-col items-center gap-4 rounded-xl border border-dashed py-16 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-muted text-muted-foreground">
        <Users className="h-6 w-6" />
      </div>
      <div className="max-w-md space-y-1">
        <p className="text-sm font-semibold">No customer directories yet</p>
        <p className="text-sm text-muted-foreground">
          Customers live in their own directory, separate from the administrators
          who use this console. Create one to start adding end users.
        </p>
      </div>
      <Button onClick={onCreate}>
        <FolderPlus className="mr-2 h-4 w-4" />
        New directory
      </Button>
    </div>
  );
}
