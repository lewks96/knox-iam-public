"use client";

import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, User } from "lucide-react";
import { poolsQuery, resolveIdentity } from "@/lib/api/identity-resolve";
import { ApiError } from "@/lib/api-client";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/lib/utils";

/**
 * Resolves an identity-actor GUID to a human-readable email, and offers a
 * click-through mini profile with a link to the full identity page.
 *
 * Identity lookups are cached per (tenant, id) — a page of audit events
 * usually involves a handful of unique actors, so this costs a few requests
 * at most. Deleted identities and missing scopes degrade to the plain GUID.
 *
 * An actor is not necessarily an administrator: a customer signing in to a
 * tenant's own application is recorded the same way, and lives in a directory
 * the staff-scoped lookup cannot see. Hence the resolver rather than a plain
 * fetch — otherwise those actors would all read as deleted.
 */

interface ActorIdentityProps {
  tenantId: string;
  actorId: string;
}

function useActorIdentity(tenantId: string, actorId: string) {
  const qc = useQueryClient();
  return useQuery({
    queryKey: ["identity", tenantId, actorId],
    queryFn: () =>
      resolveIdentity(tenantId, actorId, undefined, () =>
        qc.fetchQuery(poolsQuery)
      ),
    staleTime: 5 * 60 * 1000,
    retry: (failureCount, error) => {
      // 403 (no IdentityRead) and 404 (deleted) are permanent — don't retry.
      if (error instanceof ApiError && (error.status === 403 || error.status === 404)) {
        return false;
      }
      return failureCount < 1;
    },
  });
}

export function ActorPopover({ tenantId, actorId }: ActorIdentityProps) {
  const { data: identity, isLoading, error } = useActorIdentity(tenantId, actorId);

  const notFound = error instanceof ApiError && error.status === 404;
  const isActive = identity?.status.toLowerCase() === "active";
  const fullName = identity
    ? [identity.first_name, identity.last_name].filter(Boolean).join(" ") || null
    : null;

  return (
    <Popover>
      <PopoverTrigger
        // Rows expand on click — keep actor clicks scoped to the popover.
        onClick={(e) => e.stopPropagation()}
        className={cn(
          "inline-flex max-w-48 items-center gap-1.5 text-xs",
          "text-muted-foreground decoration-muted-foreground/50 decoration-dotted underline-offset-2 transition-colors hover:text-foreground hover:underline"
        )}
        title={actorId}
      >
        <User className="h-3.5 w-3.5 shrink-0" />
        <span className={cn("truncate", !identity && "font-mono")}>
          {identity ? identity.email : `${actorId.slice(0, 8)}…`}
        </span>
      </PopoverTrigger>
      <PopoverContent onClick={(e) => e.stopPropagation()}>
        {isLoading ? (
          <div className="space-y-2">
            <div className="h-4 w-40 animate-pulse rounded bg-muted" />
            <div className="h-3 w-24 animate-pulse rounded bg-muted" />
          </div>
        ) : identity ? (
          <div className="space-y-3">
            <div>
              <p className="break-all text-sm font-semibold">{identity.email}</p>
              {fullName && (
                <p className="mt-0.5 text-xs text-muted-foreground">{fullName}</p>
              )}
            </div>
            <div className="flex flex-wrap gap-1.5">
              <Badge variant="outline">{identity.kind}</Badge>
              <Badge variant={isActive ? "success" : "warning"}>
                {identity.status}
              </Badge>
            </div>
            <div className="space-y-1 text-xs text-muted-foreground">
              <p className="break-all font-mono">{identity.id}</p>
              <p>
                Created {new Date(identity.created_at).toLocaleDateString()}
              </p>
            </div>
            <Link
              href={`/identities/${identity.id}`}
              className="inline-flex items-center gap-1 text-xs font-medium text-foreground underline-offset-2 hover:underline"
            >
              View full profile
              <ArrowUpRight className="h-3 w-3" />
            </Link>
          </div>
        ) : (
          <div className="space-y-2">
            <p className="break-all font-mono text-xs">{actorId}</p>
            <p className="text-xs text-muted-foreground">
              {notFound
                ? "This identity no longer exists — it may have been deleted."
                : "Couldn't load identity details."}
            </p>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
