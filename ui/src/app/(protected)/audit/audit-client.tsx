"use client";

import { Fragment, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AppWindow,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Ghost,
  RefreshCw,
  ShieldAlert,
  User,
  X,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import {
  AUDIT_EVENT_TYPES,
  listAuditEvents,
  type AuditEvent,
} from "@/lib/api/audit";
import { ApiError } from "@/lib/api-client";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { poolsQuery, resolveIdentity } from "@/lib/api/identity-resolve";
import { ActorPopover } from "./actor-popover";

const PAGE_SIZE = 50;

// ── Formatting helpers ──────────────────────────────────────────────────

const TIME_RANGES = [
  { value: "1h", label: "Last hour", ms: 60 * 60 * 1000 },
  { value: "24h", label: "Last 24 hours", ms: 24 * 60 * 60 * 1000 },
  { value: "7d", label: "Last 7 days", ms: 7 * 24 * 60 * 60 * 1000 },
  { value: "30d", label: "Last 30 days", ms: 30 * 24 * 60 * 60 * 1000 },
  { value: "all", label: "All time", ms: 0 },
] as const;

type TimeRange = (typeof TIME_RANGES)[number]["value"];

function rangeToFrom(range: TimeRange): string | undefined {
  const spec = TIME_RANGES.find((r) => r.value === range);
  if (!spec || spec.ms === 0) return undefined;
  return new Date(Date.now() - spec.ms).toISOString();
}

function formatTime(iso: string): { time: string; date: string; full: string } {
  const d = new Date(iso);
  const today = new Date();
  const isToday = d.toDateString() === today.toDateString();
  return {
    time: d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
    date: isToday
      ? "Today"
      : d.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    full: d.toLocaleString(),
  };
}

/** "auth.login" → ["auth", "login"]; unknown shapes degrade gracefully. */
function splitEventType(eventType: string): [string, string] {
  const idx = eventType.indexOf(".");
  if (idx === -1) return ["", eventType];
  return [eventType.slice(0, idx), eventType.slice(idx + 1)];
}

// ── Small presentational pieces ─────────────────────────────────────────

/** Status is never conveyed by color alone: icon + label always. */
function OutcomeBadge({ outcome }: { outcome: AuditEvent["outcome"] }) {
  const spec =
    outcome === "success"
      ? {
          icon: CheckCircle2,
          label: "Success",
          className:
            "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
        }
      : outcome === "denied"
        ? {
            icon: ShieldAlert,
            label: "Denied",
            className: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
          }
        : {
            icon: XCircle,
            label: "Failure",
            className: "bg-destructive/10 text-destructive",
          };
  const Icon = spec.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-4xl px-2 py-0.5 text-xs font-medium",
        spec.className
      )}
    >
      <Icon className="h-3 w-3" />
      {spec.label}
    </span>
  );
}

function EventTypeCell({ eventType }: { eventType: string }) {
  const [category, action] = splitEventType(eventType);
  return (
    <span className="inline-flex items-baseline gap-1.5 font-mono text-[13px]">
      {category && (
        <span className="text-muted-foreground/70">{category}.</span>
      )}
      <span className="font-medium text-foreground">{action}</span>
    </span>
  );
}

const ACTOR_ICONS = { identity: User, client: AppWindow, anonymous: Ghost };

function ActorCell({ event, tenantId }: { event: AuditEvent; tenantId: string }) {
  // Identity actors resolve to a clickable mini profile; clients and
  // anonymous actors have nothing further to show.
  if (event.actor_type === "identity" && event.actor_id) {
    return <ActorPopover tenantId={tenantId} actorId={event.actor_id} />;
  }
  const Icon = ACTOR_ICONS[event.actor_type] ?? Ghost;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
      <Icon className="h-3.5 w-3.5 shrink-0" />
      {event.actor_id ? (
        <span className="truncate font-mono" title={event.actor_id}>
          {event.actor_id.slice(0, 8)}…
        </span>
      ) : (
        <span className="italic">anonymous</span>
      )}
    </span>
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex items-center gap-1 text-muted-foreground transition-colors hover:text-foreground"
      title={`Copy ${label}`}
      onClick={async (e) => {
        e.stopPropagation();
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

function DetailField({
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
      <div className="mt-1 text-xs">{children}</div>
    </div>
  );
}

function EventDetails({ event, tenantId }: { event: AuditEvent; tenantId: string }) {
  const hasDetails = event.details && Object.keys(event.details).length > 0;
  return (
    // whitespace-normal: this renders inside a TableCell, which sets
    // whitespace-nowrap - without the reset, long values (user agents)
    // refuse to wrap and overflow into the neighboring grid column.
    <div className="grid gap-x-8 gap-y-4 whitespace-normal bg-muted/40 px-6 py-4 sm:grid-cols-2 lg:grid-cols-3">
      <DetailField label="Event ID">
        <span className="inline-flex items-center gap-1.5 font-mono">
          <span className="break-all">{event.id}</span>
          <CopyButton value={event.id} label="Event ID" />
        </span>
      </DetailField>

      <DetailField label="Correlation ID">
        {event.correlation_id ? (
          <span className="inline-flex items-center gap-1.5 font-mono">
            <span className="break-all">{event.correlation_id}</span>
            <CopyButton value={event.correlation_id} label="Correlation ID" />
          </span>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </DetailField>

      <DetailField label="Actor">
        {event.actor_id ? (
          <span className="inline-flex flex-wrap items-center gap-1.5 font-mono">
            <span className="break-all">{event.actor_id}</span>
            <CopyButton value={event.actor_id} label="Actor ID" />
            {event.actor_type === "identity" && (
              <Link
                href={`/identities/${event.actor_id}`}
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-0.5 font-sans font-medium text-foreground underline-offset-2 hover:underline"
              >
                View profile
                <ArrowUpRight className="h-3 w-3" />
              </Link>
            )}
          </span>
        ) : (
          <span className="text-muted-foreground">anonymous</span>
        )}
      </DetailField>

      {event.target_type && (
        <DetailField label={`Target (${event.target_type})`}>
          <span className="break-all font-mono">{event.target_id ?? "—"}</span>
        </DetailField>
      )}

      <DetailField label="User agent">
        <span className="break-all text-muted-foreground">
          {event.user_agent ?? "—"}
        </span>
      </DetailField>

      <DetailField label="Occurred at">
        <span className="text-muted-foreground">
          {new Date(event.occurred_at).toISOString()}
        </span>
      </DetailField>

      {hasDetails && (
        <div className="sm:col-span-2 lg:col-span-3">
          <DetailField label="Details">
            <pre className="mt-1 overflow-x-auto rounded-md border bg-background px-3 py-2 font-mono text-xs leading-relaxed">
              {JSON.stringify(event.details, null, 2)}
            </pre>
          </DetailField>
        </div>
      )}
    </div>
  );
}

// ── Main page ───────────────────────────────────────────────────────────

/** Chip shown when the log is filtered to a single actor (via ?actor=). */
function ActorFilterChip({
  tenantId,
  actorId,
  onClear,
}: {
  tenantId: string;
  actorId: string;
  onClear: () => void;
}) {
  // Best-effort email resolution; the raw GUID is a fine fallback. Shares both
  // the cache key and the across-directories resolution with the actor popover,
  // so an actor reads the same either way.
  const qc = useQueryClient();
  const { data: identity } = useQuery({
    queryKey: ["identity", tenantId, actorId],
    queryFn: () =>
      resolveIdentity(tenantId, actorId, undefined, () =>
        qc.fetchQuery(poolsQuery)
      ),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });

  return (
    <span className="inline-flex h-9 items-center gap-1.5 rounded-lg border bg-muted/40 px-3 text-xs">
      <User className="h-3.5 w-3.5 text-muted-foreground" />
      <span className="text-muted-foreground">Actor:</span>
      <span className={cn("font-medium", !identity && "font-mono")} title={actorId}>
        {identity?.email ?? `${actorId.slice(0, 8)}…`}
      </span>
      <button
        type="button"
        onClick={onClear}
        title="Clear actor filter"
        className="ml-0.5 text-muted-foreground transition-colors hover:text-foreground"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </span>
  );
}

interface AuditPageClientProps {
  tenantId: string;
  /** Pre-filter the log to one actor (from the ?actor= search param). */
  initialActorId?: string;
}

export function AuditPageClient({ tenantId, initialActorId }: AuditPageClientProps) {
  const router = useRouter();
  const [range, setRange] = useState<TimeRange>("24h");
  const [eventType, setEventType] = useState<string>("all");
  const [outcome, setOutcome] = useState<string>("all");
  const [actorId, setActorId] = useState<string | undefined>(initialActorId);
  const [live, setLive] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  function clearActorFilter() {
    setActorId(undefined);
    router.replace(`/audit`, { scroll: false });
  }

  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    isRefetching,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ["audit-events", tenantId, range, eventType, outcome, actorId],
    queryFn: ({ pageParam }) =>
      listAuditEvents(tenantId, {
        from: rangeToFrom(range),
        event_type: eventType === "all" ? undefined : eventType,
        outcome: outcome === "all" ? undefined : outcome,
        actor_id: actorId,
        limit: PAGE_SIZE,
        cursor: pageParam,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    refetchInterval: live ? 10_000 : false,
    placeholderData: (prev) => prev,
  });

  const events = useMemo(
    () => data?.pages.flatMap((p) => p.items) ?? [],
    [data]
  );

  const forbidden = isError && error instanceof ApiError && error.status === 403;

  function toggleExpanded(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b pb-6">
        <div>
          <h1 className="text-xl font-bold">Audit Log</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Security events for this tenant — logins, MFA activity, token
            grants, and configuration changes.
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch id="live" checked={live} onCheckedChange={setLive} />
            <Label
              htmlFor="live"
              className={cn(
                "inline-flex cursor-pointer items-center gap-1.5 text-xs",
                live ? "text-foreground" : "text-muted-foreground"
              )}
            >
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  live ? "animate-pulse bg-emerald-500" : "bg-muted-foreground/40"
                )}
              />
              Live
            </Label>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isRefetching}
          >
            <RefreshCw
              className={cn("mr-2 h-3.5 w-3.5", isRefetching && "animate-spin")}
            />
            Refresh
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select
          value={range}
          onValueChange={(v) => setRange((v ?? "24h") as TimeRange)}
        >
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TIME_RANGES.map((r) => (
              <SelectItem key={r.value} value={r.value}>
                {r.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={eventType} onValueChange={(v) => setEventType(v ?? "all")}>
          <SelectTrigger className="w-56">
            <SelectValue placeholder="Event type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All events</SelectItem>
            {AUDIT_EVENT_TYPES.flatMap((group) => [
              <div
                key={group.group}
                className="px-2 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/70"
              >
                {group.group}
              </div>,
              ...group.types.map((t) => (
                <SelectItem key={t} value={t}>
                  <span className="font-mono text-xs">{t}</span>
                </SelectItem>
              )),
            ])}
          </SelectContent>
        </Select>

        <Select value={outcome} onValueChange={(v) => setOutcome(v ?? "all")}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Outcome" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All outcomes</SelectItem>
            <SelectItem value="success">Success</SelectItem>
            <SelectItem value="failure">Failure</SelectItem>
            <SelectItem value="denied">Denied</SelectItem>
          </SelectContent>
        </Select>

        {actorId && (
          <ActorFilterChip
            tenantId={tenantId}
            actorId={actorId}
            onClear={clearActorFilter}
          />
        )}

        <span className="ml-auto text-xs text-muted-foreground">
          {events.length} {events.length === 1 ? "event" : "events"} loaded
          {hasNextPage && " · more available"}
        </span>
      </div>

      {/* Errors */}
      {forbidden && (
        <Alert>
          <AlertDescription>
            Your session doesn&apos;t have the <code>AuditRead</code> scope.
            Ask an administrator for the <strong>AuditViewer</strong> role,
            then sign in again.
          </AlertDescription>
        </Alert>
      )}
      {isError && !forbidden && (
        <Alert variant="destructive">
          <AlertDescription>Failed to load audit events.</AlertDescription>
        </Alert>
      )}

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="h-11 animate-pulse rounded-md bg-muted" />
          ))}
        </div>
      ) : (
        !isError && (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead className="w-32">Time</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead className="text-right">IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={7}
                      className="py-12 text-center text-muted-foreground"
                    >
                      No events in this window.
                    </TableCell>
                  </TableRow>
                ) : (
                  events.map((event) => {
                    const t = formatTime(event.occurred_at);
                    const isOpen = expanded.has(event.id);
                    return (
                      <Fragment key={event.id}>
                        <TableRow
                          className="cursor-pointer"
                          onClick={() => toggleExpanded(event.id)}
                        >
                          <TableCell className="pr-0 text-muted-foreground">
                            {isOpen ? (
                              <ChevronDown className="h-3.5 w-3.5" />
                            ) : (
                              <ChevronRight className="h-3.5 w-3.5" />
                            )}
                          </TableCell>
                          <TableCell title={t.full}>
                            <span className="font-mono text-xs tabular-nums">
                              {t.time}
                            </span>
                            <span className="ml-1.5 text-[11px] text-muted-foreground">
                              {t.date}
                            </span>
                          </TableCell>
                          <TableCell>
                            <EventTypeCell eventType={event.event_type} />
                          </TableCell>
                          <TableCell>
                            <ActorCell event={event} tenantId={tenantId} />
                          </TableCell>
                          <TableCell className="max-w-44">
                            {event.target_id ? (
                              <span
                                className="block truncate text-xs text-muted-foreground"
                                title={`${event.target_type}: ${event.target_id}`}
                              >
                                {event.target_id}
                              </span>
                            ) : (
                              <span className="text-xs text-muted-foreground/50">
                                —
                              </span>
                            )}
                          </TableCell>
                          <TableCell>
                            <OutcomeBadge outcome={event.outcome} />
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs text-muted-foreground">
                            {event.ip ?? "—"}
                          </TableCell>
                        </TableRow>
                        {isOpen && (
                          <TableRow className="hover:bg-transparent">
                            <TableCell colSpan={7} className="p-0">
                              <EventDetails event={event} tenantId={tenantId} />
                            </TableCell>
                          </TableRow>
                        )}
                      </Fragment>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        )
      )}

      {/* Pagination */}
      {hasNextPage && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
          >
            {isFetchingNextPage ? "Loading…" : "Load older events"}
          </Button>
        </div>
      )}
    </div>
  );
}
