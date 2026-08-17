"use client";

import { useQuery } from "@tanstack/react-query";
import { getVersion } from "@/lib/api/system";

const UI_VERSION = process.env.NEXT_PUBLIC_UI_VERSION ?? "dev";

function formatBuildTime(raw: string): string {
  // Server emits either "@<unix-seconds>" (no chrono dep) or an RFC3339 string.
  if (raw.startsWith("@")) {
    const secs = Number(raw.slice(1));
    if (Number.isFinite(secs)) {
      return new Date(secs * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
    }
  }
  return raw;
}

export function VersionFooter() {
  const { data, isError } = useQuery({
    queryKey: ["sys", "version"],
    queryFn: getVersion,
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });

  return (
    <footer className="flex h-7 shrink-0 items-center justify-between border-t bg-background px-4 font-mono text-[10px] text-muted-foreground/70">
      <span>UI {UI_VERSION}</span>
      <span>
        {isError || !data
          ? "server: offline"
          : `server ${data.version} · ${data.git_sha} · ${formatBuildTime(data.build_time)}`}
      </span>
    </footer>
  );
}
