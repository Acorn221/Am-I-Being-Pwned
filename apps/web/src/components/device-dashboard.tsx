import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Puzzle, RefreshCw, ShieldCheck, ShieldAlert } from "lucide-react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Card } from "@amibeingpwned/ui/card";
import { ScoreArc } from "@amibeingpwned/ui/score-arc";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";

import { useTRPC } from "~/lib/trpc";

const WEB_SESSION_KEY = "aibp_web_session";

type RiskBucket = "critical" | "high" | "medium" | "low" | "clean" | "unknown";

function bucketFromLevel(riskLevel: string | null | undefined, isFlagged: boolean | null): RiskBucket {
  if (isFlagged) return "critical";
  const level = riskLevel ?? "unknown";
  if (level === "critical" || level === "high" || level === "medium" || level === "low" || level === "clean") {
    return level as RiskBucket;
  }
  return "unknown";
}

const BUCKET_SCORE: Record<RiskBucket, number> = {
  critical: 0,
  high: 25,
  medium: 55,
  low: 80,
  clean: 100,
  unknown: 90,
};

const BUCKET_COLOR: Record<RiskBucket, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#60a5fa",
  clean: "#10b981",
  unknown: "#6b7280",
};

const BUCKET_LABEL: Record<RiskBucket, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  clean: "Clean",
  unknown: "Unscanned",
};

function calcScore(buckets: Record<RiskBucket, number>, total: number): number {
  if (total === 0) return 100;
  const sum = (Object.keys(buckets) as RiskBucket[]).reduce(
    (acc, key) => acc + buckets[key] * BUCKET_SCORE[key],
    0,
  );
  return Math.round(sum / total);
}

function scoreLabel(score: number): string {
  if (score >= 80) return "All clear";
  if (score >= 60) return "Low risk";
  if (score >= 40) return "Needs attention";
  return "At risk";
}


interface DeviceDashboardProps {
  token: string;
}

export function DeviceDashboard({ token }: DeviceDashboardProps) {
  const trpc = useTRPC();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const wst = params.get("wst");
    if (wst) {
      localStorage.setItem(WEB_SESSION_KEY, wst);
      const url = new URL(window.location.href);
      url.searchParams.delete("wst");
      window.history.replaceState(null, "", url.pathname + (url.search || ""));
    }
  }, []);

  const { data, isPending, error } = useQuery(
    trpc.devices.getWebSession.queryOptions({ token }),
  );

  if (isPending) {
    return (
      <div className="bg-background flex min-h-screen items-center justify-center">
        <RefreshCw className="h-6 w-6 animate-spin opacity-30" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-background flex min-h-screen items-center justify-center">
        <div className="text-center space-y-2 max-w-sm px-4">
          <ShieldAlert className="h-10 w-10 text-muted-foreground mx-auto mb-4" />
          <p className="text-foreground font-semibold">Session expired</p>
          <p className="text-muted-foreground text-sm">
            Your session has expired or is invalid. Re-enroll from your invite link.
          </p>
        </div>
      </div>
    );
  }

  const extensions = data.extensions;
  const orgName = data.orgName ?? "Your organization";

  const buckets: Record<RiskBucket, number> = {
    critical: 0, high: 0, medium: 0, low: 0, clean: 0, unknown: 0,
  };
  for (const ext of extensions) {
    buckets[bucketFromLevel(ext.riskLevel, ext.isFlagged)]++;
  }
  const score = calcScore(buckets, extensions.length);
  const hasIssues = buckets.critical > 0 || buckets.high > 0 || buckets.medium > 0;

  const riskChips: { bucket: RiskBucket; count: number }[] = (
    ["critical", "high", "medium", "low", "clean", "unknown"] as RiskBucket[]
  )
    .map((b) => ({ bucket: b, count: buckets[b] }))
    .filter(({ count }) => count > 0);

  return (
    <div className="bg-background min-h-screen">
      {/* Header */}
      <header className="border-border/50 flex h-14 items-center border-b px-6 gap-3">
        <div className="flex items-center gap-2 flex-1">
          <img src="/logo.png" alt="" className="h-6 w-auto opacity-90" />
          <span className="text-foreground text-sm font-semibold tracking-tight">
            Am I Being Pwned?
          </span>
        </div>
        <span className="text-muted-foreground text-xs border border-border/50 rounded-full px-3 py-1">
          {orgName}
        </span>
      </header>

      <div className="mx-auto max-w-2xl px-6 py-10 space-y-10">
        {/* Score hero */}
        <div className="flex flex-col items-center gap-3">
          <ScoreArc score={score} className="w-48 h-48" />
          <div className="text-center space-y-1">
            <div className="flex items-center justify-center gap-1.5">
              {hasIssues
                ? <ShieldAlert className="h-4 w-4 text-orange-400" />
                : <ShieldCheck className="h-4 w-4 text-emerald-400" />
              }
              <span className="text-sm font-medium text-foreground">
                {scoreLabel(score)}
              </span>
            </div>
            <p className="text-muted-foreground text-xs">
              {extensions.length} extension{extensions.length !== 1 ? "s" : ""} scanned
            </p>
          </div>

          {/* Risk breakdown chips */}
          {riskChips.length > 0 && (
            <div className="flex flex-wrap justify-center gap-2 mt-1">
              {riskChips.map(({ bucket, count }) => (
                <span
                  key={bucket}
                  className="inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium border"
                  style={{
                    color: BUCKET_COLOR[bucket],
                    borderColor: `${BUCKET_COLOR[bucket]}30`,
                    backgroundColor: `${BUCKET_COLOR[bucket]}10`,
                  }}
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ backgroundColor: BUCKET_COLOR[bucket] }}
                  />
                  {count} {BUCKET_LABEL[bucket]}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Extensions table */}
        <section className="space-y-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Puzzle className="h-4 w-4 text-muted-foreground" />
            Extensions
          </h2>

          <Card className="overflow-hidden border-border/50 p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-border/50 hover:bg-transparent">
                  <TableHead className="text-xs font-medium text-muted-foreground/70 pl-4">
                    Extension
                  </TableHead>
                  <TableHead className="text-xs font-medium text-muted-foreground/70">
                    Risk
                  </TableHead>
                  <TableHead className="text-xs font-medium text-muted-foreground/70">
                    Status
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {extensions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="py-16 text-center">
                      <div className="flex flex-col items-center gap-2">
                        <Puzzle className="h-8 w-8 text-muted-foreground/30" />
                        <p className="text-muted-foreground text-sm">No extensions synced yet</p>
                        <p className="text-muted-foreground/60 text-xs">
                          Make sure the browser extension is installed and has completed its first sync.
                        </p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  extensions
                    .slice()
                    .sort((a, b) => {
                      const order: RiskBucket[] = ["critical", "high", "medium", "low", "clean", "unknown"];
                      return (
                        order.indexOf(bucketFromLevel(a.riskLevel, a.isFlagged)) -
                        order.indexOf(bucketFromLevel(b.riskLevel, b.isFlagged))
                      );
                    })
                    .map((ext) => {
                      const bucket = bucketFromLevel(ext.riskLevel, ext.isFlagged);
                      return (
                        <TableRow
                          key={ext.chromeExtensionId}
                          className="cursor-pointer border-border/40 hover:bg-muted/20 transition-colors"
                          onClick={() => window.open(`/report/${ext.chromeExtensionId}`, "_blank")}
                        >
                          <TableCell className="pl-4">
                            <div className="flex items-center gap-2.5">
                              <span
                                className="w-2 h-2 rounded-full shrink-0"
                                style={{ backgroundColor: BUCKET_COLOR[bucket] }}
                              />
                              <span className="text-sm font-medium text-foreground truncate max-w-[200px]">
                                {ext.name ?? ext.chromeExtensionId}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <span
                              className="text-xs font-medium"
                              style={{ color: BUCKET_COLOR[bucket] }}
                            >
                              {BUCKET_LABEL[bucket]}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={ext.enabled ? "outline" : "secondary"}
                              className="text-xs font-normal"
                            >
                              {ext.enabled ? "Enabled" : "Disabled"}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      );
                    })
                )}
              </TableBody>
            </Table>
          </Card>
        </section>
      </div>
    </div>
  );
}
