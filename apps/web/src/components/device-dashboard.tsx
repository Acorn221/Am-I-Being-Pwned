import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Puzzle, RefreshCw } from "lucide-react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Card } from "@amibeingpwned/ui/card";
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

function bucketFromScore(riskScore: number | null, isFlagged: boolean | null): RiskBucket {
  if (isFlagged) return "critical";
  if (riskScore === null) return "unknown";
  if (riskScore >= 80) return "critical";
  if (riskScore >= 60) return "high";
  if (riskScore >= 40) return "medium";
  if (riskScore >= 20) return "low";
  return "clean";
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

function arcColor(score: number): string {
  if (score >= 80) return "#10b981";
  if (score >= 60) return "#eab308";
  if (score >= 40) return "#f97316";
  return "#ef4444";
}

function ScoreArc({ score }: { score: number }) {
  const r = 36;
  const circumference = 2 * Math.PI * r;
  const trackArc = circumference * 0.75;
  const fillArc = trackArc * (score / 100);

  return (
    <svg viewBox="0 0 100 100" className="w-40 h-40">
      <circle
        cx="50"
        cy="50"
        r={r}
        fill="none"
        className="stroke-muted"
        strokeWidth="7"
        strokeDasharray={`${trackArc} ${circumference}`}
        strokeLinecap="round"
        transform="rotate(135 50 50)"
      />
      <circle
        cx="50"
        cy="50"
        r={r}
        fill="none"
        stroke={arcColor(score)}
        strokeWidth="7"
        strokeDasharray={`${fillArc} ${circumference}`}
        strokeLinecap="round"
        transform="rotate(135 50 50)"
      />
      <text
        x="50"
        y="46"
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="22"
        fontWeight="700"
        className="fill-foreground"
      >
        {score}
      </text>
      <text
        x="50"
        y="63"
        textAnchor="middle"
        fontSize="8"
        letterSpacing="0.08em"
        className="fill-muted-foreground"
      >
        SCORE
      </text>
    </svg>
  );
}

interface DeviceDashboardProps {
  token: string;
}

export function DeviceDashboard({ token }: DeviceDashboardProps) {
  const trpc = useTRPC();

  // If the token came in via ?wst= query param, persist it and clean up the URL
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
        <RefreshCw className="h-8 w-8 animate-spin opacity-30" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-background flex min-h-screen items-center justify-center">
        <div className="text-center space-y-2">
          <p className="text-foreground font-medium">Session expired</p>
          <p className="text-muted-foreground text-sm">
            Your session has expired or is invalid. Re-enroll from your invite link.
          </p>
        </div>
      </div>
    );
  }

  const extensions = data?.extensions ?? [];
  const orgName = data?.orgName ?? "Your organization";

  // Compute score
  const buckets: Record<RiskBucket, number> = {
    critical: 0, high: 0, medium: 0, low: 0, clean: 0, unknown: 0,
  };
  for (const ext of extensions) {
    const bucket = bucketFromScore(ext.riskScore, ext.isFlagged);
    buckets[bucket]++;
  }
  const score = calcScore(buckets, extensions.length);

  return (
    <div className="bg-background min-h-screen">
      {/* Header */}
      <header className="border-border flex h-14 items-center border-b px-6 gap-2">
        <img src="/logo.png" alt="" className="h-7 w-auto" />
        <span className="text-foreground text-sm font-semibold">Am I Being Pwned?</span>
        <span className="text-muted-foreground text-sm ml-2">- {orgName}</span>
      </header>

      <div className="mx-auto max-w-3xl space-y-8 p-6">
        {/* Score */}
        <div className="flex flex-col items-center gap-2 pt-4">
          <ScoreArc score={score} />
          <p className="text-muted-foreground text-sm">
            {extensions.length} extension{extensions.length !== 1 ? "s" : ""} scanned
          </p>
        </div>

        {/* Extensions table */}
        <section className="space-y-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Puzzle className="h-4 w-4" />
            Your Extensions
          </h2>

          <Card className="overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Extension</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {extensions.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={3}
                      className="text-muted-foreground py-10 text-center text-sm"
                    >
                      No extensions found. Make sure the browser extension is installed and synced.
                    </TableCell>
                  </TableRow>
                )}
                {extensions
                  .slice()
                  .sort((a, b) => {
                    const order: RiskBucket[] = ["critical", "high", "medium", "low", "clean", "unknown"];
                    return (
                      order.indexOf(bucketFromScore(a.riskScore, a.isFlagged)) -
                      order.indexOf(bucketFromScore(b.riskScore, b.isFlagged))
                    );
                  })
                  .map((ext) => {
                    const bucket = bucketFromScore(ext.riskScore, ext.isFlagged);
                    return (
                      <TableRow
                        key={ext.chromeExtensionId}
                        className="cursor-pointer hover:bg-muted/30"
                        onClick={() =>
                          window.open(`/report/${ext.chromeExtensionId}`, "_blank")
                        }
                      >
                        <TableCell className="text-sm font-medium">
                          {ext.name ?? ext.chromeExtensionId}
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
                          <Badge variant={ext.enabled ? "default" : "secondary"}>
                            {ext.enabled ? "Enabled" : "Disabled"}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    );
                  })}
              </TableBody>
            </Table>
          </Card>
        </section>
      </div>
    </div>
  );
}
