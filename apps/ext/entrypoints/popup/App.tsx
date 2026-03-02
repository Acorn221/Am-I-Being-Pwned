import { useEffect, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";
import { ScoreArc } from "@amibeingpwned/ui/score-arc";

import { API_BASE_URL } from "../../lib/api";
import { getStoredWebSessionToken } from "../../lib/device";
import { publicClient } from "../../lib/trpc";

type RiskBucket = "critical" | "high" | "medium" | "low" | "clean" | "unknown";

function bucketFromLevel(
  riskLevel: string | null | undefined,
  isFlagged: boolean | null,
): RiskBucket {
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
  high: "High risk",
  medium: "Medium risk",
  low: "Low risk",
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


interface Issue {
  id: string;
  name: string;
  bucket: RiskBucket;
}

export default function App() {
  const [score, setScore] = useState<number | null>(null);
  const [total, setTotal] = useState(0);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [notEnrolled, setNotEnrolled] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const [wst, installed] = await Promise.all([
          getStoredWebSessionToken(),
          chrome.management.getAll(),
        ]);

        if (!wst) {
          setNotEnrolled(true);
          return;
        }

        const result = await publicClient.devices.getWebSession.query({ token: wst });
        const list = result.extensions;

        const riskMap = new Map(list.map((e) => [e.chromeExtensionId, e]));

        const buckets: Record<RiskBucket, number> = {
          critical: 0, high: 0, medium: 0, low: 0, clean: 0, unknown: 0,
        };

        const found: Issue[] = [];
        let count = 0;

        for (const ext of installed) {
          if (ext.type !== "extension" || ext.id === chrome.runtime.id)
            continue;
          const data = riskMap.get(ext.id);
          const bucket = data
            ? bucketFromLevel(data.riskLevel, data.isFlagged)
            : "unknown";
          buckets[bucket]++;
          count++;
          if (bucket === "critical" || bucket === "high" || bucket === "medium")
            found.push({ id: ext.id, name: ext.name, bucket });
        }

        const order: RiskBucket[] = ["critical", "high", "medium"];
        found.sort((a, b) => order.indexOf(a.bucket) - order.indexOf(b.bucket));

        setTotal(count);
        setScore(calcScore(buckets, count));
        setIssues(found.slice(0, 4));
      } catch {
        setError("Could not load extension data.");
      }
    })();
  }, []);

  const openDashboard = () => {
    void getStoredWebSessionToken().then((wst) => {
      if (!wst) return;
      void chrome.tabs.create({ url: `${API_BASE_URL}/dashboard?wst=${wst}` });
      window.close();
    });
  };

  const openReport = (extId: string) => {
    void chrome.tabs.create({ url: `${API_BASE_URL}/report/${extId}` });
    window.close();
  };

  return (
    <div className="w-[300px] p-4 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <img src="/icon/32.png" alt="" className="w-5 h-5 rounded" />
        <span className="text-sm font-semibold text-foreground">
          Am I Being Pwned?
        </span>
      </div>

      {notEnrolled ? (
        <div className="flex flex-col items-center gap-3 py-2 text-center">
          <p className="text-sm text-foreground font-medium">Not connected</p>
          <p className="text-xs text-muted-foreground">
            Open your enrollment link to connect this device to your organization.
          </p>
          <Button
            className="w-full"
            size="sm"
            onClick={() => {
              void chrome.tabs.create({ url: API_BASE_URL });
              window.close();
            }}
          >
            Connect
          </Button>
        </div>
      ) : (
        <>
          <div className="flex flex-col items-center gap-1">
            {error ? (
              <p className="text-sm text-destructive">{error}</p>
            ) : score === null ? (
              <div className="w-36 h-36 rounded-full bg-muted/20 animate-pulse" />
            ) : (
              <ScoreArc score={score} className="w-36 h-36" />
            )}
            {score !== null && !error && (
              <p className="text-xs text-muted-foreground">
                {total} extension{total !== 1 ? "s" : ""} scanned
              </p>
            )}
          </div>

          {issues.length > 0 && (
            <div className="flex flex-col gap-1">
              {issues.map((issue) => (
                <button
                  key={issue.id}
                  onClick={() => openReport(issue.id)}
                  className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-left hover:bg-muted/30 transition-colors w-full"
                >
                  <span className="text-xs text-foreground truncate flex-1 mr-2">
                    {issue.name}
                  </span>
                  <span
                    className="text-xs font-medium shrink-0"
                    style={{ color: BUCKET_COLOR[issue.bucket] }}
                  >
                    {BUCKET_LABEL[issue.bucket]}
                  </span>
                </button>
              ))}
            </div>
          )}

          {issues.length === 0 && score !== null && (
            <p className="text-xs text-muted-foreground text-center">
              No high-risk extensions detected.
            </p>
          )}

          <Button className="w-full" size="sm" onClick={openDashboard}>
            View Dashboard
          </Button>
        </>
      )}
    </div>
  );
}
