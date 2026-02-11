import { useEffect, useState } from "react";
import type { ExtensionDatabase, RiskLevel } from "@amibeingpwned/types";
import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import { fetchExtensionDatabase } from "../../lib/api";
import { API_BASE_URL } from "../../lib/api";

const riskRows = [
  { key: "critical", label: "Critical", variant: "destructive" },
  { key: "high", label: "High", variant: "destructive" },
  { key: "medium", label: "Medium", variant: "outline" },
  { key: "low", label: "Low", variant: "secondary" },
  { key: "clean", label: "Clean", variant: "secondary" },
  { key: "unknown", label: "Not Scanned", variant: "secondary" },
] as const;

type RiskBucket = (typeof riskRows)[number]["key"];

function bucketForRisk(risk: RiskLevel): RiskBucket {
  switch (risk) {
    case "critical":
      return "critical";
    case "high":
    case "medium-high":
      return "high";
    case "medium":
    case "medium-low":
      return "medium";
    case "low":
      return "low";
    case "clean":
      return "clean";
    case "unavailable":
      return "unknown";
  }
}

export default function App() {
  const [counts, setCounts] = useState<Record<RiskBucket, number> | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [db, installed] = await Promise.all([
          fetchExtensionDatabase(),
          chrome.management.getAll(),
        ]);

        const buckets: Record<RiskBucket, number> = {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          clean: 0,
          unknown: 0,
        };

        let count = 0;
        for (const ext of installed) {
          if (ext.type !== "extension" || ext.id === chrome.runtime.id) continue;
          const report = (db as ExtensionDatabase)[ext.id];
          const bucket = bucketForRisk(report?.risk ?? "unavailable");
          buckets[bucket]++;
          count++;
        }

        setCounts(buckets);
        setTotal(count);
      } catch {
        setError("Could not load extension data.");
      }
    }

    void load();
  }, []);

  const openDashboard = () => {
    void chrome.tabs.create({ url: API_BASE_URL });
    window.close();
  };

  return (
    <div className="p-4 w-[350px]">
      <h1 className="text-sm font-semibold text-foreground tracking-tight mb-3">
        Am I Being Pwned?
      </h1>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {!error && !counts && (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-7 rounded-md bg-muted/50 animate-pulse"
            />
          ))}
        </div>
      )}

      {counts && (
        <>
          <p className="text-xs text-muted-foreground mb-2">
            {total} extension{total !== 1 ? "s" : ""} installed
          </p>

          <div className="flex flex-col gap-1.5 mb-3">
            {riskRows.map(({ key, label, variant }) => {
              const count = counts[key];
              if (count === 0) return null;
              return (
                <div
                  key={key}
                  className="flex items-center justify-between rounded-md border border-border px-3 py-1.5"
                >
                  <Badge variant={variant}>{label}</Badge>
                  <span className="text-sm font-medium tabular-nums text-foreground">
                    {count}
                  </span>
                </div>
              );
            })}

            {total === 0 && (
              <p className="text-sm text-muted-foreground text-center py-2">
                No extensions found.
              </p>
            )}
          </div>
        </>
      )}

      <Button className="w-full" size="sm" onClick={openDashboard}>
        View Full Dashboard
      </Button>
    </div>
  );
}
