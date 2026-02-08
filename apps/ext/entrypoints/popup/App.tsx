import { useEffect, useState } from "react";

import type { ExtensionReport, RiskLevel } from "@acme/types";
import { Badge } from "@acme/ui/badge";
import { Button } from "@acme/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@acme/ui/card";

const API_BASE = import.meta.env.DEV
  ? "http://localhost:3000"
  : "https://amibeingpwned.com";

interface InstalledExtension {
  id: string;
  name: string;
  enabled: boolean;
  icons?: { size: number; url: string }[];
}

type ScanResult =
  | { status: "known"; ext: InstalledExtension; report: ExtensionReport }
  | { status: "unknown"; ext: InstalledExtension };

const riskOrder: Record<RiskLevel, number> = {
  critical: 0,
  high: 1,
  "medium-high": 2,
  medium: 3,
  "medium-low": 4,
  low: 5,
  clean: 6,
};

const riskBadge: Record<
  RiskLevel,
  { label: string; variant: "destructive" | "outline" | "secondary" }
> = {
  critical: { label: "Critical", variant: "destructive" },
  high: { label: "High", variant: "destructive" },
  "medium-high": { label: "Med-High", variant: "destructive" },
  medium: { label: "Medium", variant: "outline" },
  "medium-low": { label: "Med-Low", variant: "outline" },
  low: { label: "Low", variant: "outline" },
  clean: { label: "Clean", variant: "secondary" },
};

async function fetchKnownIds(): Promise<Set<string>> {
  try {
    const res = await fetch(`${API_BASE}/extensions/index.json`);
    if (!res.ok) return new Set();
    const ids: string[] = await res.json();
    return new Set(ids);
  } catch {
    return new Set();
  }
}

async function fetchReport(id: string): Promise<ExtensionReport | null> {
  try {
    const res = await fetch(`${API_BASE}/extensions/${id}.json`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function App() {
  const [results, setResults] = useState<ScanResult[] | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function scan() {
    setScanning(true);
    setError(null);
    try {
      const installed: InstalledExtension[] = await browser.management.getAll();

      // Filter out themes and this extension itself
      const extensions = installed.filter(
        (e) =>
          (e as { type?: string }).type === "extension" &&
          e.id !== browser.runtime.id,
      );

      // Fetch the index of known bad extension IDs
      const knownIds = await fetchKnownIds();

      // Only fetch reports for extensions that are in our database
      const matches = extensions.filter((e) => knownIds.has(e.id));
      const reports = await Promise.all(
        matches.map(async (ext) => {
          const report = await fetchReport(ext.id);
          return { ext, report };
        }),
      );

      const mapped: ScanResult[] = extensions.map((ext) => {
        const match = reports.find((r) => r.ext.id === ext.id);
        if (match?.report) {
          return { status: "known", ext, report: match.report };
        }
        return { status: "unknown", ext };
      });

      // Sort: known threats first (by risk severity), then unknowns
      mapped.sort((a, b) => {
        const aRisk = a.status === "known" ? riskOrder[a.report.risk] : 5;
        const bRisk = b.status === "known" ? riskOrder[b.report.risk] : 5;
        return aRisk - bRisk;
      });

      setResults(mapped);
    } catch {
      setError("Could not connect to the database. Try again later.");
    } finally {
      setScanning(false);
    }
  }

  // Auto-scan on mount
  useEffect(() => {
    void scan();
  }, []);

  const knownThreats = results?.filter(
    (r) => r.status === "known" && r.report.risk !== "clean",
  );

  return (
    <div className="w-[400px] p-4">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-foreground text-lg font-bold">Am I Being Pwned?</h1>
        <Badge variant="destructive" className="text-xs">
          Beta
        </Badge>
      </div>

      {/* Summary */}
      {results && (
        <Card className="mb-4">
          <CardHeader className="p-4">
            <CardTitle className="text-sm">
              {knownThreats && knownThreats.length > 0
                ? `${knownThreats.length} threat${knownThreats.length > 1 ? "s" : ""} found`
                : "No known threats"}
            </CardTitle>
            <CardDescription className="text-xs">
              Scanned {results.length} extension
              {results.length !== 1 ? "s" : ""} against our database.
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      {/* Results list */}
      {error ? (
        <div className="py-8 text-center text-sm text-red-400">{error}</div>
      ) : results ? (
        <div className="flex max-h-[400px] flex-col gap-2 overflow-y-auto">
          {results.map((r) => (
            <ExtensionRow key={r.ext.id} result={r} />
          ))}
        </div>
      ) : (
        <div className="text-muted-foreground py-8 text-center text-sm">
          {scanning ? "Scanning..." : "Click scan to check your extensions."}
        </div>
      )}

      {/* Rescan button */}
      <Button
        className="mt-4 w-full"
        size="sm"
        onClick={() => void scan()}
        disabled={scanning}
      >
        {scanning ? "Scanning..." : "Rescan"}
      </Button>
    </div>
  );
}

function ExtensionRow({ result }: { result: ScanResult }) {
  const [expanded, setExpanded] = useState(false);
  const { ext } = result;
  const icon = ext.icons?.at(-1)?.url;

  if (result.status === "unknown") {
    return (
      <div className="border-border flex items-center gap-3 rounded-md border p-2.5">
        {icon ? (
          <img src={icon} alt="" className="size-6 rounded" />
        ) : (
          <div className="bg-muted size-6 rounded" />
        )}
        <div className="min-w-0 flex-1">
          <div className="text-foreground truncate text-sm font-medium">
            {ext.name}
          </div>
        </div>
        <Badge variant="secondary" className="shrink-0 text-xs">
          Unknown
        </Badge>
      </div>
    );
  }

  const { report } = result;
  const badge = riskBadge[report.risk];

  return (
    <div className="border-border rounded-md border">
      <button
        type="button"
        className="hover:bg-muted/50 flex w-full items-center gap-3 p-2.5 text-left transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {icon ? (
          <img src={icon} alt="" className="size-6 rounded" />
        ) : (
          <div className="bg-muted size-6 rounded" />
        )}
        <div className="min-w-0 flex-1">
          <div className="text-foreground truncate text-sm font-medium">
            {ext.name}
          </div>
          {report.risk !== "clean" && (
            <div className="text-muted-foreground truncate text-xs">
              {report.summary}
            </div>
          )}
        </div>
        <Badge variant={badge.variant} className="shrink-0 text-xs">
          {badge.label}
        </Badge>
      </button>

      {expanded && report.risk !== "clean" && (
        <div className="border-border border-t p-3">
          {report.vulnerabilities.length > 0 && (
            <div className="mb-2">
              <div className="text-foreground mb-1 text-xs font-semibold">
                Vulnerabilities
              </div>
              <ul className="space-y-1">
                {report.vulnerabilities.map((v) => (
                  <li key={v.id} className="text-muted-foreground text-xs">
                    <span className="font-medium">
                      [{v.severity.toUpperCase()}]
                    </span>{" "}
                    {v.title}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {report.endpoints.length > 0 && (
            <div>
              <div className="text-foreground mb-1 text-xs font-semibold">
                Communicates with
              </div>
              <div className="text-muted-foreground text-xs">
                {report.endpoints.join(", ")}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
