import { useState } from "react";
import { ShieldAlert, X } from "lucide-react";
import type { DetectedExtension } from "~/hooks/use-extension-probe";
import { PROBE_RISK_STYLES, PROBE_RISK_DOT, probeRiskRank } from "~/lib/risk";

export function ScanResultsSection({
  detected,
  probing,
  checkedCount,
}: {
  detected: DetectedExtension[];
  probing: boolean;
  checkedCount: number;
}) {
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;

  if (probing) {
    return (
      <div className="border-border/50 border-b">
        <div className="mx-auto flex max-w-6xl items-center gap-3 px-6 py-3">
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="bg-primary absolute inline-flex h-full w-full animate-ping rounded-full opacity-75" />
            <span className="bg-primary relative inline-flex h-2 w-2 rounded-full" />
          </span>
          <span className="text-muted-foreground text-xs">
            Running partial scan against known extensions...
          </span>
        </div>
      </div>
    );
  }

  if (detected.length === 0) {
    return (
      <div className="border-border/50 border-b">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 shrink-0 rounded-full bg-green-500" />
            <span className="text-muted-foreground text-xs">
              Partial scan complete - no known threats found across{" "}
              {checkedCount} checked extensions. A full audit may surface more.
            </span>
          </div>
          <button
            onClick={() => setDismissed(true)}
            className="text-muted-foreground hover:text-foreground ml-4 shrink-0"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    );
  }

  const sorted = [...detected].sort(
    (a, b) => probeRiskRank(a.risk) - probeRiskRank(b.risk),
  );

  return (
    <div className="border-border/50 border-b bg-red-500/5">
      <div className="mx-auto max-w-6xl px-6 py-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 shrink-0 text-red-400" />
            <span className="text-foreground text-sm font-medium">
              Partial scan - {detected.length} threat
              {detected.length !== 1 ? "s" : ""} found
            </span>
            <span className="text-muted-foreground text-xs">
              ({checkedCount} extensions checked)
            </span>
          </div>
          <button
            onClick={() => setDismissed(true)}
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {sorted.map((e) => (
            <span
              key={e.id}
              className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs ${(PROBE_RISK_STYLES[e.risk] ?? PROBE_RISK_STYLES.MEDIUM)}`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${(PROBE_RISK_DOT[e.risk] ?? "bg-yellow-500")}`}
              />
              <span className="font-medium">{e.risk}</span>
              <span className="opacity-75">{e.name}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
