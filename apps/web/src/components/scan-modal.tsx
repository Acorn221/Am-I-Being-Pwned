import { ShieldAlert } from "lucide-react";
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@amibeingpwned/ui";
import type { DetectedExtension } from "~/hooks/use-extension-probe";
import { PROBE_RISK_STYLES, PROBE_RISK_DOT, probeRiskRank } from "~/lib/risk";

export function ScanModal({
  detected,
  open,
  onClose,
  checkedCount,
}: {
  detected: DetectedExtension[];
  open: boolean;
  onClose: () => void;
  checkedCount: number;
}) {
  const sorted = [...detected].sort((a, b) => probeRiskRank(a.risk) - probeRiskRank(b.risk));

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-lg p-0 gap-0 overflow-hidden">
        <DialogHeader className="border-border border-b px-6 py-5 text-left">
          <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-red-500/15">
            <ShieldAlert className="h-5 w-5 text-red-400" />
          </div>
          <DialogTitle>
            Partial scan complete -{" "}
            {detected.length} threat{detected.length !== 1 ? "s" : ""} found
          </DialogTitle>
          <DialogDescription>
            We checked {checkedCount} known extensions on this browser and found
            flagged ones. A full audit covers every extension across your fleet.
          </DialogDescription>
        </DialogHeader>

        <ul className="divide-border max-h-72 divide-y overflow-y-auto">
          {sorted.map((e) => (
            <li key={e.id} className="flex items-start gap-3 px-6 py-4">
              <span
                className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${(PROBE_RISK_DOT[e.risk] ?? "bg-yellow-500")}`}
              />
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded border px-1.5 py-0.5 text-xs font-medium ${(PROBE_RISK_STYLES[e.risk] ?? PROBE_RISK_STYLES.MEDIUM)}`}
                  >
                    {e.risk}
                  </span>
                  <span className="text-foreground truncate text-sm font-medium">
                    {e.name}
                  </span>
                </div>
                <p className="text-muted-foreground mt-1 text-xs leading-relaxed">
                  {e.summary.split(". ")[0]}.
                </p>
              </div>
            </li>
          ))}
        </ul>

        <DialogFooter className="border-border flex-col items-start border-t px-6 py-4 sm:flex-col">
          <p className="text-muted-foreground mb-3 text-xs">
            This was a partial scan. A full audit checks every extension, every
            device, continuously.
          </p>
          <div className="flex w-full gap-3">
            <Button size="sm" asChild className="flex-1">
              <a
                href="https://calendar.app.google/ErKTbbbDDHzjAEESA"
                target="_blank"
                rel="noreferrer"
              >
                Book a Demo
              </a>
            </Button>
            <Button size="sm" variant="outline" onClick={onClose}>
              Dismiss
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
