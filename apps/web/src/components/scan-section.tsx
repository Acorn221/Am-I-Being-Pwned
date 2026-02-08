import type { ExtensionReport, InstalledExtensionInfo } from "@amibeingpwned/types";
import { Button } from "@amibeingpwned/ui/button";
import {
  Table,
  TableBody,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";

import type { ExtensionStatus } from "~/hooks/use-extension";
import type { ReportMap } from "~/hooks/use-extension-database";
import { riskOrder } from "~/lib/risk";
import { ScanResultRow } from "~/components/scan-result-row";
import { useMemo } from "react";

interface ScanRow {
  ext: InstalledExtensionInfo;
  report: ExtensionReport | null;
  dbLoading: boolean;
}

export function ScanSection({
  status,
  extensions,
  scan,
  scanning,
  scanError,
  reports,
  dbLoading,
}: {
  status: ExtensionStatus;
  extensions: InstalledExtensionInfo[] | null;
  scan: () => Promise<void>;
  scanning: boolean;
  scanError: string | null;
  reports: ReportMap;
  dbLoading: boolean;
}) {
  const scanRows: ScanRow[] | null = useMemo(() => {
    if (!extensions) return null;
    return extensions
      .map((ext) => ({
        ext,
        report: reports.get(ext.id) ?? null,
        dbLoading,
      }))
      .sort((a, b) => {
        const aRisk = a.report ? riskOrder[a.report.risk] : a.dbLoading ? 6.5 : 7;
        const bRisk = b.report ? riskOrder[b.report.risk] : b.dbLoading ? 6.5 : 7;
        return aRisk - bRisk;
      });
  }, [extensions, reports, dbLoading]);

  const threatCount = scanRows?.filter(
    (r) => r.report && r.report.risk !== "clean",
  ).length;

  return (
    <section id="scan" className="mx-auto max-w-6xl px-6 py-16">
      <h2 className="text-foreground mb-2 text-xl font-semibold">
        Your Extensions
      </h2>

      {status === "detecting" && (
        <div className="border-border rounded-lg border p-8 text-center">
          <p className="text-muted-foreground text-sm">
            Looking for the Am I Being Pwned? extension...
          </p>
        </div>
      )}

      {status === "not_installed" && (
        <div className="border-border rounded-lg border p-8 text-center">
          <p className="text-foreground mb-2 font-medium">
            Extension not detected
          </p>
          <p className="text-muted-foreground mb-4 text-sm">
            Install the Am I Being Pwned? Chrome extension to scan your
            installed extensions against our threat database.
          </p>
          <Button asChild>
            <a href="https://chromewebstore.google.com" target="_blank" rel="noreferrer">
              Install from Chrome Web Store
            </a>
          </Button>
        </div>
      )}

      {status === "connected" && scanning && !extensions && (
        <div className="border-border rounded-lg border p-8 text-center">
          <p className="text-muted-foreground text-sm">
            Scanning your extensions...
          </p>
        </div>
      )}

      {scanError && (
        <div className="mt-4 rounded-lg bg-red-950/50 p-4 text-sm text-red-400">
          {scanError}
        </div>
      )}

      {scanRows && (
        <div className="mt-4">
          <div className="mb-4 flex items-center gap-3">
            <p className="text-muted-foreground text-sm">
              {scanRows.length} extension{scanRows.length !== 1 ? "s" : ""} found
              {dbLoading
                ? " — checking against database..."
                : threatCount
                  ? ` — ${threatCount} threat${threatCount > 1 ? "s" : ""} found`
                  : " — no known threats"}
            </p>
            <Button
              size="sm"
              variant="outline"
              onClick={() => void scan()}
              disabled={scanning}
            >
              {scanning ? "Scanning..." : "Rescan"}
            </Button>
          </div>

          <div className="border-border rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Extension</TableHead>
                  <TableHead className="w-24">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scanRows.map(({ ext, report, dbLoading: loading }) => (
                  <ScanResultRow
                    key={ext.id}
                    ext={ext}
                    report={report}
                    loading={loading}
                  />
                ))}
              </TableBody>
            </Table>
          </div>

          <p className="text-muted-foreground mt-3 text-xs">
            Processed entirely in your browser. Your extension list is never sent to any server.
          </p>
        </div>
      )}
    </section>
  );
}
