import type { ExtensionReport, InstalledExtensionInfo } from "@amibeingpwned/types";
import { Badge } from "@amibeingpwned/ui/badge";
import { TableCell, TableRow } from "@amibeingpwned/ui/table";

import { riskConfig } from "~/lib/risk";

export function ScanResultRow({
  ext,
  report,
  loading,
}: {
  ext: InstalledExtensionInfo;
  report: ExtensionReport | null;
  loading: boolean;
}) {
  const cfg = report ? riskConfig[report.risk] : null;

  return (
    <TableRow>
      <TableCell>
        <div className="text-foreground text-sm font-medium">
          {ext.name}
          {!ext.enabled && (
            <span className="text-muted-foreground ml-2 text-xs">
              (disabled)
            </span>
          )}
        </div>
        {report && report.risk !== "clean" && (
          <div className="text-muted-foreground mt-0.5 text-xs">
            {report.summary}
          </div>
        )}
      </TableCell>
      <TableCell>
        {loading ? (
          <Badge variant="secondary" className="animate-pulse">
            Checking...
          </Badge>
        ) : cfg ? (
          <Badge variant={cfg.variant}>{cfg.label}</Badge>
        ) : (
          <Badge variant="secondary">Unknown</Badge>
        )}
      </TableCell>
    </TableRow>
  );
}
