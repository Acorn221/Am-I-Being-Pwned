import type { ExtensionReport } from "@amibeingpwned/types";
import { Badge } from "@amibeingpwned/ui/badge";
import { TableCell, TableRow } from "@amibeingpwned/ui/table";

import { formatUsers, riskConfig } from "~/lib/risk";

export function DatabaseRow({
  id,
  ext,
  isExpanded,
  onToggle,
}: {
  id: string;
  ext: ExtensionReport;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const cfg = riskConfig[ext.risk];
  const totalVulns =
    ext.vulnerabilityCount.critical +
    ext.vulnerabilityCount.high +
    ext.vulnerabilityCount.medium +
    ext.vulnerabilityCount.low;

  return (
    <TableRow className="cursor-pointer" onClick={onToggle}>
      <TableCell className="overflow-hidden whitespace-normal">
        <div className="text-foreground truncate text-sm font-medium">
          {ext.name}
        </div>
        {!isExpanded && (
          <div className="text-muted-foreground mt-0.5 truncate text-xs">
            {ext.summary}
          </div>
        )}
        {isExpanded && (
          <div className="mt-3 space-y-3 pb-1">
            <div className="text-muted-foreground text-xs">
              {ext.summary}
            </div>
            {totalVulns > 0 && (
              <div>
                <div className="text-foreground mb-1 text-xs font-semibold">
                  Vulnerabilities
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {ext.vulnerabilityCount.critical > 0 && (
                    <Badge variant="destructive" className="text-[10px]">
                      {ext.vulnerabilityCount.critical} Critical
                    </Badge>
                  )}
                  {ext.vulnerabilityCount.high > 0 && (
                    <Badge variant="destructive" className="text-[10px]">
                      {ext.vulnerabilityCount.high} High
                    </Badge>
                  )}
                  {ext.vulnerabilityCount.medium > 0 && (
                    <Badge variant="outline" className="text-[10px]">
                      {ext.vulnerabilityCount.medium} Medium
                    </Badge>
                  )}
                  {ext.vulnerabilityCount.low > 0 && (
                    <Badge variant="secondary" className="text-[10px]">
                      {ext.vulnerabilityCount.low} Low
                    </Badge>
                  )}
                </div>
              </div>
            )}
            {ext.flagCategories.length > 0 && (
              <div>
                <div className="text-foreground mb-1 text-xs font-semibold">
                  Flags
                </div>
                <div className="flex flex-wrap gap-1">
                  {ext.flagCategories.map((flag) => (
                    <code
                      key={flag}
                      className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-300"
                    >
                      {flag}
                    </code>
                  ))}
                </div>
              </div>
            )}
            {ext.endpoints.length > 0 && (
              <div>
                <div className="text-foreground mb-1 text-xs font-semibold">
                  Communicates with
                </div>
                <div className="flex flex-wrap gap-1">
                  {ext.endpoints.map((ep) => (
                    <code
                      key={ep}
                      className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-300"
                    >
                      {ep}
                    </code>
                  ))}
                </div>
              </div>
            )}
            {ext.permissions.length > 0 && (
              <div>
                <div className="text-foreground mb-1 text-xs font-semibold">
                  Permissions
                </div>
                <div className="flex flex-wrap gap-1">
                  {ext.permissions.map((p) => (
                    <code
                      key={p}
                      className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400"
                    >
                      {p}
                    </code>
                  ))}
                </div>
              </div>
            )}
            <div className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 pt-1 text-[10px]">
              {ext.version && (
                <span>v{ext.version}</span>
              )}
              <span>
                Analysed {new Date(ext.updatedAt).toLocaleDateString()}
              </span>
              <span className="font-mono">{id}</span>
              <a
                href={`https://chromewebstore.google.com/detail/${id}`}
                target="_blank"
                rel="noreferrer"
                className="text-blue-400 hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                Chrome Web Store
              </a>
              <a
                href={`#/report/${id}`}
                className="text-blue-400 hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                Full Report
              </a>
            </div>
          </div>
        )}
      </TableCell>
      <TableCell className="text-muted-foreground align-top text-sm">
        {formatUsers(ext.userCount)}
      </TableCell>
      <TableCell className="align-top">
        <Badge variant={cfg.variant}>{cfg.label}</Badge>
      </TableCell>
    </TableRow>
  );
}
