import { useMemo, useState } from "react";

import type { ExtensionReport, RiskLevel } from "@amibeingpwned/types";
import {
  Table,
  TableBody,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";

import type { ReportMap } from "~/hooks/use-extension-database";
import { riskOrder } from "~/lib/risk";
import { DatabaseRow } from "~/components/database-row";

export function DatabaseSection({ reports }: { reports: ReportMap }) {
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const dbEntries = useMemo(() => {
    const entries = [...reports.entries()] as [string, ExtensionReport][];
    entries.sort((a, b) => {
      const riskDiff = riskOrder[a[1].risk] - riskOrder[b[1].risk];
      if (riskDiff !== 0) return riskDiff;
      return b[1].userCount - a[1].userCount;
    });
    return entries;
  }, [reports]);

  const filtered = useMemo(() => {
    if (!search.trim()) return dbEntries;
    const q = search.toLowerCase();
    return dbEntries.filter(
      ([id, ext]) =>
        ext.name.toLowerCase().includes(q) ||
        id.toLowerCase().includes(q) ||
        ext.summary.toLowerCase().includes(q),
    );
  }, [dbEntries, search]);

  return (
    <section id="database" className="mx-auto max-w-6xl px-6 py-16">
      <div className="mb-6 flex items-end justify-between gap-4">
        <div>
          <h2 className="text-foreground text-xl font-semibold">
            Extension Database
          </h2>
          <p className="text-muted-foreground text-sm">
            {filtered.length} extension{filtered.length !== 1 ? "s" : ""}{" "}
            flagged
          </p>
        </div>
        <input
          type="text"
          placeholder="Search extensions..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="border-border bg-background text-foreground placeholder:text-muted-foreground w-64 rounded-md border px-3 py-1.5 text-sm outline-none focus:ring-1 focus:ring-zinc-500"
        />
      </div>

      <div className="border-border overflow-hidden rounded-lg border">
        <Table className="table-fixed">
          <TableHeader>
            <TableRow>
              <TableHead>Extension</TableHead>
              <TableHead className="w-20">Users</TableHead>
              <TableHead className="w-24">Risk</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map(([id, ext]) => (
              <DatabaseRow
                key={id}
                id={id}
                ext={ext}
                isExpanded={expandedId === id}
                onToggle={() => setExpandedId(expandedId === id ? null : id)}
              />
            ))}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
