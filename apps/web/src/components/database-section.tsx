import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, TriangleAlert, X } from "lucide-react";

import type { ExtensionReport } from "@amibeingpwned/types";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";

import type { ReportMap } from "~/hooks/use-extension-database";
import { DatabaseRow } from "~/components/database-row";
import { ExtensionPastePanel } from "~/components/extension-paste-panel";
import { riskOrder } from "~/lib/risk";

function Pagination({
  page,
  totalPages,
  total,
  pageSize,
  onPage,
  className,
}: {
  page: number;
  totalPages: number;
  total: number;
  pageSize: number;
  onPage: (p: number) => void;
  className?: string;
}) {
  return (
    <div className={`flex items-center justify-between ${className ?? ""}`}>
      <p className="text-muted-foreground text-sm">
        {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of{" "}
        {total}
      </p>
      <div className="flex items-center gap-2">
        <button
          disabled={page === 0}
          onClick={() => onPage(page - 1)}
          className="text-muted-foreground hover:text-foreground disabled:pointer-events-none disabled:opacity-30"
        >
          <ChevronLeft className="h-5 w-5" />
        </button>
        <span className="text-muted-foreground text-sm">
          {page + 1} / {totalPages}
        </span>
        <button
          disabled={page >= totalPages - 1}
          onClick={() => onPage(page + 1)}
          className="text-muted-foreground hover:text-foreground disabled:pointer-events-none disabled:opacity-30"
        >
          <ChevronRight className="h-5 w-5" />
        </button>
      </div>
    </div>
  );
}

export function DatabaseSection({ reports }: { reports: ReportMap }) {
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showDisclaimer, setShowDisclaimer] = useState(true);
  const [pasteFilterIds, setPasteFilterIds] = useState<Set<string> | null>(
    null,
  );
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;

  const dbEntries = useMemo(() => {
    const riskWeight: Record<string, number> = {
      critical: 5,
      high: 4,
      "medium-high": 3,
      medium: 2,
      "medium-low": 1.5,
      low: 1,
      clean: 0,
      unavailable: 0,
    };
    const score = (ext: ExtensionReport) =>
      (riskWeight[ext.risk] ?? 0) * Math.log10(Math.max(ext.userCount, 1));
    return [...reports.entries()].sort(([, a], [, b]) => score(b) - score(a));
  }, [reports, reports.size]);

  const pasteFiltered = useMemo(() => {
    if (!pasteFilterIds) return dbEntries;
    return dbEntries.filter(([id]) => pasteFilterIds.has(id));
  }, [dbEntries, pasteFilterIds]);

  const filtered = useMemo(() => {
    setPage(0);
    if (!search.trim()) return pasteFiltered;
    const q = search.toLowerCase();
    return pasteFiltered.filter(
      ([id, ext]) =>
        ext.name.toLowerCase().includes(q) ||
        id.toLowerCase().includes(q) ||
        ext.summary.toLowerCase().includes(q),
    );
  }, [pasteFiltered, search]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <section id="database" className="mx-auto max-w-6xl px-6 py-16">
      <ExtensionPastePanel
        onFilterChange={setPasteFilterIds}
        reports={reports}
      />

      <div className="mb-6 flex items-end justify-between gap-4">
        <div>
          <h2 className="text-foreground text-xl font-semibold">
            Extension Database
          </h2>
          <p className="text-muted-foreground text-sm">
            {pasteFilterIds
              ? `${filtered.length} of your extension${filtered.length !== 1 ? "s" : ""} found in database`
              : `${filtered.length} extension${filtered.length !== 1 ? "s" : ""} flagged`}
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

      {showDisclaimer && (
        <div className="border-border bg-card mb-4 flex items-start gap-3 rounded-lg border p-4">
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-yellow-500" />
          <p className="text-muted-foreground text-sm">
            Reports are generated using automated AI analysis and may contain
            inaccuracies. Users should independently verify all findings before
            taking action. This tool is not a substitute for a professional
            security audit.
          </p>
          <button
            onClick={() => setShowDisclaimer(false)}
            className="text-muted-foreground hover:text-foreground shrink-0 p-0.5"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {totalPages > 1 && (
        <Pagination
          page={page}
          totalPages={totalPages}
          total={filtered.length}
          pageSize={PAGE_SIZE}
          onPage={setPage}
          className="mb-4"
        />
      )}

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
            {filtered.length === 0 && pasteFilterIds ? (
              <TableRow>
                <TableCell
                  colSpan={3}
                  className="text-muted-foreground py-8 text-center text-sm"
                >
                  None of your pasted extensions were found in the database.
                </TableCell>
              </TableRow>
            ) : (
              paginated.map(([id, ext], index) => (
                <DatabaseRow
                  key={id}
                  id={id}
                  ext={ext}
                  index={index}
                  isExpanded={expandedId === id}
                  onToggle={() => setExpandedId(expandedId === id ? null : id)}
                />
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {totalPages > 1 && (
        <Pagination
          page={page}
          totalPages={totalPages}
          total={filtered.length}
          pageSize={PAGE_SIZE}
          onPage={setPage}
          className="mt-4"
        />
      )}
    </section>
  );
}
