import { useEffect, useMemo, useState } from "react";

import type { ExtensionReport, RiskLevel } from "@acme/types";
import { Badge } from "@acme/ui/badge";
import { Button } from "@acme/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@acme/ui/table";

const riskConfig: Record<
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

const riskOrder: Record<RiskLevel, number> = {
  critical: 0,
  high: 1,
  "medium-high": 2,
  medium: 3,
  "medium-low": 4,
  low: 5,
  clean: 6,
};

function formatUsers(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M+`;
  if (count >= 1_000) return `${Math.round(count / 1_000)}k+`;
  if (count === 0) return "N/A";
  return `${count}`;
}

type ExtEntry = [string, ExtensionReport];

function App() {
  const [entries, setEntries] = useState<ExtEntry[]>([]);
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch("/extensions/index.json");
        const ids: string[] = await res.json();
        const reports = await Promise.all(
          ids.map(async (id) => {
            const r = await fetch(`/extensions/${id}.json`);
            const data: ExtensionReport = await r.json();
            return [id, data] as ExtEntry;
          }),
        );
        reports.sort(
          (a, b) => riskOrder[a[1].risk] - riskOrder[b[1].risk],
        );
        setEntries(reports);
      } catch {
        // Static files — if they fail the site is down anyway
      }
    }
    void load();
  }, []);

  const filtered = useMemo(() => {
    if (!search.trim()) return entries;
    const q = search.toLowerCase();
    return entries.filter(
      ([id, ext]) =>
        ext.name.toLowerCase().includes(q) ||
        id.toLowerCase().includes(q) ||
        ext.summary.toLowerCase().includes(q),
    );
  }, [entries, search]);

  const stats = useMemo(() => {
    const total = entries.length;
    const critical = entries.filter(
      ([, e]) => e.risk === "critical" || e.risk === "high",
    ).length;
    const totalUsers = entries.reduce((sum, [, e]) => sum + e.userCount, 0);
    return { total, critical, totalUsers };
  }, [entries]);

  return (
    <div className="bg-background min-h-screen">
      {/* Nav */}
      <nav className="border-border/50 border-b">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <span className="text-foreground text-sm font-semibold tracking-tight">
            Am I Being Pwned?
          </span>
          <a
            href="https://github.com/AcornPublishing/Am-I-Being-Pwned"
            className="text-muted-foreground hover:text-foreground text-sm transition-colors"
          >
            GitHub
          </a>
        </div>
      </nav>

      {/* Hero */}
      <header className="mx-auto max-w-6xl px-6 pt-20 pb-16">
        <p className="text-muted-foreground mb-3 text-sm font-medium uppercase tracking-wider">
          Browser Extension Security
        </p>
        <h1 className="text-foreground mb-4 text-4xl font-bold tracking-tight sm:text-5xl">
          Are your extensions
          <br />
          working against you?
        </h1>
        <p className="text-muted-foreground mb-8 max-w-xl text-lg">
          We analyse browser extensions for data harvesting, session hijacking,
          network tampering, and other threats. Install our extension to scan
          what you have installed — or browse the database below.
        </p>
        <div className="flex gap-3">
          <Button size="lg">Install Extension</Button>
          <Button size="lg" variant="outline" asChild>
            <a href="#database">Browse Database</a>
          </Button>
        </div>
      </header>

      {/* Stats */}
      <div className="border-border/50 border-y">
        <div className="mx-auto grid max-w-6xl grid-cols-3 divide-x divide-border/50">
          <div className="px-6 py-6">
            <div className="text-foreground text-2xl font-bold">
              {stats.total}
            </div>
            <div className="text-muted-foreground text-sm">
              Extensions analysed
            </div>
          </div>
          <div className="px-6 py-6">
            <div className="text-2xl font-bold text-red-400">
              {stats.critical}
            </div>
            <div className="text-muted-foreground text-sm">
              High / Critical risk
            </div>
          </div>
          <div className="px-6 py-6">
            <div className="text-foreground text-2xl font-bold">
              {formatUsers(stats.totalUsers)}
            </div>
            <div className="text-muted-foreground text-sm">
              Affected users
            </div>
          </div>
        </div>
      </div>

      {/* How it works */}
      <section className="mx-auto max-w-6xl px-6 py-16">
        <h2 className="text-foreground mb-8 text-xl font-semibold">
          How it works
        </h2>
        <div className="grid gap-8 sm:grid-cols-3">
          <div>
            <div className="text-muted-foreground mb-2 text-sm font-medium">
              01
            </div>
            <h3 className="text-foreground mb-1 font-medium">Install</h3>
            <p className="text-muted-foreground text-sm">
              Add the extension to your browser. It only needs the{" "}
              <code className="rounded bg-zinc-800 px-1 py-0.5 text-xs">
                management
              </code>{" "}
              permission to list your extensions.
            </p>
          </div>
          <div>
            <div className="text-muted-foreground mb-2 text-sm font-medium">
              02
            </div>
            <h3 className="text-foreground mb-1 font-medium">Scan</h3>
            <p className="text-muted-foreground text-sm">
              Open the popup and it automatically checks your installed
              extensions against our database of known threats.
            </p>
          </div>
          <div>
            <div className="text-muted-foreground mb-2 text-sm font-medium">
              03
            </div>
            <h3 className="text-foreground mb-1 font-medium">Review</h3>
            <p className="text-muted-foreground text-sm">
              See which extensions are flagged, why they were flagged, and what
              endpoints they communicate with.
            </p>
          </div>
        </div>
      </section>

      {/* What we detect */}
      <section className="border-border/50 border-y">
        <div className="mx-auto max-w-6xl px-6 py-16">
          <h2 className="text-foreground mb-8 text-xl font-semibold">
            What we detect
          </h2>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {[
              {
                title: "Data Harvesting",
                desc: "Extensions silently collecting browsing history, keystrokes, and personal data.",
              },
              {
                title: "Session Hijacking",
                desc: "Stealing authentication tokens and cookies to impersonate you on websites.",
              },
              {
                title: "Code Injection",
                desc: "Injecting scripts into pages to modify content, redirect traffic, or insert ads.",
              },
              {
                title: "Network Tampering",
                desc: "Intercepting requests to inject malware, alter DNS, or proxy through malicious servers.",
              },
            ].map((threat) => (
              <div key={threat.title}>
                <h3 className="text-foreground mb-1 text-sm font-medium">
                  {threat.title}
                </h3>
                <p className="text-muted-foreground text-sm">{threat.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Database */}
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

        <div className="border-border rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Extension</TableHead>
                <TableHead className="w-20">Users</TableHead>
                <TableHead className="w-24">Risk</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(([id, ext]) => {
                const cfg = riskConfig[ext.risk];
                const isExpanded = expandedId === id;
                return (
                  <TableRow
                    key={id}
                    className="cursor-pointer"
                    onClick={() => setExpandedId(isExpanded ? null : id)}
                  >
                    <TableCell>
                      <div className="text-foreground text-sm font-medium">
                        {ext.name}
                      </div>
                      <div className="text-muted-foreground mt-0.5 text-xs">
                        {ext.summary.length > 120
                          ? ext.summary.slice(0, 120) + "..."
                          : ext.summary}
                      </div>
                      {isExpanded && (
                        <div className="mt-3 space-y-3 pb-1">
                          <div className="text-muted-foreground text-xs">
                            {ext.summary}
                          </div>
                          {ext.vulnerabilities.length > 0 && (
                            <div>
                              <div className="text-foreground mb-1 text-xs font-semibold">
                                Vulnerabilities
                              </div>
                              <ul className="space-y-1">
                                {ext.vulnerabilities.map((v) => (
                                  <li
                                    key={v.id}
                                    className="text-muted-foreground text-xs"
                                  >
                                    <Badge
                                      variant={
                                        v.severity === "critical" ||
                                        v.severity === "high"
                                          ? "destructive"
                                          : "outline"
                                      }
                                      className="mr-1.5 text-[10px]"
                                    >
                                      {v.severity}
                                    </Badge>
                                    {v.title}
                                    {v.cvssScore && (
                                      <span className="text-muted-foreground ml-1">
                                        (CVSS {v.cvssScore})
                                      </span>
                                    )}
                                  </li>
                                ))}
                              </ul>
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
                          <div className="text-muted-foreground pt-1 font-mono text-[10px]">
                            {id}
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
              })}
            </TableBody>
          </Table>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-border/50 border-t">
        <div className="mx-auto max-w-6xl px-6 py-8">
          <div className="text-muted-foreground flex items-center justify-between text-sm">
            <span>Am I Being Pwned?</span>
            <span>Open source browser extension security scanner</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
