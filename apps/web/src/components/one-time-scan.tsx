import { useState } from "react";
import { Copy, Check as CheckIcon, ExternalLink } from "lucide-react";

import type { ReportMap } from "~/hooks/use-extension-database";
import { Badge, Button } from "@amibeingpwned/ui";
import { parseExtensionList } from "~/lib/parse-extension-list";
import { riskConfig, riskOrder } from "~/lib/risk";
import { navigate } from "~/router";

interface ScanResult {
  id: string;
  name: string;
  risk: keyof typeof riskConfig;
}

export function OneTimeScan({ reports }: { reports: ReportMap }) {
  const [text, setText] = useState("");
  const [results, setResults] = useState<ScanResult[] | null>(null);
  const [copied, setCopied] = useState(false);

  function handleScan() {
    const { extensions } = parseExtensionList(text);
    const found = extensions
      .filter((e) => reports.has(e.id))
      .map((e) => {
        const report = reports.get(e.id)!;
        return { id: e.id, name: report.name, risk: report.risk as keyof typeof riskConfig };
      })
      .sort((a, b) => (riskOrder[a.risk] ?? 99) - (riskOrder[b.risk] ?? 99));
    setResults(found);
  }

  function handleReset() {
    setText("");
    setResults(null);
  }

  const threats = results?.filter((r) => r.risk !== "clean" && r.risk !== "unavailable") ?? [];
  const clean = results?.filter((r) => r.risk === "clean" || r.risk === "unavailable") ?? [];

  return (
    <div>
      {results === null ? (
        <>
          <ol className="text-muted-foreground mb-4 list-inside list-decimal space-y-1.5 text-sm">
            <li>
              Open{" "}
              <code className="bg-accent rounded px-1.5 py-0.5 text-xs">
                chrome://system/
              </code>
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard.writeText("chrome://system/");
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }}
                className="text-muted-foreground hover:text-foreground ml-1 inline-flex translate-y-px rounded p-1 hover:bg-zinc-700/50"
                title="Copy to clipboard"
              >
                {copied ? (
                  <CheckIcon className="size-3 text-green-500" />
                ) : (
                  <Copy className="size-3" />
                )}
              </button>{" "}
              in a new tab
            </li>
            <li>
              Click <strong>Expand</strong> next to <strong>Extensions</strong>
            </li>
            <li>Select all the text and paste it below</li>
          </ol>

          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={
              "aghfnjkcakhmadgdomlmlhhaocbkloab : Just Black : version 3\nahfgeienlihckogmohjhadlkjgocpleb : Web Store : version 0_2"
            }
            rows={6}
            className="border-border bg-background text-foreground placeholder:text-muted-foreground mb-3 w-full rounded-md border px-3 py-2 font-mono text-xs outline-none focus:ring-1 focus:ring-zinc-500"
          />

          <div className="flex items-center gap-3">
            <Button onClick={handleScan} disabled={!text.trim()}>
              Scan Extensions
            </Button>
            <span className="text-muted-foreground text-xs">
              Processed entirely in your browser — nothing is sent to our servers.
            </span>
          </div>
        </>
      ) : (
        <div>
          {threats.length === 0 ? (
            <div className="border-border mb-4 rounded-lg border p-6 text-center">
              <p className="text-foreground mb-1 font-medium">No threats found</p>
              <p className="text-muted-foreground text-sm">
                None of your {results.length} matched extensions have known issues. That's great — but our database is always growing.
              </p>
            </div>
          ) : (
            <div className="border-border mb-4 rounded-lg border">
              <div className="border-border border-b px-4 py-3">
                <p className="text-foreground text-sm font-medium">
                  {threats.length} threat{threats.length !== 1 ? "s" : ""} found
                  {clean.length > 0 && (
                    <span className="text-muted-foreground font-normal">
                      {" "}
                      &middot; {clean.length} clean
                    </span>
                  )}
                </p>
              </div>
              <ul className="divide-border divide-y">
                {threats.map((r) => {
                  const cfg = riskConfig[r.risk];
                  return (
                    <li
                      key={r.id}
                      className="flex items-center justify-between px-4 py-3"
                    >
                      <div className="flex items-center gap-3">
                        <Badge variant={cfg.variant}>{cfg.label}</Badge>
                        <span className="text-foreground text-sm">{r.name}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => navigate(`/report/${r.id}`)}
                        className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs transition-colors"
                      >
                        View report
                        <ExternalLink className="h-3 w-3" />
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          <Button variant="outline" size="sm" onClick={handleReset}>
            Scan again
          </Button>
        </div>
      )}
    </div>
  );
}
