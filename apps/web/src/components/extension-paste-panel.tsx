import { useState } from "react";
import { ChevronDown, ClipboardPaste, Copy, Check } from "lucide-react";
import { Button } from "@amibeingpwned/ui/button";

import type { ReportMap } from "~/hooks/use-extension-database";
import { parseExtensionList } from "~/lib/parse-extension-list";

interface CheckResult {
  totalParsed: number;
  foundInDb: number;
  notInDb: number;
  ids: Set<string>;
}

export function ExtensionPastePanel({
  onFilterChange,
  reports,
}: {
  onFilterChange: (ids: Set<string> | null) => void;
  reports: ReportMap;
}) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [result, setResult] = useState<CheckResult | null>(null);
  const [copied, setCopied] = useState(false);

  function handleCheck() {
    const { extensions } = parseExtensionList(text);
    if (extensions.length === 0) return;

    const ids = new Set(extensions.map((e) => e.id));
    const foundInDb = extensions.filter((e) => reports.has(e.id)).length;

    setResult({
      totalParsed: extensions.length,
      foundInDb,
      notInDb: extensions.length - foundInDb,
      ids,
    });
    onFilterChange(ids);
  }

  function handleClear() {
    setResult(null);
    setText("");
    onFilterChange(null);
  }

  return (
    <div className="border-border bg-card mb-4 rounded-lg border">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-4 py-3 text-left"
      >
        <ClipboardPaste className="text-muted-foreground h-4 w-4 shrink-0" />
        <span className="text-foreground text-sm font-medium">
          Check My Extensions
        </span>
        <ChevronDown
          className={`text-muted-foreground ml-auto h-4 w-4 shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div className="border-border border-t px-4 pb-4 pt-3">
          {!result ? (
            <>
              <p className="text-muted-foreground mb-2 text-sm">
                Don't have the extension? You can still check your extensions manually:
              </p>
              <ol className="text-muted-foreground mb-3 list-inside list-decimal space-y-1 text-sm">
                <li>
                  Open{" "}
                  <code className="bg-muted rounded px-1.5 py-0.5 text-xs">
                    chrome://system/
                  </code>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      void navigator.clipboard.writeText("chrome://system/");
                      setCopied(true);
                      setTimeout(() => setCopied(false), 1500);
                    }}
                    className="text-muted-foreground hover:text-foreground ml-1 inline-flex translate-y-px rounded p-1 hover:bg-zinc-700/50"
                    title="Copy to clipboard"
                  >
                    {copied
                      ? <Check className="size-3 text-green-500" />
                      : <Copy className="size-3" />}
                  </button>{" "}
                  in a new tab
                </li>
                <li>Click <strong>Expand</strong> next to <strong>Extensions</strong></li>
                <li>Select all the text and copy it</li>
                <li>Paste it below and click <strong>Check</strong></li>
              </ol>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder={"aghfnjkcakhmadgdomlmlhhaocbkloab : Just Black : version 3\nahfgeienlihckogmohjhadlkjgocpleb : Web Store : version 0_2"}
                rows={5}
                className="border-border bg-background text-foreground placeholder:text-muted-foreground mb-2 w-full rounded-md border px-3 py-2 font-mono text-xs outline-none focus:ring-1 focus:ring-zinc-500"
              />
              <div className="flex items-center gap-3">
                <Button size="sm" onClick={handleCheck} disabled={!text.trim()}>
                  Check
                </Button>
                <span className="text-muted-foreground text-xs">
                  Processed entirely in your browser
                </span>
              </div>
            </>
          ) : (
            <div className="flex items-center gap-3">
              <p className="text-muted-foreground text-sm">
                <strong className="text-foreground">{result.foundInDb}</strong>{" "}
                of {result.totalParsed} extension
                {result.totalParsed !== 1 ? "s" : ""} found in database
                {result.notInDb > 0 && (
                  <span>
                    {" "}
                    &middot; {result.notInDb} not in database
                  </span>
                )}
              </p>
              <Button size="sm" variant="outline" onClick={handleClear}>
                Clear Filter
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
