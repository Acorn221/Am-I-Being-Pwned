import { useEffect, useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

import type { ExtensionReport } from "@amibeingpwned/types";
import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";

import { formatUsers, riskConfig } from "~/lib/risk";
import { navigate } from "~/router";

export function ReportPage({
  extensionId,
  ext,
}: {
  extensionId: string;
  ext?: ExtensionReport;
}) {
  const [content, setContent] = useState<string | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`/website-reports/${extensionId}.md`)
      .then((res) => {
        if (!res.ok) throw new Error("Not found");
        return res.text();
      })
      .then((text) => {
        if (!cancelled) setContent(text);
      })
      .catch(() => {
        if (!cancelled) setError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [extensionId]);

  const cfg = ext ? riskConfig[ext.risk] : null;

  return (
    <div className="bg-background min-h-screen">
      <nav className="bg-background/80 border-border/50 sticky top-0 z-50 border-b backdrop-blur-sm">
        <div className="mx-auto flex max-w-4xl items-center justify-between gap-4 px-6 py-3">
          <div className="flex items-center gap-3 overflow-hidden">
            <Button
              variant="outline"
              size="sm"
              className="shrink-0"
              onClick={() => {
                navigate("/");
              }}
            >
              Back
            </Button>
            {ext ? (
              <div className="flex items-center gap-2 overflow-hidden">
                <span className="text-foreground truncate text-sm font-semibold">
                  {ext.name}
                </span>
                {cfg && <Badge variant={cfg.variant} className="shrink-0">{cfg.label}</Badge>}
                <span className="text-muted-foreground shrink-0 text-xs">
                  {formatUsers(ext.userCount)} users
                </span>
              </div>
            ) : (
              <span className="text-foreground text-sm font-semibold tracking-tight">
                Am I Being Pwned?
              </span>
            )}
          </div>
          <a
            href={`https://chromewebstore.google.com/detail/${extensionId}`}
            target="_blank"
            rel="noreferrer"
            className="text-muted-foreground hover:text-foreground shrink-0 text-sm transition-colors"
          >
            Chrome Web Store
          </a>
        </div>
      </nav>

      <main className="mx-auto max-w-4xl px-6 py-10">
        {error && (
          <div className="text-center">
            <p className="text-foreground mb-2 text-lg font-medium">
              Report not found
            </p>
            <p className="text-muted-foreground mb-4 text-sm">
              No detailed report available for this extension.
            </p>
            <Button
              variant="outline"
              onClick={() => {
                navigate("/");
              }}
            >
              Back to database
            </Button>
          </div>
        )}

        {!error && !content && (
          <p className="text-muted-foreground text-sm">Loading report...</p>
        )}

        {content && (
          <article className="prose prose-invert prose-sm max-w-none">
            <Markdown remarkPlugins={[remarkGfm]}>{content}</Markdown>
          </article>
        )}
      </main>
    </div>
  );
}
