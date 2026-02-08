import { useEffect, useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { Button } from "@amibeingpwned/ui/button";

export function ReportPage({ extensionId }: { extensionId: string }) {
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

  return (
    <div className="bg-background min-h-screen">
      <nav className="border-border/50 border-b">
        <div className="mx-auto flex max-w-4xl items-center gap-4 px-6 py-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              window.location.hash = "";
            }}
          >
            Back
          </Button>
          <span className="text-foreground text-sm font-semibold tracking-tight">
            Am I Being Pwned?
          </span>
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
                window.location.hash = "";
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
