import { DEMO_TOKEN_HOMEPAGE } from "@amibeingpwned/types";

import { Button } from "@amibeingpwned/ui";
import { ExtensionPreviewCards } from "~/components/extension-preview-cards";
import { TypingTitle } from "~/components/typing-title";

export function HeroSection() {
  return (
    <header className="mx-auto flex min-h-screen max-w-6xl items-center px-6">
      <div className="flex w-full flex-col md:flex-row md:items-center md:justify-between">
        <div className="flex-1">
          <p className="text-primary mb-3 text-sm font-medium tracking-wider uppercase">
            Enterprise Browser Security
          </p>
          <TypingTitle />
          <p className="text-muted-foreground mb-8 max-w-xl text-lg">
            Browser extensions are the most overlooked attack surface in
            enterprise environments. We audit, score, and monitor extensions
            across your fleet, before they cause damage.
          </p>
          <div className="flex flex-wrap gap-3">
            <Button size="lg" asChild>
              <a href={`/demo/${DEMO_TOKEN_HOMEPAGE}`}>
                Scan my extensions
              </a>
            </Button>
            <Button size="lg" variant="outline" asChild>
              <a
                href="https://calendar.app.google/ErKTbbbDDHzjAEESA"
                target="_blank"
                rel="noreferrer"
              >
                Book a Demo
              </a>
            </Button>
          </div>
        </div>
        <div className="hidden flex-1 md:block">
          <ExtensionPreviewCards />
        </div>
      </div>
    </header>
  );
}
