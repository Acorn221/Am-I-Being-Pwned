import { Button } from "@amibeingpwned/ui";

export function Navbar() {
  return (
    <nav className="border-border/50 bg-background/95 sticky top-0 z-50 border-b backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <span className="text-foreground text-sm font-semibold tracking-tight">
          Am I Being Pwned?
        </span>
        <div className="flex items-center gap-6">
          <a
            href="/#how-it-works"
            className="text-foreground/70 hover:text-foreground hidden text-sm transition-colors sm:block"
          >
            How it works
          </a>
          <a
            href="/#pricing"
            className="text-foreground/70 hover:text-foreground hidden text-sm transition-colors sm:block"
          >
            Pricing
          </a>
          <Button size="sm" asChild>
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
    </nav>
  );
}
