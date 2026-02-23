import { Check } from "lucide-react";
import { Button } from "@amibeingpwned/ui";

const FREE_FEATURES = [
  "One-time extension scan",
  "1,000+ extension reports",
  "Risk scores & vulnerability summaries",
  "Processed entirely in your browser",
] as const;

const ENTERPRISE_FEATURES = [
  "Everything in Free",
  "Fleet-wide continuous monitoring",
  "API access & integrations",
  "Audit-ready compliance reports",
  "Dedicated support + SLA",
] as const;

const DEMO_HREF = "https://calendar.app.google/ErKTbbbDDHzjAEESA";

export function PricingSection() {
  return (
    <section
      id="pricing"
      className="border-border/50 mx-auto max-w-6xl border-t px-6 py-16"
    >
      <h2 className="text-foreground mb-2 text-xl font-semibold">Pricing</h2>
      <p className="text-muted-foreground mb-12 text-sm">
        Free to start. Enterprise monitoring for teams that need more.
      </p>
      <div className="grid gap-4 sm:max-w-2xl sm:grid-cols-2">
        {/* Free */}
        <div className="border-border bg-card flex flex-col rounded-lg border p-6">
          <div className="mb-6">
            <h3 className="text-foreground mb-1 text-sm font-semibold">Free</h3>
            <div className="text-foreground text-3xl font-bold">$0</div>
            <div className="text-muted-foreground text-xs">forever</div>
          </div>
          <ul className="text-muted-foreground mb-8 flex-1 space-y-3 text-xs">
            {FREE_FEATURES.map((f) => (
              <li key={f} className="flex items-start gap-2">
                <Check className="text-primary mt-0.5 h-3 w-3 shrink-0" />
                {f}
              </li>
            ))}
          </ul>
          <Button variant="outline" size="sm" className="w-full" asChild>
            <a href={DEMO_HREF} target="_blank" rel="noreferrer">
              Book a Demo
            </a>
          </Button>
        </div>

        {/* Enterprise */}
        <div className="border-primary bg-card flex flex-col rounded-lg border-2 p-6">
          <div className="mb-6">
            <h3 className="text-foreground mb-1 text-sm font-semibold">
              Enterprise
            </h3>
            <div className="text-foreground text-3xl font-bold">Custom</div>
            <div className="text-muted-foreground text-xs">
              contact for pricing
            </div>
          </div>
          <ul className="text-muted-foreground mb-8 flex-1 space-y-3 text-xs">
            {ENTERPRISE_FEATURES.map((f) => (
              <li key={f} className="flex items-start gap-2">
                <Check className="text-primary mt-0.5 h-3 w-3 shrink-0" />
                {f}
              </li>
            ))}
          </ul>
          <Button size="sm" className="w-full" asChild>
            <a href={DEMO_HREF} target="_blank" rel="noreferrer">
              Book a Demo
            </a>
          </Button>
        </div>
      </div>
    </section>
  );
}
