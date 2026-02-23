import { useState } from "react";
import { Check } from "lucide-react";

import { Button } from "@amibeingpwned/ui";

export const DEMO_HREF = "https://calendar.app.google/ErKTbbbDDHzjAEESA";

const CURRENCIES = {
  GBP: { symbol: "£", label: "GBP", rates: [500, 1000, 2500] },
  USD: { symbol: "$", label: "USD", rates: [630, 1260, 3150] },
  EUR: { symbol: "€", label: "EUR", rates: [580, 1160, 2900] },
} as const;

type Currency = keyof typeof CURRENCIES;

const TIERS = [
  {
    name: "Starter",
    period: "per scan",
    description: "Up to 50 users. Perfect for small teams.",
    features: [
      "Up to 50 users",
      "Full fleet extension audit",
      "Risk scores & vulnerability summaries",
      "Actionable remediation report",
    ],
    highlight: false,
    cta: "Get started",
  },
  {
    name: "Growth",
    period: "per scan",
    description: "Up to 200 users. Most mid-market companies.",
    features: [
      "Up to 200 users",
      "Everything in Starter",
      "Audit-ready compliance reports",
      "Executive summary for stakeholders",
    ],
    highlight: true,
    cta: "Get started",
  },
  {
    name: "Enterprise",
    period: "per scan",
    description: "Unlimited users. Larger organisations.",
    features: [
      "Unlimited users",
      "Everything in Growth",
      "Dedicated support + SLA",
      "Custom reporting & exports",
    ],
    highlight: false,
    cta: "Book a demo",
  },
] as const;

export function PricingSection() {
  const [currency, setCurrency] = useState<Currency>("GBP");
  const { symbol, rates } = CURRENCIES[currency];

  return (
    <section
      id="pricing"
      className="border-border/50 mx-auto max-w-6xl border-t px-6 py-16"
    >
      <div className="mb-12 flex items-end justify-between gap-4">
        <div>
          <h2 className="text-foreground mb-2 text-xl font-semibold">
            Pricing
          </h2>
          <p className="text-muted-foreground text-sm">
            Simple, transparent pricing. No hidden fees.
          </p>
        </div>
        <div className="border-border flex rounded-lg border text-sm">
          {(Object.keys(CURRENCIES) as Currency[]).map((c) => (
            <button
              key={c}
              onClick={() => setCurrency(c)}
              className={`px-3 py-1.5 text-xs font-medium transition-colors first:rounded-l-lg last:rounded-r-lg ${
                currency === c
                  ? "bg-foreground text-background"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {CURRENCIES[c].label}
            </button>
          ))}
        </div>
      </div>
      <div className="mb-8 grid gap-4 sm:grid-cols-3">
        {TIERS.map((tier, i) => (
          <div
            key={tier.name}
            className={`bg-card flex flex-col rounded-lg p-6 ${
              tier.highlight
                ? "border-primary border-2"
                : "border-border border"
            }`}
          >
            <div className="mb-6">
              <h3 className="text-foreground mb-1 text-sm font-semibold">
                {tier.name}
              </h3>
              <div className="text-foreground text-3xl font-bold">
                {symbol}
                {(rates[i] ?? CURRENCIES.USD.rates[i] ?? 0).toLocaleString()}
              </div>
              <div className="text-muted-foreground text-xs">{tier.period}</div>
              <p className="text-muted-foreground mt-2 text-xs">
                {tier.description}
              </p>
            </div>
            <ul className="text-muted-foreground mb-8 flex-1 space-y-3 text-xs">
              {tier.features.map((f) => (
                <li key={f} className="flex items-start gap-2">
                  <Check className="text-primary mt-0.5 h-3 w-3 shrink-0" />
                  {f}
                </li>
              ))}
            </ul>
            <Button
              size="sm"
              variant={tier.highlight ? "default" : "outline"}
              className="w-full"
              asChild
            >
              <a href={DEMO_HREF} target="_blank" rel="noreferrer">
                {tier.cta}
              </a>
            </Button>
          </div>
        ))}
      </div>
      <div className="border-border bg-card/50 rounded-lg border border-dashed px-6 py-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-foreground mb-1 text-sm font-semibold">
              Continuous monitoring
              <span className="text-muted-foreground ml-2 text-xs font-normal">
                coming soon
              </span>
            </p>
            <p className="text-muted-foreground text-xs leading-relaxed">
              Always-on fleet monitoring with real-time alerts, weekly digests,
              and automatic detection of newly risky extensions. Get in touch if
              this is something you need now.
            </p>
          </div>
          <Button size="sm" variant="outline" className="shrink-0" asChild>
            <a href={DEMO_HREF} target="_blank" rel="noreferrer">
              Express interest
            </a>
          </Button>
        </div>
      </div>
    </section>
  );
}
