// import { useMemo } from "react";
import { Check, Eye, Globe, ShieldAlert, Syringe, Wifi } from "lucide-react";

import { Button } from "@amibeingpwned/ui";

import type { ReportMap } from "~/hooks/use-extension-database";
import { ExtensionPreviewCards } from "~/components/extension-preview-cards";
import { HeroCycleProvider } from "~/components/hero-cycle-context";
// import { OneTimeScan } from "~/components/one-time-scan";
import { TypingTitle } from "~/components/typing-title";
// import { formatUsers } from "~/lib/risk";
import { navigate } from "~/router";

function HeroSection() {
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
              <a
                href="https://calendar.app.google/ErKTbbbDDHzjAEESA"
                target="_blank"
                rel="noreferrer"
              >
                Book a Demo
              </a>
            </Button>
            <Button size="lg" variant="outline" asChild>
              <a href="#how-it-works">How it works</a>
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

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function App({ reports }: { reports: ReportMap }) {
  // TODO: re-enable when database is back
  // const stats = useMemo(() => {
  //   const entries = [...reports.values()];
  //   const total = entries.length;
  //   const critical = entries.filter(
  //     (e) => e.risk === "critical" || e.risk === "high",
  //   ).length;
  //   const totalUsers = entries
  //     .filter(
  //       (e) =>
  //         e.risk === "critical" || e.risk === "high" || e.risk === "medium",
  //     )
  //     .reduce((sum, e) => sum + (e.userCount || 0), 0);
  //   return { total, critical, totalUsers };
  // }, [reports]);

  return (
    <div className="bg-background min-h-screen">
      {/* Hero */}
      <HeroCycleProvider>
        <HeroSection />
      </HeroCycleProvider>

      {/* Nav */}
      <nav className="border-border/50 bg-background/95 sticky top-0 z-50 border-b backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <span className="text-foreground text-sm font-semibold tracking-tight">
            Am I Being Pwned?
          </span>
          <div className="flex items-center gap-6">
            <a
              href="#how-it-works"
              className="text-foreground/70 hover:text-foreground text-sm transition-colors"
            >
              How it works
            </a>
            <a
              href="#pricing"
              className="text-foreground/70 hover:text-foreground text-sm transition-colors"
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

      {/* Stats — commented out until database is re-enabled */}
      {/* <div className="border-border/50 border-y">
        <div className="divide-border/50 mx-auto grid max-w-6xl grid-cols-3 divide-x">
          <div className="px-6 py-6">
            <div className="text-foreground text-2xl font-bold">{stats.total}</div>
            <div className="text-muted-foreground text-sm">Extensions analysed</div>
          </div>
          <div className="px-6 py-6">
            <div className="text-2xl font-bold text-red-400">{stats.critical}</div>
            <div className="text-muted-foreground text-sm">High / Critical risk</div>
          </div>
          <div className="px-6 py-6">
            <div className="text-foreground text-2xl font-bold">{formatUsers(stats.totalUsers)}</div>
            <div className="text-muted-foreground text-sm">Affected users</div>
          </div>
        </div>
      </div> */}

      {/* What we detect */}
      <section className="border-border/50 border-y">
        <div className="mx-auto max-w-6xl px-6 py-16">
          <h2 className="text-foreground mb-8 text-xl font-semibold">
            What we detect
          </h2>
          <div className="flex flex-col items-center gap-4">
            <div className="grid w-full gap-4 sm:grid-cols-3">
              {[
                {
                  icon: Eye,
                  title: "Data Harvesting",
                  desc: "Silently collecting browsing history, keystrokes, and personal data.",
                },
                {
                  icon: Globe,
                  title: "Session Hijacking",
                  desc: "Stealing auth tokens and cookies to impersonate you on websites.",
                },
                {
                  icon: Syringe,
                  title: "Code Injection",
                  desc: "Injecting scripts into pages to modify content or insert ads.",
                },
              ].map((threat) => (
                <div
                  key={threat.title}
                  className="border-border rounded-lg border p-4"
                >
                  <threat.icon className="text-muted-foreground mb-3 h-5 w-5" />
                  <h3 className="text-foreground mb-1 text-sm font-medium">
                    {threat.title}
                  </h3>
                  <p className="text-muted-foreground text-xs leading-relaxed">
                    {threat.desc}
                  </p>
                </div>
              ))}
            </div>
            <div className="grid w-full gap-4 sm:max-w-[66.666%] sm:grid-cols-2">
              {[
                {
                  icon: Wifi,
                  title: "Network Tampering",
                  desc: "Intercepting requests to inject malware or proxy through malicious servers.",
                },
                {
                  icon: ShieldAlert,
                  title: "Vulnerabilities",
                  desc: "Poor security hygiene, outdated dependencies, or known CVEs.",
                },
              ].map((threat) => (
                <div
                  key={threat.title}
                  className="border-border rounded-lg border p-4"
                >
                  <threat.icon className="text-muted-foreground mb-3 h-5 w-5" />
                  <h3 className="text-foreground mb-1 text-sm font-medium">
                    {threat.title}
                  </h3>
                  <p className="text-muted-foreground text-xs leading-relaxed">
                    {threat.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" className="mx-auto max-w-6xl px-6 py-16">
        <h2 className="text-foreground mb-2 text-xl font-semibold">
          How it works
        </h2>
        <p className="text-muted-foreground mb-12 text-sm">
          Up and running in minutes. No agents to deploy, no data leaving your
          network.
        </p>
        <div className="grid gap-8 sm:grid-cols-3">
          {[
            {
              step: "01",
              title: "Connect your inventory",
              desc: "Share your extension list via our Chrome extension or API. No sensitive data leaves your machine — only extension IDs and metadata.",
            },
            {
              step: "02",
              title: "Automated risk analysis",
              desc: "We scan permissions, network behavior, code patterns, and known CVEs across your entire extension set and score each one.",
            },
            {
              step: "03",
              title: "Actionable reports",
              desc: "Get risk-scored results with plain-English explanations. Block, replace, or monitor extensions — with evidence you can share with stakeholders.",
            },
          ].map((item) => (
            <div key={item.step} className="flex flex-col gap-3">
              <span className="text-primary font-mono text-xs font-semibold tracking-widest">
                {item.step}
              </span>
              <h3 className="text-foreground text-sm font-semibold">
                {item.title}
              </h3>
              <p className="text-muted-foreground text-xs leading-relaxed">
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* One-time scan — commented out until database is re-enabled */}
      {/* <section id="scan" className="border-border/50 border-y">
        <div className="mx-auto max-w-6xl px-6 py-16">
          <h2 className="text-foreground mb-2 text-xl font-semibold">
            Scan your extensions — free
          </h2>
          <p className="text-muted-foreground mb-8 text-sm">
            Paste your extension list below and we'll check it against our
            database of {stats.total.toLocaleString()} analysed extensions instantly, in your browser.
          </p>
          <OneTimeScan reports={reports} />
        </div>
      </section> */}

      {/* Pricing */}
      <section id="pricing" className="mx-auto max-w-6xl px-6 py-16">
        <h2 className="text-foreground mb-2 text-xl font-semibold">Pricing</h2>
        <p className="text-muted-foreground mb-12 text-sm">
          Free to start. Enterprise monitoring for teams that need more.
        </p>
        <div className="grid gap-4 sm:max-w-2xl sm:grid-cols-2">
          {/* Free */}
          <div className="border-border bg-card flex flex-col rounded-lg border p-6">
            <div className="mb-6">
              <h3 className="text-foreground mb-1 text-sm font-semibold">
                Free
              </h3>
              <div className="text-foreground text-3xl font-bold">$0</div>
              <div className="text-muted-foreground text-xs">forever</div>
            </div>
            <ul className="text-muted-foreground mb-8 flex-1 space-y-3 text-xs">
              {[
                "One-time extension scan",
                "1,000+ extension reports",
                "Risk scores & vulnerability summaries",
                "Processed entirely in your browser",
              ].map((f) => (
                <li key={f} className="flex items-start gap-2">
                  <Check className="text-primary mt-0.5 h-3 w-3 shrink-0" />
                  {f}
                </li>
              ))}
            </ul>
            <Button variant="outline" size="sm" className="w-full" asChild>
              <a
                href="https://calendar.app.google/ErKTbbbDDHzjAEESA"
                target="_blank"
                rel="noreferrer"
              >
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
              {[
                "Everything in Free",
                "Fleet-wide continuous monitoring",
                "API access & integrations",
                "Audit-ready compliance reports",
                "Dedicated support + SLA",
              ].map((f) => (
                <li key={f} className="flex items-start gap-2">
                  <Check className="text-primary mt-0.5 h-3 w-3 shrink-0" />
                  {f}
                </li>
              ))}
            </ul>
            <Button size="sm" className="w-full" asChild>
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
      </section>

      {/* Footer */}
      <footer className="border-border/50 border-t">
        <div className="mx-auto max-w-6xl px-6 py-10">
          <div className="flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <p className="text-foreground mb-1 text-sm font-semibold">
                Am I Being Pwned?
              </p>
              <p className="text-muted-foreground text-xs">
                Protecting organizations from malicious browser extensions.
              </p>
              <p className="text-muted-foreground mt-3 text-xs">
                &copy; {new Date().getFullYear()} J4A Industries. All rights
                reserved.
              </p>
            </div>
            <div className="flex flex-wrap gap-x-6 gap-y-2">
              {[
                {
                  label: "FAQ",
                  onClick: () => navigate("/faq"),
                  href: "/faq",
                },
                { label: "Privacy Policy", href: "#" },
                { label: "Terms of Service", href: "#" },
                { label: "Contact", href: "mailto:hello@amibeingpwned.com" },
              ].map((link) => (
                <a
                  key={link.label}
                  href={link.href}
                  onClick={
                    link.onClick
                      ? (e) => {
                          e.preventDefault();
                          link.onClick();
                        }
                      : undefined
                  }
                  className="text-muted-foreground hover:text-foreground text-sm transition-colors"
                >
                  {link.label}
                </a>
              ))}
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
