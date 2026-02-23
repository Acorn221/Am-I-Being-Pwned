import { useEffect, useState } from "react";
import {
  Check,
  ChevronLeft,
  ChevronRight,
  Eye,
  Globe,
  ShieldAlert,
  Syringe,
  Wifi,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui";

import type { ReportMap } from "~/hooks/use-extension-database";
import { ExtensionPreviewCards } from "~/components/extension-preview-cards";
import { HeroCycleProvider } from "~/components/hero-cycle-context";
// import { OneTimeScan } from "~/components/one-time-scan";
import { TypingTitle } from "~/components/typing-title";
// import { formatUsers } from "~/lib/risk";
import { navigate } from "~/router";

const THREATS = [
  {
    icon: Eye,
    title: "Data Harvesting",
    desc: "Extensions silently collect browsing history, keystrokes, form inputs, and personal data - then upload it to remote servers. Often disguised as productivity tools or ad blockers, these extensions build detailed profiles of every employee in your organisation.",
  },
  {
    icon: Globe,
    title: "Session Hijacking",
    desc: "By reading authentication tokens and cookies, malicious extensions can impersonate your employees on any website - including internal tools, SaaS platforms, and corporate email. The attacker never needs a password.",
  },
  {
    icon: Syringe,
    title: "Code Injection",
    desc: "Extensions with broad host permissions can inject arbitrary JavaScript into any page your employees visit. This enables ad injection, UI manipulation, credential skimming, and modification of internal web apps.",
  },
  {
    icon: Wifi,
    title: "Network Tampering",
    desc: "Some extensions intercept and modify network requests in real time - proxying traffic through attacker-controlled servers, injecting malware into responses, or routing your employees' connections through residential botnet nodes.",
  },
  {
    icon: ShieldAlert,
    title: "Known Vulnerabilities",
    desc: "Beyond malicious intent, many extensions have poor security hygiene: outdated dependencies with known CVEs, insecure data storage, and unvalidated remote code execution paths. Any of these can be exploited by a third party.",
  },
] as const;

const INTERVAL_MS = 5000;

function ThreatCarousel() {
  const [active, setActive] = useState(0);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (paused) return;
    const id = setInterval(() => {
      setActive((i) => (i + 1) % THREATS.length);
    }, INTERVAL_MS);
    return () => clearInterval(id);
  }, [paused, active]);

  const threat = THREATS[active % THREATS.length];
  if (!threat) return null;

  function prev() {
    setActive((i) => (i - 1 + THREATS.length) % THREATS.length);
    setPaused(true);
  }

  function next() {
    setActive((i) => (i + 1) % THREATS.length);
    setPaused(true);
  }

  return (
    <div
      className="flex gap-8"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      {/* Sidebar nav - desktop */}
      <div
        className="hidden flex-col gap-1 sm:flex"
        style={{ minWidth: "11rem" }}
      >
        {THREATS.map((t, i) => (
          <button
            key={t.title}
            onClick={() => {
              setActive(i);
              setPaused(true);
            }}
            className={`rounded-md px-3 py-2 text-left text-sm transition-colors ${
              i === active
                ? "bg-accent text-foreground font-medium"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t.title}
          </button>
        ))}
      </div>

      {/* Card */}
      <div className="flex-1">
        <div
          key={active}
          className="border-border bg-card animate-in fade-in min-h-58 rounded-xl border p-8 duration-300"
        >
          <threat.icon className="text-primary mb-5 h-7 w-7" />
          <h3 className="text-foreground mb-3 text-xl font-semibold">
            {threat.title}
          </h3>
          <p className="text-muted-foreground leading-relaxed">{threat.desc}</p>
        </div>

        {/* Mobile nav */}
        <div className="mt-4 flex items-center gap-3 sm:hidden">
          <button
            onClick={prev}
            className="text-muted-foreground hover:text-foreground"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <div className="flex flex-1 justify-center gap-1.5">
            {THREATS.map((_, i) => (
              <button
                key={i}
                onClick={() => {
                  setActive(i);
                  setPaused(true);
                }}
                className={`h-1 rounded-full transition-all duration-300 ${
                  i === active ? "bg-primary w-6" : "bg-border w-3"
                }`}
              />
            ))}
          </div>
          <button
            onClick={next}
            className="text-muted-foreground hover:text-foreground"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>

        {/* Progress dots - desktop */}
        <div className="mt-4 hidden gap-1.5 sm:flex">
          {THREATS.map((_, i) => (
            <button
              key={i}
              onClick={() => {
                setActive(i);
                setPaused(true);
              }}
              className={`h-1 rounded-full transition-all duration-300 ${
                i === active ? "bg-primary w-6" : "bg-border w-3"
              }`}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

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

      {/* Stats - commented out until database is re-enabled */}
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
          <h2 className="text-foreground mb-2 text-xl font-semibold">
            What we detect
          </h2>
          <p className="text-muted-foreground mb-10 text-sm">
            Five categories of malicious behaviour, all found in real extensions
            on the Chrome Web Store.
          </p>
          <ThreatCarousel />
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
              desc: "Share your extension list via our Chrome extension or API. No sensitive data leaves your machine - only extension IDs and metadata.",
            },
            {
              step: "02",
              title: "Automated risk analysis",
              desc: "We scan permissions, network behavior, code patterns, and known CVEs across your entire extension set and score each one.",
            },
            {
              step: "03",
              title: "Actionable reports",
              desc: "Get risk-scored results with plain-English explanations. Block, replace, or monitor extensions - with evidence you can share with stakeholders.",
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

      {/* One-time scan - commented out until database is re-enabled */}
      {/* <section id="scan" className="border-border/50 border-y">
        <div className="mx-auto max-w-6xl px-6 py-16">
          <h2 className="text-foreground mb-2 text-xl font-semibold">
            Scan your extensions - free
          </h2>
          <p className="text-muted-foreground mb-8 text-sm">
            Paste your extension list below and we'll check it against our
            database of {stats.total.toLocaleString()} analysed extensions instantly, in your browser.
          </p>
          <OneTimeScan reports={reports} />
        </div>
      </section> */}

      {/* Pricing */}
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
