import { useCallback, useEffect, useState } from "react";
import {
  Check,
  ChevronLeft,
  ChevronRight,
  Eye,
  Globe,
  ShieldAlert,
  Syringe,
  Wifi,
  X,
} from "lucide-react";

import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@amibeingpwned/ui";

import type { DetectedExtension } from "~/hooks/use-extension-probe";
import type { ReportMap } from "~/hooks/use-extension-database";
import { useExtensionProbe } from "~/hooks/use-extension-probe";
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
    desc: "Extensions silently collect browsing history, keystrokes, form inputs, and personal data - then upload it to remote servers. Often disguised as productivity tools or ad blockers, these extensions can build detailed profiles of every employee in your organisation without anyone noticing.",
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
    title: "Vulnerability Discovery",
    desc: "Many extensions are built with little regard for security and are vulnerable to attacks, we have already identified over 4 vulnerabilities in popular extensions with CVSS scores between 8 and 9.6",
  },
  {
    icon: ShieldAlert,
    title: "Known Vulnerabilities",
    desc: "Beyond malicious intent, many extensions have poor security hygiene: outdated dependencies with known CVEs, insecure data storage, and un-validated remote code execution paths. Any of these can be exploited by a third party.",
  },
] as const;

const INTERVAL_MS = 5000;
const SLIDE_DURATION = 350;

function ThreatCarousel() {
  const [active, setActive] = useState(0);
  const [prevIndex, setPrevIndex] = useState<number | null>(null);
  const [direction, setDirection] = useState<"forward" | "back">("forward");
  const [paused, setPaused] = useState(false);

  const goTo = useCallback(
    (index: number) => {
      if (prevIndex !== null || index === active) return;
      const n = THREATS.length;
      const diff = (index - active + n) % n;
      const dir: "forward" | "back" = diff <= n / 2 ? "forward" : "back";
      setDirection(dir);
      setPrevIndex(active);
      setActive(index);
      setTimeout(() => setPrevIndex(null), SLIDE_DURATION);
    },
    [active, prevIndex],
  );

  useEffect(() => {
    if (paused) return;
    const id = setInterval(() => {
      goTo((active + 1) % THREATS.length);
    }, INTERVAL_MS);
    return () => clearInterval(id);
  }, [paused, active, goTo]);

  const threat = THREATS[active];
  if (!threat) return null;

  function prev() {
    goTo((active - 1 + THREATS.length) % THREATS.length);
    setPaused(true);
  }

  function next() {
    goTo((active + 1) % THREATS.length);
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
              goTo(i);
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
        <style>{`
          @keyframes slide-in-right  { from { transform: translateX(100%); } to { transform: translateX(0); } }
          @keyframes slide-out-left  { from { transform: translateX(0); }    to { transform: translateX(-100%); } }
          @keyframes slide-in-left   { from { transform: translateX(-100%); } to { transform: translateX(0); } }
          @keyframes slide-out-right { from { transform: translateX(0); }    to { transform: translateX(100%); } }
        `}</style>
        <div className="relative h-64 overflow-hidden rounded-xl">
          {/* Outgoing card */}
          {prevIndex !== null &&
            (() => {
              const prev = THREATS[prevIndex];
              if (!prev) return null;
              return (
                <div
                  className="border-border bg-card absolute inset-0 rounded-xl border p-8"
                  style={{
                    animation: `${direction === "forward" ? "slide-out-left" : "slide-out-right"} ${SLIDE_DURATION}ms ease forwards`,
                  }}
                >
                  <prev.icon className="text-primary mb-5 h-7 w-7" />
                  <h3 className="text-foreground mb-3 text-xl font-semibold">
                    {prev.title}
                  </h3>
                  <p className="text-muted-foreground leading-relaxed">
                    {prev.desc}
                  </p>
                </div>
              );
            })()}

          {/* Incoming card */}
          <div
            className={`border-border bg-card h-full rounded-xl border p-8${prevIndex !== null ? "absolute inset-0" : ""}`}
            style={
              prevIndex !== null
                ? {
                    animation: `${direction === "forward" ? "slide-in-right" : "slide-in-left"} ${SLIDE_DURATION}ms ease forwards`,
                  }
                : {}
            }
          >
            <threat.icon className="text-primary mb-5 h-7 w-7" />
            <h3 className="text-foreground mb-3 text-xl font-semibold">
              {threat.title}
            </h3>
            <p className="text-muted-foreground leading-relaxed">
              {threat.desc}
            </p>
          </div>
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
                  goTo(i);
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
                goTo(i);
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

const RISK_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

const RISK_PRIORITY = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const riskRank = (risk: string) => {
  const i = RISK_PRIORITY.indexOf(risk);
  return i === -1 ? 99 : i;
};
const RISK_DOT: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
};

function ScanModal({
  detected,
  open,
  onClose,
}: {
  detected: DetectedExtension[];
  open: boolean;
  onClose: () => void;
}) {
  const sorted = [...detected].sort((a, b) => riskRank(a.risk) - riskRank(b.risk));

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-lg p-0 gap-0 overflow-hidden">
        <DialogHeader className="border-border border-b px-6 py-5 text-left">
          <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-red-500/15">
            <ShieldAlert className="h-5 w-5 text-red-400" />
          </div>
          <DialogTitle>
            {detected.length} threat{detected.length !== 1 ? "s" : ""} detected
            on this browser
          </DialogTitle>
          <DialogDescription>
            We found flagged extensions installed right now. Here's what we
            know.
          </DialogDescription>
        </DialogHeader>

        <ul className="divide-border max-h-72 divide-y overflow-y-auto">
          {sorted.map((e) => (
            <li key={e.id} className="flex items-start gap-3 px-6 py-4">
              <span
                className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${(RISK_DOT[e.risk] ?? "bg-yellow-500")}`}
              />
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded border px-1.5 py-0.5 text-xs font-medium ${(RISK_STYLES[e.risk] ?? RISK_STYLES.MEDIUM)}`}
                  >
                    {e.risk}
                  </span>
                  <span className="text-foreground truncate text-sm font-medium">
                    {e.name}
                  </span>
                </div>
                <p className="text-muted-foreground mt-1 text-xs leading-relaxed">
                  {e.summary.split(". ")[0]}.
                </p>
              </div>
            </li>
          ))}
        </ul>

        <DialogFooter className="border-border flex-col items-start border-t px-6 py-4 sm:flex-col">
          <p className="text-muted-foreground mb-3 text-xs">
            This is one device. Imagine this across your entire fleet.
          </p>
          <div className="flex w-full gap-3">
            <Button size="sm" asChild className="flex-1">
              <a
                href="https://calendar.app.google/ErKTbbbDDHzjAEESA"
                target="_blank"
                rel="noreferrer"
              >
                Book a Demo
              </a>
            </Button>
            <Button size="sm" variant="outline" onClick={onClose}>
              Dismiss
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ScanResultsSection({
  detected,
  probing,
}: {
  detected: DetectedExtension[];
  probing: boolean;
}) {
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;
  if (probing) {
    return (
      <div className="border-border/50 border-b">
        <div className="mx-auto flex max-w-6xl items-center gap-3 px-6 py-3">
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="bg-primary absolute inline-flex h-full w-full animate-ping rounded-full opacity-75" />
            <span className="bg-primary relative inline-flex h-2 w-2 rounded-full" />
          </span>
          <span className="text-muted-foreground text-xs">
            Scanning your browser extensions...
          </span>
        </div>
      </div>
    );
  }

  if (detected.length === 0) return null;

  const sorted = [...detected].sort(
    (a, b) =>
      riskRank(a.risk) - riskRank(b.risk),
  );

  return (
    <div className="border-border/50 border-b bg-red-500/5">
      <div className="mx-auto max-w-6xl px-6 py-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 shrink-0 text-red-400" />
            <span className="text-foreground text-sm font-medium">
              {detected.length} flagged extension
              {detected.length !== 1 ? "s" : ""} on this browser
            </span>
          </div>
          <button
            onClick={() => setDismissed(true)}
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {sorted.map((e) => (
            <span
              key={e.id}
              className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs ${(RISK_STYLES[e.risk] ?? RISK_STYLES.MEDIUM)}`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${(RISK_DOT[e.risk] ?? "bg-yellow-500")}`}
              />
              <span className="font-medium">{e.risk}</span>
              <span className="opacity-75">{e.name}</span>
            </span>
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
  const { detected, probing } = useExtensionProbe();
  const [modalDismissed, setModalDismissed] = useState(false);

  const threats = detected.filter(
    (e) => e.risk === "CRITICAL" || e.risk === "HIGH",
  );
  const showModal = !probing && !modalDismissed && threats.length > 0;

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

      <ScanModal
        detected={threats}
        open={showModal}
        onClose={() => setModalDismissed(true)}
      />

      <ScanResultsSection detected={detected} probing={probing} />

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
            Five categories of malicious behavior, all found in real extensions
            on the Chrome Web Store.
          </p>
          <ThreatCarousel />
        </div>
      </section>

      {/* Proof of concept videos */}
      <section className="mx-auto max-w-6xl px-6 pt-8 pb-4">
        <h2 className="text-foreground mb-2 text-xl font-semibold">
          Caught in the wild
        </h2>
        <p className="text-muted-foreground mb-8 text-sm">
          Real extensions, real exfiltration - recorded and verified by our
          team.
        </p>
        <div className="grid gap-8 sm:grid-cols-3">
          {[
            {
              id: "PQDfvDpT5Ls",
              title: "Ad blocker exfiltrating every URL you visit",
              desc: "A popular ad blocker silently uploading your full browsing history to remote servers - every page, every click.",
            },
            {
              id: "UYwUmaVohQk",
              title: "WhatRuns caught scraping AI chats",
              desc: "WhatRuns was found harvesting full browsing URLs and the contents of AI chat sessions without any user knowledge or consent.",
            },
            {
              id: "IOdGJEky1SU",
              title: "StayFocusd: productivity tool or spyware?",
              desc: "A widely-trusted productivity extension demonstrated exfiltrating complete browsing history data in real time.",
            },
          ].map((video) => (
            <div key={video.id} className="flex flex-col gap-3">
              <div className="border-border overflow-hidden rounded-lg border">
                <iframe
                  src={`https://www.youtube-nocookie.com/embed/${video.id}`}
                  title={video.title}
                  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                  allowFullScreen
                  className="aspect-video w-full"
                />
              </div>
              <h3 className="text-foreground text-sm font-semibold">
                {video.title}
              </h3>
              <p className="text-muted-foreground text-xs leading-relaxed">
                {video.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" className="mx-auto max-w-6xl px-6 py-16">
        <h2 className="text-foreground mb-2 text-xl font-semibold">
          How it works
        </h2>
        <p className="text-muted-foreground mb-12 text-sm">
          Turn around your browser security in under 48 hours, with no
          deployment or maintenance overhead.
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
              desc: "We use a combination of static analysis, LLM agents and human expertise to identify problematic extensions.",
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
