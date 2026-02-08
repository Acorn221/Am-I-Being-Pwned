import { useMemo } from "react";

import { Button } from "@amibeingpwned/ui/button";

import { useExtension } from "~/hooks/use-extension";
import { useExtensionDatabase } from "~/hooks/use-extension-database";
import { formatUsers } from "~/lib/risk";
import { DatabaseSection } from "~/components/database-section";
import { ScanSection } from "~/components/scan-section";

function App() {
  const { reports, loading: dbLoading } = useExtensionDatabase();
  const { status, extensions, scan, scanning, error: scanError } = useExtension();

  const stats = useMemo(() => {
    const entries = [...reports.values()];
    const total = entries.length;
    const critical = entries.filter(
      (e) => e.risk === "critical" || e.risk === "high",
    ).length;
    const totalUsers = entries.reduce((sum, e) => sum + e.userCount, 0);
    return { total, critical, totalUsers };
  }, [reports]);

  return (
    <div className="bg-background min-h-screen">
      {/* Nav */}
      <nav className="border-border/50 border-b">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <span className="text-foreground text-sm font-semibold tracking-tight">
            Am I Being Pwned?
          </span>
          <a
            href="https://github.com/AcornPublishing/Am-I-Being-Pwned"
            className="text-muted-foreground hover:text-foreground text-sm transition-colors"
          >
            GitHub
          </a>
        </div>
      </nav>

      {/* Hero */}
      <header className="mx-auto max-w-6xl px-6 pt-20 pb-16">
        <p className="text-muted-foreground mb-3 text-sm font-medium uppercase tracking-wider">
          Chrome Extension Security
        </p>
        <h1 className="text-foreground mb-4 text-4xl font-bold tracking-tight sm:text-5xl">
          Am I Being{" "}
          <span className="bg-linear-to-t from-red-300 to-white bg-clip-text text-transparent">Pwned?</span>
        </h1>
        <p className="text-muted-foreground mb-8 max-w-xl text-lg">
          We use AI tools to analyse Chrome extensions for data harvesting, session hijacking,
          network tampering, and other threats, manually verifying the worst offenders.
          Install our Chrome extension to scan what you have installed or browse the database below.
        </p>
        <div className="flex gap-3">
          {status === "connected" ? (
            <Button size="lg" onClick={() => void scan()} disabled={scanning}>
              {scanning ? "Scanning..." : extensions ? "Rescan" : "Scan My Extensions"}
            </Button>
          ) : status === "not_installed" ? (
            <Button size="lg" asChild>
              <a href="https://chromewebstore.google.com" target="_blank" rel="noreferrer">
                Install Extension
              </a>
            </Button>
          ) : (
            <Button size="lg" disabled>
              Detecting extension...
            </Button>
          )}
          <Button size="lg" variant="outline" asChild>
            <a href="#database">Browse Database</a>
          </Button>
        </div>
      </header>

      {/* Stats */}
      <div className="border-border/50 border-y">
        <div className="mx-auto grid max-w-6xl grid-cols-3 divide-x divide-border/50">
          <div className="px-6 py-6">
            <div className="text-foreground text-2xl font-bold">
              {stats.total}
            </div>
            <div className="text-muted-foreground text-sm">
              Extensions analysed
            </div>
          </div>
          <div className="px-6 py-6">
            <div className="text-2xl font-bold text-red-400">
              {stats.critical}
            </div>
            <div className="text-muted-foreground text-sm">
              High / Critical risk
            </div>
          </div>
          <div className="px-6 py-6">
            <div className="text-foreground text-2xl font-bold">
              {formatUsers(stats.totalUsers)}
            </div>
            <div className="text-muted-foreground text-sm">
              Affected users
            </div>
          </div>
        </div>
      </div>

      {/* Scan */}
      <ScanSection
        status={status}
        extensions={extensions}
        scan={scan}
        scanning={scanning}
        scanError={scanError}
        reports={reports}
        dbLoading={dbLoading}
      />

      {/* How it works */}
      <section className="mx-auto max-w-6xl px-6 py-16">
        <h2 className="text-foreground mb-8 text-xl font-semibold">
          How it works
        </h2>
        <div className="grid gap-8 sm:grid-cols-3">
          <div>
            <div className="text-muted-foreground mb-2 text-sm font-medium">01</div>
            <h3 className="text-foreground mb-1 font-medium">Install</h3>
            <p className="text-muted-foreground text-sm">
              Add the extension to your browser. It only needs the{" "}
              <code className="rounded bg-zinc-800 px-1 py-0.5 text-xs">management</code>{" "}
              permission to list your extensions.
            </p>
          </div>
          <div>
            <div className="text-muted-foreground mb-2 text-sm font-medium">02</div>
            <h3 className="text-foreground mb-1 font-medium">Scan</h3>
            <p className="text-muted-foreground text-sm">
              Visit this page and your extensions are automatically checked
              against our threat database.
            </p>
          </div>
          <div>
            <div className="text-muted-foreground mb-2 text-sm font-medium">03</div>
            <h3 className="text-foreground mb-1 font-medium">Review</h3>
            <p className="text-muted-foreground text-sm">
              See which extensions are flagged, why they were flagged, and what
              endpoints they communicate with.
            </p>
          </div>
        </div>
      </section>

      {/* What we detect */}
      <section className="border-border/50 border-y">
        <div className="mx-auto max-w-6xl px-6 py-16">
          <h2 className="text-foreground mb-8 text-xl font-semibold">
            What we detect
          </h2>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { title: "Data Harvesting", desc: "Extensions silently collecting browsing history, keystrokes, and personal data." },
              { title: "Session Hijacking", desc: "Stealing authentication tokens and cookies to impersonate you on websites." },
              { title: "Code Injection", desc: "Injecting scripts into pages to modify content, redirect traffic, or insert ads." },
              { title: "Network Tampering", desc: "Intercepting requests to inject malware, alter DNS, or proxy through malicious servers." },
              { title: "Vulnerabilities", desc: "Extensions that have poor security hygiene or vulnerabilities." },

            ].map((threat) => (
              <div key={threat.title}>
                <h3 className="text-foreground mb-1 text-sm font-medium">{threat.title}</h3>
                <p className="text-muted-foreground text-sm">{threat.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Database */}
      <DatabaseSection reports={reports} />

      {/* Footer */}
      <footer className="border-border/50 border-t">
        <div className="mx-auto max-w-6xl px-6 py-8">
          <div className="text-muted-foreground flex items-center justify-between text-sm">
            <span>Am I Being Pwned?</span>
            <span>Open source browser extension security scanner</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
