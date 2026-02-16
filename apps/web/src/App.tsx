import { useMemo } from "react";
import { Eye, Globe, ShieldAlert, Syringe, Wifi } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { ReportMap } from "~/hooks/use-extension-database";
import { DatabaseSection } from "~/components/database-section";
import { ExtensionPreviewCards } from "~/components/extension-preview-cards";
import {
  HeroCycleProvider,
  useHeroCycle,
} from "~/components/hero-cycle-context";
import { TypingTitle } from "~/components/typing-title";
import { formatUsers } from "~/lib/risk";

function HeroSection({ reports }: { reports: ReportMap }) {
  const { pause, resume } = useHeroCycle();

  return (
    <header className="mx-auto flex min-h-screen max-w-6xl items-center px-6">
      <div className="flex w-full flex-col md:flex-row md:items-center md:justify-between">
        <div className="flex-1" onMouseEnter={pause} onMouseLeave={resume}>
          <p className="text-muted-foreground mb-3 text-sm font-medium tracking-wider uppercase">
            Am I Being Pwned
          </p>
          <TypingTitle />
          <p className="text-muted-foreground mb-8 max-w-xl text-lg">
            We use AI tools to analyse Chrome extensions for data harvesting,
            session hijacking, network tampering, and vulnerabilities,
            manually verifying the worst offenders. Install our Chrome
            extension to scan what you have installed or browse the database
            below.
          </p>
          <div className="flex gap-3">
            <Button size="lg" disabled className="hidden sm:inline-flex">
              Install Extension (Coming Soon)
            </Button>
            <Button size="lg" variant="outline" asChild>
              <a href="#database">Browse Database</a>
            </Button>
          </div>
        </div>
        <div className="hidden flex-1 md:block" onMouseEnter={pause} onMouseLeave={resume}>
          <ExtensionPreviewCards reports={reports} />
        </div>
      </div>
    </header>
  );
}

function App({ reports }: { reports: ReportMap }) {
  const stats = useMemo(() => {
    const entries = [...reports.values()];
    const total = entries.length;
    const critical = entries.filter(
      (e) => e.risk === "critical" || e.risk === "high",
    ).length;
    const totalUsers = entries
      .filter(
        (e) =>
          e.risk === "critical" || e.risk === "high" || e.risk === "medium",
      )
      .reduce((sum, e) => sum + e.userCount, 0);
    return { total, critical, totalUsers };
  }, [reports]);

  return (
    <div className="bg-background min-h-screen">
      {/* Hero */}
      <HeroCycleProvider>
        <HeroSection reports={reports} />
      </HeroCycleProvider>

      {/* Nav */}
      <nav className="border-border/50 border-b">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <span className="text-foreground text-sm font-semibold tracking-tight">
            Am I Being Pwned?
          </span>
        </div>
      </nav>

      {/* Stats */}
      <div className="border-border/50 border-y">
        <div className="divide-border/50 mx-auto grid max-w-6xl grid-cols-3 divide-x">
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
            <div className="text-muted-foreground text-sm">Affected users</div>
          </div>
        </div>
      </div>

      {/* What we detect */}
      <section className="mx-auto max-w-6xl px-6 py-16">
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
      </section>

      {/* Database */}
      <DatabaseSection reports={reports} />

      {/* Footer */}
      <footer className="border-border/50 border-t">
        <div className="mx-auto max-w-6xl px-6 py-8 text-center">
          <p className="text-muted-foreground text-sm">
            Made with ❤️ by James Arnott
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
