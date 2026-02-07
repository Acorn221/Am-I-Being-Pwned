import { Badge } from "@acme/ui/badge";
import { Button } from "@acme/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@acme/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@acme/ui/table";

import "./App.css";

type Status = "dangerous" | "suspicious" | "safe";

const sampleExtensions: {
  name: string;
  id: string;
  users: string;
  status: Status;
  issues: string[];
}[] = [
  {
    name: "PDF Toolbox",
    id: "mhjfbmdgcfjbbpaeojofohoefgiehjai",
    users: "2M+",
    status: "dangerous",
    issues: ["Exfiltrates browsing data", "Phones home to C2 server"],
  },
  {
    name: "Autoskip for YouTube",
    id: "hmbnhhcgiecenbbkgdoeclkelmmklhgn",
    users: "9M+",
    status: "dangerous",
    issues: ["Injects affiliate codes", "Tracks all page visits"],
  },
  {
    name: "Crystal Ad Block",
    id: "lklmhefoneoahhcghgapcbdpmjlbfbfj",
    users: "120k+",
    status: "dangerous",
    issues: ["Fake ad blocker", "Harvests cookies & session tokens"],
  },
  {
    name: "HoverZoom+",
    id: "pccckmaobkjjboncdfnnofkonhgpceea",
    users: "800k+",
    status: "suspicious",
    issues: ["Excessive permissions", "Sends data to analytics endpoint"],
  },
  {
    name: "The Great Suspender",
    id: "klbibkeccnjlkjkiokjodocebajanakg",
    users: "2M+",
    status: "dangerous",
    issues: ["Sold to malicious actor", "Executes remote code"],
  },
  {
    name: "uBlock Origin",
    id: "cjpalhdlnbpafiamejdnhcphjbkeiagm",
    users: "40M+",
    status: "safe",
    issues: [],
  },
  {
    name: "Honey",
    id: "bmnlcjabgnpnenekpadlanbbkooimhnj",
    users: "17M+",
    status: "suspicious",
    issues: ["Replaces affiliate codes", "Tracks purchase history"],
  },
  {
    name: "Bitwarden",
    id: "nngceckbapebfimnlniiiahkandclblb",
    users: "3M+",
    status: "safe",
    issues: [],
  },
];

const statusConfig: Record<
  Status,
  { label: string; variant: "destructive" | "outline" | "secondary" }
> = {
  dangerous: { label: "Dangerous", variant: "destructive" },
  suspicious: { label: "Suspicious", variant: "outline" },
  safe: { label: "Safe", variant: "secondary" },
};

const threats = [
  {
    title: "Data Harvesting",
    description:
      "Extensions silently collecting your browsing history, keystrokes, and personal data to sell to third parties.",
    icon: (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="size-6"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
        <path d="m9 12 2 2 4-4" />
      </svg>
    ),
  },
  {
    title: "Session Hijacking",
    description:
      "Malicious extensions stealing your authentication tokens and cookies to impersonate you on websites.",
    icon: (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="size-6"
      >
        <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
  },
  {
    title: "Code Injection",
    description:
      "Extensions injecting scripts into web pages to modify content, redirect traffic, or insert ads and trackers.",
    icon: (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="size-6"
      >
        <polyline points="16 18 22 12 16 6" />
        <polyline points="8 6 2 12 8 18" />
      </svg>
    ),
  },
  {
    title: "Network Tampering",
    description:
      "Intercepting and modifying your web requests to inject malware, alter DNS, or proxy traffic through malicious servers.",
    icon: (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="size-6"
      >
        <path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5" />
        <path d="M8.5 8.5v.01" />
        <path d="M16 15.5v.01" />
        <path d="M12 12v.01" />
        <path d="M11 17v.01" />
        <path d="M7 14v.01" />
      </svg>
    ),
  },
];

function App() {
  return (
    <div className="bg-background min-h-screen">
      {/* Hero */}
      <div className="relative overflow-hidden">
        <div className="via-background to-background absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-red-900/20" />
        <div className="relative mx-auto max-w-5xl px-6 pt-24 pb-16 text-center">
          <Badge variant="destructive" className="mb-6 text-sm">
            Browser Extension Security Scanner
          </Badge>
          <h1 className="text-foreground mb-4 text-5xl font-extrabold tracking-tight sm:text-7xl">
            Am I Being{" "}
            <span className="bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
              Pwned
            </span>
            ?
          </h1>
          <p className="text-muted-foreground mx-auto mb-10 max-w-2xl text-lg">
            Find out if your browser extensions are secretly harvesting your
            data, hijacking your sessions, or doing things they shouldn&apos;t
            be.
          </p>
          <Button size="lg" className="bg-red-600 text-white hover:bg-red-700">
            Scan My Extensions
          </Button>
        </div>
      </div>

      {/* Extensions Table */}
      <div className="mx-auto max-w-5xl px-6 py-16">
        <h2 className="text-foreground mb-2 text-2xl font-bold">
          Known Problematic Extensions
        </h2>
        <p className="text-muted-foreground mb-6">
          Extensions we&apos;ve flagged based on behaviour analysis.
        </p>
        <div className="border-border rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Extension</TableHead>
                <TableHead>Users</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Issues</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sampleExtensions.map((ext) => {
                const cfg = statusConfig[ext.status];
                return (
                  <TableRow key={ext.id}>
                    <TableCell>
                      <div>
                        <div className="text-foreground font-medium">
                          {ext.name}
                        </div>
                        <div className="text-muted-foreground font-mono text-xs">
                          {ext.id}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {ext.users}
                    </TableCell>
                    <TableCell>
                      <Badge variant={cfg.variant}>{cfg.label}</Badge>
                    </TableCell>
                    <TableCell className="max-w-xs">
                      {ext.issues.length > 0 ? (
                        <ul className="text-muted-foreground list-inside list-disc text-sm">
                          {ext.issues.map((issue) => (
                            <li key={issue}>{issue}</li>
                          ))}
                        </ul>
                      ) : (
                        <span className="text-sm text-green-500">
                          No issues found
                        </span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </div>

      {/* Threats */}
      <div className="mx-auto max-w-5xl px-6 py-16">
        <h2 className="text-foreground mb-2 text-2xl font-bold">
          What We Detect
        </h2>
        <p className="text-muted-foreground mb-6">
          The most common ways extensions compromise your security.
        </p>
        <div className="grid gap-6 sm:grid-cols-2">
          {threats.map((threat) => (
            <Card
              key={threat.title}
              className="border-border/50 bg-card/50 transition-colors hover:border-red-500/30"
            >
              <CardHeader>
                <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-red-500/10 text-red-500">
                  {threat.icon}
                </div>
                <CardTitle>{threat.title}</CardTitle>
                <CardDescription>{threat.description}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
      </div>

      {/* Footer */}
      <footer className="border-border text-muted-foreground border-t py-8 text-center text-sm">
        <p>
          Am I Being Pwned? — Open source browser extension security scanner.
        </p>
      </footer>
    </div>
  );
}

export default App;
