import { useMutation } from "@tanstack/react-query";
import {
  AlertTriangle,
  CalendarDays,
  Check,
  CheckCircle2,
  ChevronRight,
  Copy,
  HelpCircle,
  Loader2,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@amibeingpwned/ui/dialog";

import { Navbar } from "~/components/navbar";
import { useTRPC } from "~/lib/trpc";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BOOK_A_CALL_URL = "https://calendar.app.google/ErKTbbbDDHzjAEESA";
const EXT_ID_RE = /\b[a-p]{32}\b/g;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Step =
  | { kind: "loading" }
  | { kind: "invalid" }
  | { kind: "paste"; label: string }
  | { kind: "scanning" }
  | { kind: "results"; label: string; data: ScanResult };

interface ExtensionResult {
  id: string;
  name: string | null;
  riskScore: number | null;
  risk: string;
  isFlagged: boolean;
}

interface ScanResult {
  extensions: ExtensionResult[];
  riskCounts: Record<string, number>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseExtensionIds(text: string): string[] {
  const matches = text.match(EXT_ID_RE);
  if (!matches) return [];
  return [...new Set(matches)];
}

const RISK_STYLES: Record<string, { pill: string; dot: string; label: string }> = {
  critical: {
    pill: "bg-red-500/15 text-red-500 border border-red-500/30",
    dot: "bg-red-500",
    label: "Critical",
  },
  high: {
    pill: "bg-orange-500/15 text-orange-500 border border-orange-500/30",
    dot: "bg-orange-500",
    label: "High",
  },
  medium: {
    pill: "bg-yellow-500/15 text-yellow-600 border border-yellow-500/30",
    dot: "bg-yellow-500",
    label: "Medium",
  },
  low: {
    pill: "bg-blue-500/15 text-blue-500 border border-blue-500/30",
    dot: "bg-blue-500",
    label: "Low",
  },
  clean: {
    pill: "bg-emerald-500/15 text-emerald-600 border border-emerald-500/30",
    dot: "bg-emerald-500",
    label: "Clean",
  },
  unscanned: {
    pill: "bg-muted text-muted-foreground border border-border",
    dot: "bg-muted-foreground",
    label: "Not in database",
  },
};

function getRisk(risk: string) {
  return RISK_STYLES[risk] ?? RISK_STYLES["unscanned"]!;
}

const HELP_STEPS = [
  {
    n: 1,
    title: 'Find "extensions" and click Expand',
    caption:
      'Scroll down the page until you see the extensions row. Click the Expand... button next to it.',
    img: "/imgs/expand-btn.png",
    alt: "chrome://system page with arrow pointing to the Expand button next to extensions",
  },
  {
    n: 2,
    title: "Select all the text and copy it",
    caption:
      "Click anywhere in the expanded text, press Cmd+A (Mac) or Ctrl+A (Windows) to select everything, then Cmd+C / Ctrl+C to copy.",
    img: "/imgs/copy-img.png",
    alt: "Expanded extensions list with arrow showing the text to select and copy",
  },
] as const;

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <button
      onClick={() => void handleCopy()}
      className="bg-muted hover:bg-muted/80 border-border inline-flex items-center gap-2 rounded-lg border px-3 py-2 font-mono text-sm transition-colors"
    >
      <span className="text-foreground">{text}</span>
      <span className="text-muted-foreground ml-1 flex items-center gap-1 text-xs">
        {copied ? (
          <>
            <Check className="h-3 w-3 text-emerald-500" />
            <span className="text-emerald-500">Copied</span>
          </>
        ) : (
          <>
            <Copy className="h-3 w-3" />
            Copy
          </>
        )}
      </span>
    </button>
  );
}

function StepRow({
  n,
  title,
  children,
  last,
  action,
}: {
  n: number;
  title: string;
  children: React.ReactNode;
  last?: boolean;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex gap-4">
      <div className="flex flex-col items-center">
        <div className="bg-primary text-primary-foreground flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-bold">
          {n}
        </div>
        {!last && <div className="bg-border mt-2 w-px flex-1" />}
      </div>
      <div className={`pb-8 ${last ? "pb-0" : ""} min-w-0 flex-1 pt-1`}>
        <div className="mb-2 flex items-center gap-3">
          <p className="text-foreground font-semibold">{title}</p>
          {action}
        </div>
        {children}
      </div>
    </div>
  );
}

function ExtensionRow({ ext }: { ext: ExtensionResult }) {
  const r = getRisk(ext.risk);
  const isBad = ext.risk === "critical" || ext.risk === "high" || ext.isFlagged;

  return (
    <div
      className={`flex items-center gap-3 rounded-lg px-4 py-3 ${
        isBad
          ? "bg-destructive/5 border border-destructive/20"
          : "bg-muted/40 border border-transparent"
      }`}
    >
      <div className={`h-2 w-2 shrink-0 rounded-full ${r.dot}`} />
      <div className="min-w-0 flex-1">
        <p className="text-foreground truncate text-sm font-medium">
          {ext.name ?? ext.id}
        </p>
        {ext.name && (
          <p className="text-muted-foreground truncate font-mono text-[11px]">
            {ext.id}
          </p>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {ext.riskScore !== null && (
          <span className="text-muted-foreground w-6 text-right text-xs tabular-nums">
            {ext.riskScore}
          </span>
        )}
        <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${r.pill}`}>
          {r.label}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Help modal
// ---------------------------------------------------------------------------

function HelpModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl gap-0 overflow-hidden p-0">
        <DialogHeader className="border-b px-6 py-4">
          <DialogTitle className="flex items-center gap-2 text-base">
            <HelpCircle className="text-primary h-4 w-4" />
            How to get your extension list
          </DialogTitle>
        </DialogHeader>

        <div className="divide-y overflow-y-auto">
          {HELP_STEPS.map((step) => (
            <div key={step.n} className="px-6 py-5">
              <div className="mb-3 flex items-center gap-3">
                <span className="bg-primary text-primary-foreground flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold">
                  {step.n}
                </span>
                <p className="text-foreground font-semibold">{step.title}</p>
              </div>
              <p className="text-muted-foreground mb-4 text-sm leading-relaxed">
                {step.caption}
              </p>
              <div className="border-border overflow-hidden rounded-xl border bg-black/5 dark:bg-white/5">
                <img
                  src={step.img}
                  alt={step.alt}
                  className="h-auto w-full object-contain"
                  draggable={false}
                />
              </div>
            </div>
          ))}
        </div>

        <div className="border-t px-6 py-4">
          <Button onClick={onClose} className="w-full sm:w-auto">
            <X className="mr-1.5 h-4 w-4" />
            Got it, close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function DemoPage({ token }: { token: string }) {
  const trpc = useTRPC();
  const [step, setStep] = useState<Step>({ kind: "loading" });
  const [pasteText, setPasteText] = useState("");
  const [showHelp, setShowHelp] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const validateMutation = useMutation(trpc.demo.validateToken.mutationOptions());
  const scanMutation = useMutation(trpc.demo.scan.mutationOptions());

  useEffect(() => {
    validateMutation.mutate(
      { token },
      {
        onSuccess(data) {
          setStep(data.valid ? { kind: "paste", label: data.label } : { kind: "invalid" });
        },
        onError() {
          setStep({ kind: "invalid" });
        },
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  function handleScan() {
    const ids = parseExtensionIds(pasteText);
    if (ids.length === 0) return;
    const label = step.kind === "paste" ? step.label : "";
    setStep({ kind: "scanning" });
    scanMutation.mutate(
      { token, extensionIds: ids },
      {
        onSuccess(data) {
          setStep({ kind: "results", label, data: data as ScanResult });
        },
        onError() {
          setStep({ kind: "paste", label });
        },
      },
    );
  }

  // ---------------------------------------------------------------------------
  // Loading / scanning
  // ---------------------------------------------------------------------------

  if (step.kind === "loading" || step.kind === "scanning") {
    return (
      <div className="bg-background flex min-h-screen flex-col">
        <Navbar />
        <div className="flex flex-1 flex-col items-center justify-center gap-4">
          <div className="relative">
            <ScanSearch className="text-primary h-12 w-12" />
            <Loader2 className="text-primary absolute -right-1 -top-1 h-5 w-5 animate-spin" />
          </div>
          <p className="text-muted-foreground text-sm">
            {step.kind === "loading" ? "Loading your scan link..." : "Analysing your extensions..."}
          </p>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Invalid link
  // ---------------------------------------------------------------------------

  if (step.kind === "invalid") {
    return (
      <div className="bg-background flex min-h-screen flex-col">
        <Navbar />
        <div className="flex flex-1 items-center justify-center px-4">
          <div className="w-full max-w-sm text-center">
            <div className="bg-muted mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full">
              <AlertTriangle className="text-muted-foreground h-6 w-6" />
            </div>
            <h2 className="text-foreground mb-2 text-xl font-semibold">
              Link not found
            </h2>
            <p className="text-muted-foreground text-sm leading-relaxed">
              This demo link has expired or been revoked. Reach out to the person who shared
              it for a fresh one.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Results
  // ---------------------------------------------------------------------------

  if (step.kind === "results") {
    const { data } = step;
    const total = Object.values(data.riskCounts).reduce((a, b) => a + b, 0);
    const threats = (data.riskCounts.critical ?? 0) + (data.riskCounts.high ?? 0);
    const flaggedExts = data.extensions.filter(
      (e) => e.isFlagged || e.risk === "critical" || e.risk === "high",
    );
    const otherExts = data.extensions.filter(
      (e) => !e.isFlagged && e.risk !== "critical" && e.risk !== "high",
    );
    const allClear = threats === 0;

    return (
      <div className="bg-background min-h-screen">
        <Navbar />

        {/* Hero banner */}
        <div
          className={`border-b px-4 py-10 text-center ${
            allClear
              ? "from-emerald-500/5 to-background bg-gradient-to-b"
              : "from-destructive/8 to-background bg-gradient-to-b"
          }`}
        >
          <div
            className={`mx-auto mb-3 flex h-16 w-16 items-center justify-center rounded-full ${
              allClear ? "bg-emerald-500/15" : "bg-destructive/15"
            }`}
          >
            {allClear ? (
              <ShieldCheck className="h-8 w-8 text-emerald-500" />
            ) : (
              <ShieldAlert className="text-destructive h-8 w-8" />
            )}
          </div>
          <h1 className="text-foreground mb-2 text-2xl font-bold">
            {allClear
              ? "No high-risk extensions found"
              : `${threats} high-risk extension${threats === 1 ? "" : "s"} detected`}
          </h1>
          <p className="text-muted-foreground text-sm">
            Scanned {total} extension{total === 1 ? "" : "s"} against the Am I Being Pwned? threat database.
          </p>
        </div>

        <div className="mx-auto max-w-2xl px-4 py-8">
          {/* Stats row */}
          <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: "Total scanned", value: total, style: "text-foreground" },
              {
                label: "High / Critical",
                value: (data.riskCounts.critical ?? 0) + (data.riskCounts.high ?? 0),
                style: threats > 0 ? "text-destructive" : "text-muted-foreground",
              },
              {
                label: "Medium risk",
                value: data.riskCounts.medium ?? 0,
                style: (data.riskCounts.medium ?? 0) > 0 ? "text-orange-500" : "text-muted-foreground",
              },
              {
                label: "Not in database",
                value: data.riskCounts.unscanned ?? 0,
                style: "text-muted-foreground",
              },
            ].map(({ label, value, style }) => (
              <div key={label} className="bg-muted/50 border-border rounded-xl border p-4 text-center">
                <div className={`text-3xl font-bold tabular-nums ${style}`}>{value}</div>
                <div className="text-muted-foreground mt-1 text-xs">{label}</div>
              </div>
            ))}
          </div>

          {/* Flagged */}
          {flaggedExts.length > 0 && (
            <section className="mb-6">
              <h2 className="text-destructive mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-widest">
                <ShieldAlert className="h-3.5 w-3.5" />
                Threats detected
              </h2>
              <div className="flex flex-col gap-2">
                {flaggedExts.map((ext) => (
                  <ExtensionRow key={ext.id} ext={ext} />
                ))}
              </div>
            </section>
          )}

          {/* Others */}
          {otherExts.length > 0 && (
            <section className="mb-8">
              <h2 className="text-muted-foreground mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-widest">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Other extensions
              </h2>
              <div className="flex flex-col gap-1.5">
                {otherExts.map((ext) => (
                  <ExtensionRow key={ext.id} ext={ext} />
                ))}
              </div>
            </section>
          )}

          {/* Book a call */}
          <div className="from-primary/10 via-primary/5 to-background rounded-2xl border bg-gradient-to-br p-6">
            <div className="mb-5 flex items-start gap-4">
              <div className="bg-primary/10 flex h-10 w-10 shrink-0 items-center justify-center rounded-full">
                <CalendarDays className="text-primary h-5 w-5" />
              </div>
              <div>
                <h3 className="text-foreground mb-1 font-semibold">
                  Want to protect your whole team?
                </h3>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Book a 30-minute call - we'll walk you through what we found and show
                  you how Am I Being Pwned? monitors and enforces extension policies
                  across your entire fleet, automatically.
                </p>
              </div>
            </div>
            <Button size="lg" asChild className="w-full sm:w-auto">
              <a href={BOOK_A_CALL_URL} target="_blank" rel="noreferrer">
                Book a call
                <ChevronRight className="ml-1 h-4 w-4" />
              </a>
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Paste step
  // ---------------------------------------------------------------------------

  const parsedIds = parseExtensionIds(pasteText);
  const canScan = parsedIds.length > 0;

  return (
    <div className="bg-background min-h-screen">
      <HelpModal open={showHelp} onClose={() => setShowHelp(false)} />
      <Navbar />

      {/* Hero */}
      <div className="from-primary/5 to-background border-b bg-gradient-to-b px-4 py-12 text-center">
        <div className="bg-primary/10 mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full">
          <ScanSearch className="text-primary h-7 w-7" />
        </div>
        <h1 className="text-foreground mb-2 text-3xl font-bold tracking-tight">
          Scan your extensions
        </h1>
        <p className="text-muted-foreground mx-auto max-w-md text-base">
          Find out which browser extensions on your machine are risky - takes 30 seconds,
          no account needed.
        </p>
      </div>

      <div className="mx-auto max-w-xl px-4 py-10">
        {/* Steps */}
        <div className="mb-10">
          <StepRow n={1} title="Open Chrome's system info page">
            <p className="text-muted-foreground mb-3 text-sm leading-relaxed">
              Click the button below to copy the address, then open a new tab, paste it
              into the address bar, and press Enter.
            </p>
            <CopyButton text="chrome://system" label="Copy URL" />
          </StepRow>

          <StepRow
            n={2}
            title="Expand the extensions section"
            action={
              <button
                onClick={() => setShowHelp(true)}
                className="text-primary hover:text-primary/80 flex items-center gap-1 text-xs font-medium transition-colors"
              >
                <HelpCircle className="h-3.5 w-3.5" />
                Show me how
              </button>
            }
          >
            <p className="text-muted-foreground text-sm leading-relaxed">
              Scroll down the page until you see a row labelled{" "}
              <span className="text-foreground font-medium">extensions</span>. Click the{" "}
              <span className="text-foreground font-medium">expand</span> button next to
              it to reveal the full list.
            </p>
          </StepRow>

          <StepRow n={3} title="Select all, copy, and paste below" last>
            <p className="text-muted-foreground mb-4 text-sm leading-relaxed">
              Click anywhere inside the expanded text, press{" "}
              <kbd className="bg-muted border-border rounded border px-1.5 py-0.5 font-mono text-xs">
                Cmd+A
              </kbd>{" "}
              or{" "}
              <kbd className="bg-muted border-border rounded border px-1.5 py-0.5 font-mono text-xs">
                Ctrl+A
              </kbd>{" "}
              to select everything, then paste it into the box below.
            </p>

            <div className="bg-card border-border overflow-hidden rounded-xl border shadow-sm">
              <textarea
                ref={textareaRef}
                value={pasteText}
                onChange={(e) => setPasteText(e.target.value)}
                placeholder="Paste the text from chrome://system here..."
                className="placeholder:text-muted-foreground focus:outline-none w-full resize-none bg-transparent p-4 font-mono text-xs leading-relaxed"
                rows={7}
              />
              <div className="border-border flex items-center justify-between border-t px-4 py-3">
                <span className="text-muted-foreground text-xs">
                  {pasteText.length === 0
                    ? "Waiting for paste..."
                    : canScan
                      ? `${parsedIds.length} extension${parsedIds.length === 1 ? "" : "s"} detected`
                      : "No extension IDs found - paste the full expanded section"}
                </span>
                <Button
                  onClick={() => handleScan()}
                  disabled={!canScan || scanMutation.isPending}
                  size="sm"
                >
                  {scanMutation.isPending ? (
                    <>
                      <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      Scan now
                      <ChevronRight className="ml-1 h-3.5 w-3.5" />
                    </>
                  )}
                </Button>
              </div>
            </div>

            {scanMutation.isError && (
              <p className="text-destructive mt-2 text-sm">
                Something went wrong. Please try again.
              </p>
            )}
          </StepRow>
        </div>
      </div>
    </div>
  );
}
