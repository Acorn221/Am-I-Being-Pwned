import { useState } from "react";
import {
  ArrowLeft,
  Building2,
  Check,
  ChevronRight,
  Globe,
  KeyRound,
  Link2,
  Puzzle,
  ShieldCheck,
  X,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

// Scopes required only for the Workspace path (Chrome Management API)
const WORKSPACE_SCOPES = [
  "https://www.googleapis.com/auth/chrome.management.appdetails.readonly",
  "https://www.googleapis.com/auth/chrome.management.reports.readonly",
];

type Method = "workspace" | "extension" | null;
type Step = 1 | 2;

// ---- step indicator -------------------------------------------------------

function StepIndicator({ step }: { step: Step }) {
  return (
    <div className="mb-10 flex flex-col items-center gap-3">
      <div className="flex items-center gap-2">
        <StepDot active={step >= 1} done={step > 1} label="1" />
        <div
          className={`h-px w-10 transition-colors ${step > 1 ? "bg-primary" : "bg-border"}`}
        />
        <StepDot active={step >= 2} done={false} label="2" />
      </div>
      <p className="text-muted-foreground text-xs">Step {step} of 2</p>
    </div>
  );
}

function StepDot({
  active,
  done,
  label,
}: {
  active: boolean;
  done: boolean;
  label: string;
}) {
  return (
    <div
      className={`flex h-7 w-7 items-center justify-center rounded-full border text-xs font-semibold transition-all ${
        done
          ? "border-primary bg-primary text-primary-foreground"
          : active
            ? "border-primary text-primary"
            : "border-border text-muted-foreground"
      }`}
    >
      {done ? <Check className="h-3.5 w-3.5" /> : label}
    </div>
  );
}

// ---- step 1: pick a method ------------------------------------------------

const METHODS = [
  {
    id: "workspace" as const,
    icon: Building2,
    iconBg: "bg-sky-500/10",
    iconColor: "text-sky-400",
    tag: "Managed fleets",
    tagColor: "bg-sky-500/10 text-sky-400",
    title: "Google Workspace",
    desc: "Pull extension data across your entire fleet via the Chrome Management API. Zero software to deploy - Google already has the inventory.",
    pros: [
      "Instant fleet-wide visibility with no per-device setup",
      "Automatically covers every managed Chrome device",
      "Single sign-on - no extra credentials to manage",
    ],
    cons: [
      "Requires a Google Workspace subscription",
      "Only covers devices enrolled in Chrome Browser Cloud Management",
    ],
  },
  {
    id: "extension" as const,
    icon: Puzzle,
    iconBg: "bg-violet-500/10",
    iconColor: "text-violet-400",
    tag: "Any browser",
    tagColor: "bg-violet-500/10 text-violet-400",
    title: "Chrome Extension",
    desc: "Install our lightweight extension on each machine. Works on personal or unmanaged devices that Google Workspace can't see.",
    pros: [
      "No Workspace subscription required",
      "Covers BYOD and unmanaged devices",
      "Real-time data direct from each browser",
    ],
    cons: [
      "Extension must be installed on each device individually",
      "Each device needs an invite link generated from your dashboard",
    ],
  },
] as const;

function Step1({
  selected,
  onSelect,
  onContinue,
}: {
  selected: Method;
  onSelect: (m: Method) => void;
  onContinue: () => void;
}) {
  return (
    <div className="w-full max-w-3xl">
      <div className="mb-8 text-center">
        <h1 className="text-foreground mb-2 text-2xl font-semibold tracking-tight">
          How will you connect your devices?
        </h1>
        <p className="text-muted-foreground text-sm">
          Both methods give you the same risk scoring and alerts. Pick the one
          that fits your setup.
        </p>
      </div>

      <div className="mb-8 grid gap-4 sm:grid-cols-2">
        {METHODS.map((m) => {
          const Icon = m.icon;
          const isSelected = selected === m.id;
          return (
            <button
              key={m.id}
              onClick={() => onSelect(m.id)}
              className={`group relative flex cursor-pointer flex-col rounded-xl border p-6 text-left transition-all ${
                isSelected
                  ? "border-primary bg-primary/5 ring-1 ring-primary"
                  : "border-border bg-card hover:border-border/80 hover:bg-card/80"
              }`}
            >
              {isSelected && (
                <span className="bg-primary text-primary-foreground absolute right-4 top-4 flex h-5 w-5 items-center justify-center rounded-full">
                  <Check className="h-3 w-3" />
                </span>
              )}

              <div className="mb-4 flex items-center gap-3">
                <div className={`rounded-lg p-2.5 ${m.iconBg}`}>
                  <Icon className={`h-5 w-5 ${m.iconColor}`} />
                </div>
                <span
                  className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${m.tagColor}`}
                >
                  {m.tag}
                </span>
              </div>

              <h2 className="text-foreground mb-2 text-base font-semibold">
                {m.title}
              </h2>
              <p className="text-muted-foreground mb-5 text-xs leading-relaxed">
                {m.desc}
              </p>

              <ul className="mt-auto space-y-2 text-xs">
                {m.pros.map((p) => (
                  <li key={p} className="flex items-start gap-2">
                    <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" />
                    <span className="text-foreground/80">{p}</span>
                  </li>
                ))}
                {m.cons.map((c) => (
                  <li key={c} className="flex items-start gap-2">
                    <X className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                    <span className="text-muted-foreground">{c}</span>
                  </li>
                ))}
              </ul>
            </button>
          );
        })}
      </div>

      <div className="flex justify-center">
        <Button
          size="lg"
          disabled={!selected}
          onClick={onContinue}
          className="gap-2 px-10"
        >
          Continue
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

// ---- step 2a: google workspace --------------------------------------------

function Step2Workspace({
  onBack,
  onSignIn,
  loading,
  error,
}: {
  onBack: () => void;
  onSignIn: (scopes: string[]) => void;
  loading: boolean;
  error: string | null;
}) {
  const PERMISSIONS = [
    {
      icon: Globe,
      title: "View extension inventory",
      desc: "Read which extensions are installed on managed Chrome devices across your org.",
    },
    {
      icon: ShieldCheck,
      title: "Read device reports",
      desc: "Access Chrome management reports to track extension versions and usage.",
    },
    {
      icon: KeyRound,
      title: "No write access",
      desc: "We never modify settings, install software, or access any personal data.",
    },
  ];

  return (
    <div className="w-full max-w-md">
      <BackButton onClick={onBack} />

      <div className="bg-card border-border rounded-xl border p-8 shadow-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <div className="rounded-2xl bg-sky-500/10 p-4">
            <Building2 className="h-8 w-8 text-sky-400" />
          </div>
          <div>
            <h2 className="text-foreground text-lg font-semibold">
              Connect Google Workspace
            </h2>
            <p className="text-muted-foreground mt-1 text-sm">
              Sign in with a Workspace account that has Chrome management
              access.
            </p>
          </div>
        </div>

        <div className="mb-6 space-y-3">
          <p className="text-foreground/50 text-xs font-medium uppercase tracking-wider">
            What we access
          </p>
          {PERMISSIONS.map((p) => {
            const Icon = p.icon;
            return (
              <div key={p.title} className="flex items-start gap-3">
                <div className="bg-muted mt-0.5 rounded-md p-1.5">
                  <Icon className="text-foreground/60 h-3.5 w-3.5" />
                </div>
                <div>
                  <p className="text-foreground text-xs font-medium">
                    {p.title}
                  </p>
                  <p className="text-muted-foreground text-xs">{p.desc}</p>
                </div>
              </div>
            );
          })}
        </div>

        <button
          onClick={() => onSignIn(WORKSPACE_SCOPES)}
          disabled={loading}
          className="border-border text-foreground hover:bg-muted flex w-full cursor-pointer items-center justify-center gap-3 rounded-lg border bg-transparent px-4 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? <Spinner /> : <GoogleIcon />}
          {loading ? "Redirecting..." : "Continue with Google"}
        </button>

        {error && (
          <p className="text-destructive mt-3 text-center text-xs">{error}</p>
        )}
      </div>
    </div>
  );
}

// ---- step 2b: extension ---------------------------------------------------
// This page is only ever seen by the admin setting up the org.
// Team members receive a /join/:token link directly and never land here.

function Step2Extension({
  onBack,
  onSignIn,
  loading,
  error,
}: {
  onBack: () => void;
  onSignIn: (scopes: string[]) => void;
  loading: boolean;
  error: string | null;
}) {
  return (
    <div className="w-full max-w-md">
      <BackButton onClick={onBack} />

      <div className="bg-card border-border rounded-xl border p-8 shadow-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <div className="rounded-2xl bg-violet-500/10 p-4">
            <Puzzle className="h-8 w-8 text-violet-400" />
          </div>
          <div>
            <h2 className="text-foreground text-lg font-semibold">
              Set up extension monitoring
            </h2>
            <p className="text-muted-foreground mt-1 text-sm">
              Sign in to create your organisation. You'll get invite links to
              share - that's all your team members need.
            </p>
          </div>
        </div>

        {/* How it works for the admin */}
        <div className="mb-6 space-y-3">
          <p className="text-foreground/50 text-xs font-medium uppercase tracking-wider">
            How it works
          </p>

          {[
            {
              icon: GoogleIcon,
              isComponent: true,
              title: "Sign in with Google",
              desc: "Creates your org account. No Workspace subscription needed.",
            },
            {
              icon: Link2,
              isComponent: false,
              title: "Share your invite links",
              desc: "Generate unique per-device links from your dashboard settings.",
            },
            {
              icon: Puzzle,
              isComponent: false,
              title: "Team members self-enroll",
              desc: "They install the extension, visit their link, and are auto-enrolled. Done.",
            },
          ].map((step, i) => {
            return (
              <div key={i} className="flex items-start gap-3">
                <div className="bg-muted mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md">
                  {step.isComponent ? (
                    <GoogleIcon />
                  ) : (
                    <step.icon className="text-foreground/60 h-3.5 w-3.5" />
                  )}
                </div>
                <div>
                  <p className="text-foreground text-xs font-medium">
                    {step.title}
                  </p>
                  <p className="text-muted-foreground text-xs">{step.desc}</p>
                </div>
              </div>
            );
          })}
        </div>

        {/* Sign in - no Workspace scopes needed */}
        <button
          onClick={() => onSignIn([])}
          disabled={loading}
          className="border-border text-foreground hover:bg-muted flex w-full cursor-pointer items-center justify-center gap-3 rounded-lg border bg-transparent px-4 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? <Spinner /> : <GoogleIcon />}
          {loading ? "Redirecting..." : "Continue with Google"}
        </button>

        {error && (
          <p className="text-destructive mt-3 text-center text-xs">{error}</p>
        )}
      </div>
    </div>
  );
}

// ---- root page ------------------------------------------------------------

export function OnboardingPage() {
  const [step, setStep] = useState<Step>(1);
  const [method, setMethod] = useState<Method>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function handleBack() {
    setStep(1);
    setError(null);
  }

  async function handleSignIn(scopes: string[]) {
    // Placeholder - wire up to authClient.signIn.social when hooking in.
    // Workspace path passes WORKSPACE_SCOPES; extension path passes [].
    void scopes;
    setLoading(true);
    setError(null);
    await new Promise((r) => setTimeout(r, 800));
    setLoading(false);
    setError("Sign-in not wired up yet - this is a preview.");
  }

  return (
    <div className="bg-background flex min-h-screen flex-col items-center px-4 py-16">
      <div className="mb-10 flex items-center gap-2.5">
        <img
          src="/logo.png"
          alt="Am I Being Pwned?"
          className="h-8 w-8 rounded-xl"
        />
        <span className="text-foreground text-sm font-semibold">
          Am I Being Pwned?
        </span>
      </div>

      <StepIndicator step={step} />

      {step === 1 && (
        <Step1
          selected={method}
          onSelect={setMethod}
          onContinue={() => setStep(2)}
        />
      )}

      {step === 2 && method === "workspace" && (
        <Step2Workspace
          onBack={handleBack}
          onSignIn={(scopes) => void handleSignIn(scopes)}
          loading={loading}
          error={error}
        />
      )}

      {step === 2 && method === "extension" && (
        <Step2Extension
          onBack={handleBack}
          onSignIn={(scopes) => void handleSignIn(scopes)}
          loading={loading}
          error={error}
        />
      )}

      <p className="text-muted-foreground mt-10 text-center text-xs">
        By continuing you agree to our{" "}
        <a
          href="/privacy"
          className="underline underline-offset-2 transition-colors hover:text-foreground"
        >
          Privacy Policy
        </a>
        .
      </p>
    </div>
  );
}

// ---- shared helpers -------------------------------------------------------

function BackButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="text-muted-foreground hover:text-foreground mb-8 flex items-center gap-1.5 text-sm transition-colors"
    >
      <ArrowLeft className="h-4 w-4" />
      Back
    </button>
  );
}

function Spinner() {
  return (
    <svg
      className="h-4 w-4 animate-spin"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

function GoogleIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0" aria-hidden>
      <path
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
        fill="#4285F4"
      />
      <path
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
        fill="#34A853"
      />
      <path
        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
        fill="#FBBC05"
      />
      <path
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
        fill="#EA4335"
      />
    </svg>
  );
}
