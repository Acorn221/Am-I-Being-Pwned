import { useState } from "react";
import { Building2, Check, Puzzle, X } from "lucide-react";

import { authClient } from "~/lib/auth-client";
import { navigate } from "~/router";

const WORKSPACE_SCOPES = [
  "https://www.googleapis.com/auth/chrome.management.appdetails.readonly",
  "https://www.googleapis.com/auth/chrome.management.reports.readonly",
];

export function SignupPage() {
  const [loadingWorkspace, setLoadingWorkspace] = useState(false);
  const [loadingExtension, setLoadingExtension] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function signInWithGoogle(scopes: string[]) {
    const setLoading = scopes.length > 0 ? setLoadingWorkspace : setLoadingExtension;
    setLoading(true);
    setError(null);
    const { error } = await authClient.signIn.social({
      provider: "google",
      callbackURL: "/dashboard",
      ...(scopes.length > 0 && { scopes }),
    });
    if (error) {
      setError(error.message ?? "Sign in failed. Please try again.");
      setLoading(false);
    }
    // on success better-auth redirects - no need to setLoading(false)
  }

  return (
    <div className="bg-background flex min-h-screen flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-3xl space-y-8">
        {/* Logo + wordmark */}
        <div className="flex flex-col items-center gap-3">
          <img src="/logo.png" alt="Am I Being Pwned?" className="h-10 w-10 rounded-xl" />
          <div className="space-y-1 text-center">
            <h1 className="text-foreground text-xl font-semibold tracking-tight">
              Create your account
            </h1>
            <p className="text-muted-foreground text-sm">
              Choose how you want to monitor your browser extensions.
            </p>
          </div>
        </div>

        {/* Two-path cards */}
        <div className="grid gap-4 sm:grid-cols-2">
          {/* Google Workspace path */}
          <div className="bg-card border-border flex flex-col rounded-xl border p-6 shadow-sm">
            <div className="mb-4 flex items-start justify-between gap-3">
              <div className="bg-primary/10 rounded-lg p-2">
                <Building2 className="text-primary h-5 w-5" />
              </div>
              <span className="bg-primary/10 text-primary rounded-full px-2 py-0.5 text-xs font-medium">
                For IT admins
              </span>
            </div>

            <h2 className="text-foreground mb-1 text-sm font-semibold">
              Google Workspace
            </h2>
            <p className="text-muted-foreground mb-4 text-xs leading-relaxed">
              Connect your Google Workspace to pull extension data across your
              entire fleet via the Chrome Management API - no per-device setup
              required.
            </p>

            <ul className="mb-6 space-y-1.5 text-xs">
              <li className="flex items-start gap-2">
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" />
                <span className="text-foreground/80">
                  Instant fleet-wide visibility - all devices covered automatically
                </span>
              </li>
              <li className="flex items-start gap-2">
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" />
                <span className="text-foreground/80">
                  No software to install on each machine
                </span>
              </li>
              <li className="flex items-start gap-2">
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" />
                <span className="text-foreground/80">
                  Centralised dashboard with org-wide reporting
                </span>
              </li>
              <li className="flex items-start gap-2">
                <X className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                <span className="text-muted-foreground">
                  Requires Google Workspace with Chrome management enabled
                </span>
              </li>
              <li className="flex items-start gap-2">
                <X className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                <span className="text-muted-foreground">
                  Only covers managed Chrome devices enrolled in your org
                </span>
              </li>
            </ul>

            <div className="mt-auto space-y-3">
              <button
                onClick={() => void signInWithGoogle(WORKSPACE_SCOPES)}
                disabled={loadingWorkspace}
                className="border-border text-foreground hover:bg-muted flex w-full cursor-pointer items-center justify-center gap-3 rounded-lg border bg-transparent px-4 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loadingWorkspace ? <Spinner /> : <GoogleIcon />}
                {loadingWorkspace ? "Redirecting..." : "Sign up with Google"}
              </button>

              {error && (
                <p className="text-destructive text-center text-xs">{error}</p>
              )}
            </div>
          </div>

          {/* Extension path */}
          <div className="bg-card border-border flex flex-col rounded-xl border p-6 shadow-sm">
            <div className="mb-4 flex items-start justify-between gap-3">
              <div className="rounded-lg bg-violet-500/10 p-2">
                <Puzzle className="h-5 w-5 text-violet-500" />
              </div>
              <span className="rounded-full bg-violet-500/10 px-2 py-0.5 text-xs font-medium text-violet-500">
                For any team
              </span>
            </div>

            <h2 className="text-foreground mb-1 text-sm font-semibold">
              Chrome Extension
            </h2>
            <p className="text-muted-foreground mb-4 text-xs leading-relaxed">
              Install our lightweight extension on each device. No Google
              Workspace needed - works on any Chrome browser, personal or
              managed.
            </p>

            <ul className="mb-6 space-y-1.5 text-xs">
              <li className="flex items-start gap-2">
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" />
                <span className="text-foreground/80">
                  Works on any Chrome browser - no Workspace subscription needed
                </span>
              </li>
              <li className="flex items-start gap-2">
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" />
                <span className="text-foreground/80">
                  Real-time data straight from each device
                </span>
              </li>
              <li className="flex items-start gap-2">
                <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500" />
                <span className="text-foreground/80">
                  Covers BYOD and unmanaged machines Google can't see
                </span>
              </li>
              <li className="flex items-start gap-2">
                <X className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                <span className="text-muted-foreground">
                  Must be installed individually on each device
                </span>
              </li>
              <li className="flex items-start gap-2">
                <X className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                <span className="text-muted-foreground">
                  Enrollment requires an invite link generated by the admin
                </span>
              </li>
            </ul>

            <div className="mt-auto space-y-3">
              <button
                onClick={() => void signInWithGoogle([])}
                disabled={loadingExtension}
                className="border-border text-foreground hover:bg-muted flex w-full cursor-pointer items-center justify-center gap-3 rounded-lg border bg-transparent px-4 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loadingExtension ? <Spinner /> : <GoogleIcon />}
                {loadingExtension ? "Redirecting..." : "Sign up with Google"}
              </button>

              {error && (
                <p className="text-destructive text-center text-xs">{error}</p>
              )}
            </div>
          </div>
        </div>

        <p className="text-muted-foreground text-center text-xs">
          Already have an account?{" "}
          <button
            className="cursor-pointer underline underline-offset-2 transition-colors hover:text-foreground"
            onClick={() => navigate("/login")}
          >
            Sign in
          </button>
          {" "}&middot;{" "}
          <button
            className="cursor-pointer underline underline-offset-2 transition-colors hover:text-foreground"
            onClick={() => navigate("/privacy")}
          >
            Privacy Policy
          </button>
        </p>
      </div>
    </div>
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
