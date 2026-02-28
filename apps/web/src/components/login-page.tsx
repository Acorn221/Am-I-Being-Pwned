import { useState } from "react";

import { authClient } from "~/lib/auth-client";
import { navigate } from "~/router";

export function LoginPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function signInWithGoogle() {
    setLoading(true);
    setError(null);
    const { error } = await authClient.signIn.social({
      provider: "google",
      callbackURL: "/dashboard",
      scopes: [
        "https://www.googleapis.com/auth/chrome.management.appdetails.readonly",
        "https://www.googleapis.com/auth/chrome.management.reports.readonly",
      ],
    });
    if (error) {
      setError(error.message ?? "Sign in failed. Please try again.");
      setLoading(false);
    }
    // on success better-auth redirects — no need to setLoading(false)
  }

  return (
    <div className="bg-background flex min-h-screen flex-col items-center justify-center px-4">
      <div className="w-full max-w-sm space-y-6">
        {/* Logo + wordmark */}
        <div className="flex flex-col items-center gap-3">
          <img src="/logo.png" alt="Am I Being Pwned?" className="h-10 w-10 rounded-xl" />
          <div className="space-y-1 text-center">
            <h1 className="text-foreground text-lg font-semibold tracking-tight">
              Am I Being Pwned?
            </h1>
            <p className="text-muted-foreground text-sm">
              Sign in to monitor your extensions for threats.
            </p>
          </div>
        </div>

        {/* Card */}
        <div className="bg-card border-border rounded-xl border p-6 shadow-sm space-y-3">
          <button
            onClick={() => void signInWithGoogle()}
            disabled={loading}
            className="border-border text-foreground hover:bg-muted flex w-full cursor-pointer items-center justify-center gap-3 rounded-lg border bg-transparent px-4 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? <Spinner /> : <GoogleIcon />}
            {loading ? "Redirecting…" : "Continue with Google"}
          </button>

          {error && (
            <p className="text-destructive text-center text-xs">{error}</p>
          )}
        </div>

        <p className="text-muted-foreground text-center text-xs">
          By signing in you agree to our{" "}
          <button
            className="cursor-pointer underline underline-offset-2 transition-colors hover:text-foreground"
            onClick={() => navigate("/privacy")}
          >
            Privacy Policy
          </button>
          .
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
