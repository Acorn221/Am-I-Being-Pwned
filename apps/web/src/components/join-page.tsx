import { useEffect, useState } from "react";
import { CheckCircle, ExternalLink, Loader2, LayoutDashboard } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import { extensionClient } from "~/lib/extension-client";
import { useTRPC } from "~/lib/trpc";
import { useQuery } from "@tanstack/react-query";

const CHROME_STORE_URL =
  "https://chromewebstore.google.com/detail/am-i-being-pwned/amibeingpndbmhcmnjdekhljpjcbjnpl";

const POLL_INTERVAL_MS = 2000;
const WEB_SESSION_KEY = "aibp_web_session";

type JoinState =
  | { phase: "connecting" }
  | { phase: "invalid_token" }
  | { phase: "confirm" }
  | { phase: "enrolling" }
  | { phase: "install_needed" }
  | { phase: "success" }
  | { phase: "error"; message: string };

interface JoinPageProps {
  token: string;
}

async function registerWithExtension(
  token: string,
): Promise<{ ok: true; webSessionToken: string } | { ok: false; message: string }> {
  try {
    const response = await extensionClient.send({
      type: "REGISTER_WITH_INVITE",
      version: 1,
      token,
    });
    if (response.type === "INVITE_REGISTERED") return { ok: true, webSessionToken: response.webSessionToken };
    if (response.type === "ERROR") return { ok: false, message: response.message };
    return { ok: false, message: "Unexpected response from extension." };
  } catch (err) {
    return { ok: false, message: err instanceof Error ? err.message : "Failed to register device." };
  }
}

export function JoinPage({ token }: JoinPageProps) {
  const trpc = useTRPC();
  const [state, setState] = useState<JoinState>({ phase: "connecting" });

  const { data, error: tokenError } = useQuery({
    ...trpc.org.validateInviteToken.queryOptions({ token }),
    retry: false,
  });
  const orgName = data?.orgName ?? null;

  // Wait for token validation before doing anything - run detection in parallel
  useEffect(() => {
    if (state.phase !== "connecting") return;

    // Token query failed - show error immediately, don't bother detecting
    if (tokenError) {
      setState({ phase: "invalid_token" });
      return;
    }

    // Still waiting for token validation
    if (!data) return;

    // Token is valid - now detect the extension
    let stopped = false;
    void extensionClient.detect().then((id) => {
      if (stopped) return;
      setState(id ? { phase: "confirm" } : { phase: "install_needed" });
    });
    return () => { stopped = true; };
  }, [state.phase, data, tokenError]);

  // Poll for extension while showing install CTA
  useEffect(() => {
    if (state.phase !== "install_needed") return;
    let stopped = false;
    const interval = setInterval(() => {
      void extensionClient.detect().then((id) => {
        if (stopped || !id) return;
        setState({ phase: "confirm" });
      });
    }, POLL_INTERVAL_MS);
    return () => { stopped = true; clearInterval(interval); };
  }, [state.phase]);

  async function handleEnroll() {
    setState({ phase: "enrolling" });
    const result = await registerWithExtension(token);
    if (result.ok) {
      localStorage.setItem(WEB_SESSION_KEY, result.webSessionToken);
      setState({ phase: "success" });
    } else {
      setState({ phase: "error", message: result.message });
    }
  }

  return (
    <div className="bg-background flex min-h-screen flex-col items-center justify-center px-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-3">
          <img src="/logo.png" alt="Am I Being Pwned?" className="h-10 w-10 rounded-xl" />
          <div className="space-y-2 text-center">
            <h1 className="text-foreground text-lg font-semibold tracking-tight">Am I Being Pwned?</h1>
            <p className="text-muted-foreground text-sm">Device enrollment</p>
          </div>
        </div>

        <div className="bg-card border-border rounded-xl border p-6 shadow-sm">

          {state.phase === "connecting" && (
            <div className="flex flex-col items-center gap-3 py-2 text-center">
              <Loader2 className="text-muted-foreground h-6 w-6 animate-spin" />
              <p className="text-muted-foreground text-sm">Checking enrollment link...</p>
            </div>
          )}

          {state.phase === "invalid_token" && (
            <div className="space-y-2 text-center">
              <p className="text-sm font-semibold text-red-500">Invalid enrollment link</p>
              <p className="text-muted-foreground text-xs">
                This link has expired or been revoked. Ask your admin for a new one.
              </p>
            </div>
          )}

          {state.phase === "confirm" && (
            <div className="space-y-4">
              <div className="text-center space-y-1">
                <p className="text-foreground font-semibold">Enroll in {orgName ?? "your organization"}</p>
                <p className="text-muted-foreground text-sm">
                  This will register your device and let{" "}
                  {orgName ?? "your organization"} monitor your extensions for threats.
                </p>
              </div>
              <Button className="w-full" onClick={() => void handleEnroll()}>
                Enroll this device
              </Button>
            </div>
          )}

          {state.phase === "enrolling" && (
            <div className="flex flex-col items-center gap-3 py-2 text-center">
              <Loader2 className="text-muted-foreground h-6 w-6 animate-spin" />
              <p className="text-muted-foreground text-sm">Enrolling device...</p>
            </div>
          )}

          {state.phase === "install_needed" && (
            <div className="space-y-4">
              <div className="text-center">
                <p className="text-foreground text-sm">
                  <span className="font-medium">{orgName ?? "Your organization"}</span>{" "}
                  uses Am I Being Pwned to keep your extensions safe.
                </p>
                <p className="text-muted-foreground mt-3 text-sm">
                  Install the extension then come back to this tab - enrollment is automatic.
                </p>
              </div>
              <Button asChild className="w-full gap-2">
                <a href={CHROME_STORE_URL} target="_blank" rel="noreferrer">
                  <ExternalLink className="h-4 w-4" />
                  Install on Chrome
                </a>
              </Button>
            </div>
          )}

          {state.phase === "success" && (
            <div className="flex flex-col items-center gap-3 py-2 text-center">
              <div className="rounded-full bg-emerald-500/10 p-3">
                <CheckCircle className="h-6 w-6 text-emerald-500" />
              </div>
              <div>
                <p className="font-semibold">You&apos;re all set!</p>
                <p className="text-muted-foreground mt-4 text-sm">
                  {orgName ?? "Your organization"} is now monitoring your browser extensions for threats.
                </p>
              </div>
              <Button asChild className="w-full gap-2 mt-2">
                <a href="/dashboard">
                  <LayoutDashboard className="h-4 w-4" />
                  Open Dashboard
                </a>
              </Button>
            </div>
          )}

          {state.phase === "error" && (
            <div className="space-y-3">
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3">
                <p className="text-sm font-semibold text-red-500">Something went wrong</p>
                <p className="text-muted-foreground mt-1 text-xs">{state.message}</p>
              </div>
              <p className="text-muted-foreground text-center text-xs">
                Ask your admin for a fresh invite link.
              </p>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
