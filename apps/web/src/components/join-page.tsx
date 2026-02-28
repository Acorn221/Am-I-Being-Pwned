import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle, ExternalLink, LayoutDashboard } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import { extensionClient } from "~/lib/extension-client";
import { useTRPC } from "~/lib/trpc";

const CHROME_STORE_URL =
  "https://chromewebstore.google.com/detail/am-i-being-pwned/amibeingpndbmhcmnjdekhljpjcbjnpl";

const POLL_INTERVAL_MS = 2000;

type JoinState =
  | { phase: "install_needed" }
  | { phase: "success" }
  | { phase: "error"; message: string };

interface JoinPageProps {
  token: string;
}

async function tryRegister(
  token: string,
): Promise<{ ok: true; webSessionToken: string } | { ok: false; message: string } | null> {
  const extId = await extensionClient.detect();
  if (!extId) return null;

  try {
    const response = await extensionClient.send({
      type: "REGISTER_WITH_INVITE",
      version: 1,
      token,
    });

    if (response.type === "INVITE_REGISTERED") {
      return { ok: true, webSessionToken: response.webSessionToken };
    }
    if (response.type === "ERROR")
      return { ok: false, message: response.message };
    return { ok: false, message: "Unexpected response from extension." };
  } catch (err) {
    return {
      ok: false,
      message:
        err instanceof Error ? err.message : "Failed to register device.",
    };
  }
}

const WEB_SESSION_KEY = "aibp_web_session";

export function JoinPage({ token }: JoinPageProps) {
  const trpc = useTRPC();
  const [state, setState] = useState<JoinState>({ phase: "install_needed" });

  const { data } = useQuery(
    trpc.org.validateInviteToken.queryOptions({ token }),
  );
  const orgName = data?.orgName ?? null;

  // On mount: detect extension and register if present
  useEffect(() => {
    let stopped = false;

    void tryRegister(token).then((result) => {
      if (stopped || result === null) return;
      if (result.ok) {
        localStorage.setItem(WEB_SESSION_KEY, result.webSessionToken);
        setState({ phase: "success" });
      } else {
        setState({ phase: "error", message: result.message });
      }
    });

    return () => {
      stopped = true;
    };
  }, [token]);

  // Poll for extension in background while showing install CTA
  useEffect(() => {
    if (state.phase !== "install_needed") return;

    let stopped = false;

    const poll = async () => {
      const result = await tryRegister(token);
      if (stopped || result === null) return;

      if (result.ok) {
        localStorage.setItem(WEB_SESSION_KEY, result.webSessionToken);
        setState({ phase: "success" });
      } else {
        setState({ phase: "error", message: result.message });
      }
    };

    const interval = setInterval(() => void poll(), POLL_INTERVAL_MS);

    return () => {
      stopped = true;
      clearInterval(interval);
    };
  }, [state.phase, token]);

  return (
    <div className="bg-background flex min-h-screen flex-col items-center justify-center px-4">
      <div className="w-full max-w-sm space-y-6">
        {/* Logo + wordmark */}
        <div className="flex flex-col items-center gap-3">
          <img
            src="/logo.png"
            alt="Am I Being Pwned?"
            className="h-10 w-10 rounded-xl"
          />
          <div className="space-y-2 text-center">
            <h1 className="text-foreground text-lg font-semibold tracking-tight">
              Am I Being Pwned?
            </h1>
            <p className="text-muted-foreground text-sm">Device enrollment</p>
          </div>
        </div>

        {/* Card */}
        <div className="bg-card border-border rounded-xl border p-6 shadow-sm">
          {state.phase === "install_needed" && (
            <div className="space-y-4">
              <div className="text-center">
                <p className="text-foreground mt-1 text-sm">
                  <span className="">{orgName ?? "Your organization"}</span>{" "}
                  uses Am I Being Pwned to make sure your extensions aren&apos;t
                  malicious or vulnerable to attacks.
                  <p className="text-muted-foreground mt-4">
                    {" "}
                    Keep this tab open after installing - enrollment is
                    automatic.
                  </p>
                </p>
              </div>
              <Button asChild className="w-full gap-2" variant="default">
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
                  {orgName ?? "Your organization"} is now monitoring your
                  browser extensions for threats.
                </p>
              </div>
              <Button asChild className="w-full gap-2 mt-2" variant="default">
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
                <p className="text-sm font-semibold text-red-500">
                  Something went wrong
                </p>
                <p className="text-muted-foreground mt-1 text-xs">
                  {state.message}
                </p>
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
