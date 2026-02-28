/**
 * /join/:token - Employee self-enrollment page.
 *
 * Two cases:
 *   A. Extension already installed: bridge fires → send REGISTER_WITH_INVITE
 *      message → device enrolled within seconds.
 *   B. Extension not installed: show install CTA. After install, the background
 *      script scans for this open tab, extracts the token, and self-enrolls.
 */

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle, ExternalLink, Loader2 } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import { extensionClient } from "~/lib/extension-client";
import { useTRPC } from "~/lib/trpc";

type JoinState =
  | { phase: "validating" }
  | { phase: "detecting"; orgName: string }
  | { phase: "registering"; orgName: string }
  | { phase: "success"; orgName: string }
  | { phase: "install_needed"; orgName: string }
  | { phase: "error"; message: string };

const CHROME_STORE_URL =
  "https://chromewebstore.google.com/detail/am-i-being-pwned/amibeingpndbmhcmnjdekhljpjcbjnpl";

interface JoinPageProps {
  token: string;
}

export function JoinPage({ token }: JoinPageProps) {
  const trpc = useTRPC();
  const [state, setState] = useState<JoinState>({ phase: "validating" });

  // 1. Validate the token server-side to get the org name
  const validateQuery = useQuery(
    trpc.org.validateInviteToken.queryOptions({ token }),
  );

  // 2. Once validated, detect extension and attempt registration
  useEffect(() => {
    if (validateQuery.isPending) return;

    if (validateQuery.isError || !validateQuery.data) {
      const err = validateQuery.error as unknown;
      setState({
        phase: "error",
        message:
          (err instanceof Error ? err.message : null) ??
          "Invite link is invalid or has been revoked.",
      });
      return;
    }

    const { orgName } = validateQuery.data;
    setState({ phase: "detecting", orgName });

    void (async () => {
      const extId = await extensionClient.detect();

      if (!extId) {
        // Extension not installed - show install CTA
        setState({ phase: "install_needed", orgName });
        return;
      }

      // Extension detected - send registration message
      setState({ phase: "registering", orgName });
      try {
        const response = await extensionClient.send({
          type: "REGISTER_WITH_INVITE",
          version: 1,
          token,
        });

        if (response.type === "INVITE_REGISTERED") {
          setState({ phase: "success", orgName });
        } else if (response.type === "ERROR") {
          setState({ phase: "error", message: response.message });
        } else {
          setState({
            phase: "error",
            message: "Unexpected response from extension.",
          });
        }
      } catch (err) {
        setState({
          phase: "error",
          message:
            err instanceof Error ? err.message : "Failed to register device.",
        });
      }
    })();
  }, [
    validateQuery.isPending,
    validateQuery.isError,
    validateQuery.data,
    validateQuery.error,
    token,
  ]);

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
          <div className="space-y-1 text-center">
            <h1 className="text-foreground text-lg font-semibold tracking-tight">
              Am I Being Pwned?
            </h1>
            <p className="text-muted-foreground text-sm">
              Fleet device enrollment
            </p>
          </div>
        </div>

        {/* Card */}
        <div className="bg-card border-border rounded-xl border p-6 shadow-sm">
          {state.phase === "validating" && (
            <div className="flex flex-col items-center gap-3 py-2">
              <Loader2 className="text-muted-foreground h-5 w-5 animate-spin" />
              <p className="text-muted-foreground text-sm">
                Validating invite…
              </p>
            </div>
          )}

          {(state.phase === "detecting" || state.phase === "registering") && (
            <div className="flex flex-col items-center gap-3 py-2 text-center">
              <Loader2 className="text-muted-foreground h-5 w-5 animate-spin" />
              <p className="text-muted-foreground text-sm">
                {state.phase === "detecting"
                  ? "Detecting extension…"
                  : "Enrolling device…"}
              </p>
            </div>
          )}

          {state.phase === "success" && (
            <div className="flex flex-col items-center gap-3 py-2 text-center">
              <div className="rounded-full bg-emerald-500/10 p-3">
                <CheckCircle className="h-6 w-6 text-emerald-500" />
              </div>
              <div>
                <p className="font-semibold">
                  Enrolled in <span className="font-bold">{state.orgName}</span>
                </p>
                <p className="text-muted-foreground mt-1 text-sm">
                  This device will appear in your fleet dashboard shortly.
                </p>
              </div>
            </div>
          )}

          {state.phase === "install_needed" && (
            <div className="space-y-4">
              <div className="text-center">
                <p className="font-semibold">Install the extension</p>
                <p className="text-muted-foreground mt-1 text-sm">
                  You&apos;ve been invited to{" "}
                  <span className="text-foreground font-semibold">
                    {state.orgName}
                  </span>
                  . Keep this tab open after installing - enrollment is
                  automatic.
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
