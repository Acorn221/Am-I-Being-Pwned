import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCheck,
  CheckCircle,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import { Card } from "@amibeingpwned/ui/card";

import { useTRPC } from "~/lib/trpc";
import { sev, timeAgo } from "./fleet-types";

export function AlertsTab() {
  const trpc = useTRPC();
  const queryClient = useQueryClient();

  const { data: alerts, isPending } = useQuery(
    trpc.fleet.alerts.queryOptions(),
  );

  const dismiss = useMutation(
    trpc.fleet.dismissAlert.mutationOptions({
      onSuccess: () => {
        void queryClient.invalidateQueries(trpc.fleet.alerts.queryFilter());
        void queryClient.invalidateQueries(trpc.fleet.overview.queryFilter());
      },
    }),
  );

  if (isPending) {
    return (
      <div className="flex items-center justify-center py-20">
        <RefreshCw className="h-5 w-5 animate-spin opacity-30" />
      </div>
    );
  }

  if (!alerts || alerts.length === 0) {
    return (
      <div className="text-muted-foreground flex flex-col items-center gap-3 py-20">
        <ShieldCheck className="h-10 w-10 opacity-30" />
        <p className="text-sm">No unread alerts - your fleet is clean.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between pb-1">
        <p className="text-muted-foreground text-sm">{alerts.length} unread</p>
        <Button
          size="sm"
          variant="ghost"
          className="text-muted-foreground gap-1.5 text-xs"
          disabled={dismiss.isPending}
          onClick={() => {
            for (const a of alerts) dismiss.mutate({ alertId: a.id });
          }}
        >
          <CheckCheck className="h-3.5 w-3.5" />
          Dismiss all
        </Button>
      </div>

      {alerts.map((alert) => {
        const styles = sev(alert.severity);
        return (
          <div
            key={alert.id}
            className="bg-card relative flex gap-3 overflow-hidden rounded-lg border px-4 py-3"
          >
            <div className={`absolute inset-y-0 left-0 w-1 ${styles.bar}`} />
            <div className="ml-1 min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`text-sm font-semibold ${styles.text}`}>
                  {alert.title}
                </span>
                <span
                  className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold tracking-wide uppercase ${styles.badge}`}
                >
                  {alert.severity}
                </span>
                {alert.extensionName && (
                  <span className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 text-[11px]">
                    {alert.extensionName}
                  </span>
                )}
                <span className="text-muted-foreground ml-auto text-xs">
                  {timeAgo(alert.createdAt)}
                </span>
              </div>
              {alert.body && (
                <p className="text-muted-foreground mt-1 text-xs leading-relaxed">
                  {alert.body}
                </p>
              )}
            </div>
            <Button
              size="sm"
              variant="ghost"
              className="text-muted-foreground hover:text-foreground h-7 w-7 shrink-0 p-0"
              disabled={dismiss.isPending}
              onClick={() => dismiss.mutate({ alertId: alert.id })}
              title="Dismiss"
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        );
      })}
    </div>
  );
}

export function WorkspaceSetupCard({
  onSync,
  isSyncing,
  blockedReason,
  syncedButEmpty,
}: {
  onSync: () => void;
  isSyncing: boolean;
  blockedReason?: string;
  syncedButEmpty?: boolean;
}) {
  return (
    <div className="flex items-center justify-center py-12">
      <Card className="w-full max-w-md space-y-6 p-8">
        <div className="space-y-1.5">
          <h3 className="font-semibold">Connect Google Workspace</h3>
          <p className="text-muted-foreground text-sm">
            Sync Chrome extensions and enrolled devices from your org via the
            Chrome Management API.
          </p>
        </div>

        {syncedButEmpty ? (
          <div className="space-y-4">
            <p className="text-muted-foreground text-sm">
              Sync ran but Google's API returned no data yet. This is normal
              right after enrolling, it can take a few hours for newly enrolled
              browsers and their extensions to appear. Come back and hit{" "}
              <strong className="text-foreground">Try again</strong> later.
            </p>
            <div className="space-y-2.5">
              <p className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
                How to enroll a browser
              </p>
              <ol className="text-muted-foreground list-none space-y-2 text-sm">
                {[
                  <>
                    Go to{" "}
                    <a
                      href="https://admin.google.com/ac/chrome/browsers/"
                      target="_blank"
                      rel="noreferrer"
                      className="text-foreground underline underline-offset-2 hover:opacity-80"
                    >
                      Chrome Browsers in Admin Console
                    </a>{" "}
                    and generate an enrollment token.
                  </>,
                  <>
                    Deploy the token as a Chrome policy:
                    <br />
                    <span className="bg-muted mt-1 inline-block rounded px-1.5 py-0.5 font-mono text-xs">
                      CloudManagementEnrollmentToken = YOUR_TOKEN
                    </span>
                  </>,
                  <>
                    On Mac:{" "}
                    <span className="bg-muted rounded px-1.5 py-0.5 font-mono text-xs">
                      defaults write com.google.Chrome
                      CloudManagementEnrollmentToken -string "TOKEN"
                    </span>
                  </>,
                  <>
                    On Windows: set via Group Policy or registry at{" "}
                    <span className="bg-muted rounded px-1.5 py-0.5 font-mono text-xs break-all">
                      HKLM\SOFTWARE\Policies\Google\Chrome
                    </span>
                  </>,
                  "Restart Chrome, then sync again.",
                ].map((step, i) => (
                  <li key={i} className="flex items-start gap-2.5">
                    <span className="bg-muted text-muted-foreground mt-px flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs font-medium">
                      {i + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>
            <Button
              className="w-full gap-2"
              variant="outline"
              disabled={isSyncing}
              onClick={onSync}
            >
              <RefreshCw
                className={`h-4 w-4 ${isSyncing ? "animate-spin" : ""}`}
              />
              {isSyncing ? "Syncing..." : "Try again"}
            </Button>
          </div>
        ) : (
          <>
            <div className="space-y-2.5">
              <p className="text-muted-foreground text-xs font-medium tracking-wide uppercase">
                Requirements
              </p>
              {[
                "Google Workspace account (not personal Gmail)",
                "Super admin role on the domain",
                "Chrome Browser Cloud Management (CBCM) enabled",
              ].map((req) => (
                <div key={req} className="flex items-center gap-2.5 text-sm">
                  <CheckCircle className="h-4 w-4 shrink-0 text-emerald-500" />
                  <span>{req}</span>
                </div>
              ))}
            </div>

            {blockedReason ? (
              <div className="bg-destructive/10 border-destructive/20 text-destructive flex items-start gap-2.5 rounded-lg border p-3 text-sm">
                <AlertTriangle className="mt-px h-4 w-4 shrink-0" />
                <span>{blockedReason}</span>
              </div>
            ) : (
              <Button
                className="w-full gap-2"
                disabled={isSyncing}
                onClick={onSync}
              >
                <RefreshCw
                  className={`h-4 w-4 ${isSyncing ? "animate-spin" : ""}`}
                />
                {isSyncing ? "Connecting..." : "Connect & Sync"}
              </Button>
            )}
          </>
        )}
      </Card>
    </div>
  );
}
