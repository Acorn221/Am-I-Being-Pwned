import type { InstalledExtensionInfo } from "@amibeingpwned/types";
import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import { Card } from "@amibeingpwned/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";
import { useQuery } from "@tanstack/react-query";
import { Bell, LogOut, Puzzle, RefreshCw, Shield } from "lucide-react";

import {  useExtension } from "~/hooks/use-extension";
import type {ExtensionStatus} from "~/hooks/use-extension";
import { authClient } from "~/lib/auth-client";
import { useTRPC } from "~/lib/trpc";
import { navigate } from "~/router";

import { FleetDashboard } from "./fleet-dashboard";

export function DashboardPage() {
  const { data: session } = authClient.useSession();
  const { status, extensions, scan, scanning, error } = useExtension();
  const trpc = useTRPC();

  const { data: fleetOverview, isPending: fleetPending } = useQuery(
    trpc.fleet.overview.queryOptions(),
  );

  // Show a minimal loading state while we determine the user's role.
  if (fleetPending) {
    return (
      <div className="bg-background flex min-h-screen items-center justify-center">
        <RefreshCw className="h-8 w-8 animate-spin opacity-30" />
      </div>
    );
  }

  // Manager path — fleet overview query succeeded.
  if (fleetOverview) {
    return <FleetDashboard overview={fleetOverview} />;
  }

  // Regular user path — fleet query threw UNAUTHORIZED (user is not a manager).

  async function handleSignOut() {
    await authClient.signOut();
    navigate("/");
  }

  return (
    <div className="bg-background min-h-screen">
      {/* Header */}
      <header className="border-border flex h-14 items-center justify-between border-b px-6">
        <div className="flex items-center gap-2">
          <Shield className="text-primary h-5 w-5" />
          <span className="text-foreground text-sm font-semibold">
            Am I Being Pwned?
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-muted-foreground text-sm">
            {session?.user.email}
          </span>
          <Button
            size="sm"
            variant="ghost"
            className="gap-1.5"
            onClick={() => void handleSignOut()}
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </Button>
        </div>
      </header>

      <div className="mx-auto max-w-5xl space-y-6 p-6">
        {/* Extensions */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <Puzzle className="h-4 w-4" />
              Your Extensions
            </h2>
            {status === "connected" && (
              <Button
                size="sm"
                variant="ghost"
                className="gap-1.5"
                disabled={scanning}
                onClick={() => void scan()}
              >
                <RefreshCw className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            )}
          </div>

          <ExtensionsPanel
            status={status}
            extensions={extensions}
            error={error}
          />
        </section>

        {/* Alerts */}
        <section className="space-y-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Bell className="h-4 w-4" />
            Alerts
          </h2>

          <AlertsPlaceholder />
        </section>
      </div>
    </div>
  );
}

function ExtensionsPanel({
  status,
  extensions,
  error,
}: {
  status: ExtensionStatus;
  extensions: InstalledExtensionInfo[] | null;
  error: string | null;
}) {
  if (status === "detecting") {
    return (
      <Card className="text-muted-foreground flex flex-col items-center justify-center py-12 gap-2">
        <RefreshCw className="h-8 w-8 opacity-30 animate-spin" />
        <p className="text-sm">Detecting extension…</p>
      </Card>
    );
  }

  if (status === "not_installed") {
    return (
      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Extension</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell
                colSpan={2}
                className="text-muted-foreground py-12 text-center"
              >
                <Puzzle className="mx-auto mb-2 h-8 w-8 opacity-30" />
                <p className="text-sm">
                  Install the extension to start monitoring.
                </p>
                <Button
                  size="sm"
                  className="mt-3"
                  onClick={() =>
                    window.open("https://chrome.google.com/webstore", "_blank")
                  }
                >
                  Get the extension
                </Button>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </Card>
    );
  }

  // connected
  return (
    <Card className="overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Extension</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {error && (
            <TableRow>
              <TableCell
                colSpan={2}
                className="text-destructive py-6 text-center text-sm"
              >
                {error}
              </TableCell>
            </TableRow>
          )}
          {!error && (!extensions || extensions.length === 0) && (
            <TableRow>
              <TableCell
                colSpan={2}
                className="text-muted-foreground py-6 text-center text-sm"
              >
                No extensions found.
              </TableCell>
            </TableRow>
          )}
          {extensions?.map((ext) => (
            <TableRow key={ext.id}>
              <TableCell className="text-sm font-medium">{ext.name}</TableCell>
              <TableCell>
                <Badge variant={ext.enabled ? "default" : "secondary"}>
                  {ext.enabled ? "Enabled" : "Disabled"}
                </Badge>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  );
}

function AlertsPlaceholder() {
  return (
    <Card className="text-muted-foreground flex flex-col items-center justify-center py-12 gap-2">
      <Bell className="h-8 w-8 opacity-30" />
      <p className="text-sm">No alerts yet.</p>
    </Card>
  );
}
