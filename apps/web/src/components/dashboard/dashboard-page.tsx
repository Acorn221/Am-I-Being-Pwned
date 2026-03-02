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
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, Building2, LogOut, Puzzle, RefreshCw, Shield } from "lucide-react";

import {  useExtension } from "~/hooks/use-extension";
import type {ExtensionStatus} from "~/hooks/use-extension";
import { authClient } from "~/lib/auth-client";
import { setImpersonateOrgId, useTRPC } from "~/lib/trpc";
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

  // Admin with no org selected — show the org picker.
  if (session?.user.role === "admin") {
    return <AdminOrgPicker />;
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
          <img src="/logo.png" alt="" className="h-7 w-auto" />
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

function AdminOrgPicker() {
  const trpc = useTRPC();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery(
    trpc.admin.orgs.list.queryOptions({ limit: 100 }),
  );

  async function handleSignOut() {
    await authClient.signOut();
    navigate("/");
  }

  function selectOrg(id: string) {
    setImpersonateOrgId(id);
    void queryClient.invalidateQueries();
  }

  return (
    <div className="bg-background min-h-screen">
      <header className="border-border flex h-14 items-center justify-between border-b px-6">
        <div className="flex items-center gap-2">
          <img src="/logo.png" alt="" className="h-7 w-auto" />
          <span className="text-foreground text-sm font-semibold">
            Am I Being Pwned?
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" className="gap-1.5" onClick={() => navigate("/admin")}>
            <Shield className="h-3.5 w-3.5" />
            Admin panel
          </Button>
          <Button size="sm" variant="ghost" className="gap-1.5" onClick={() => void handleSignOut()}>
            <LogOut className="h-4 w-4" />
            Sign out
          </Button>
        </div>
      </header>

      <div className="flex flex-col items-center justify-center px-4 py-16">
        <Building2 className="text-muted-foreground mb-4 h-10 w-10" />
        <h2 className="text-foreground mb-1 text-lg font-semibold">Pick an org to view</h2>
        <p className="text-muted-foreground mb-8 text-sm">
          Select an organisation to god-mode into its fleet dashboard.
        </p>

        {isLoading ? (
          <RefreshCw className="text-muted-foreground h-5 w-5 animate-spin" />
        ) : (
          <div className="w-full max-w-sm space-y-2">
            {data?.rows.map((org) => (
              <button
                key={org.id}
                onClick={() => selectOrg(org.id)}
                className="border-border hover:bg-muted flex w-full items-center justify-between rounded-lg border px-4 py-3 text-left transition-colors"
              >
                <div>
                  <p className="text-foreground text-sm font-medium">{org.name}</p>
                  <p className="text-muted-foreground text-xs">{org.slug}</p>
                </div>
                <Badge variant="outline" className="capitalize text-xs">
                  {org.plan}
                </Badge>
              </button>
            ))}
            {data?.rows.length === 0 && (
              <p className="text-muted-foreground text-center text-sm">No organisations found.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
