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
import {
  AlertTriangle,
  Building2,
  LogOut,
  Monitor,
  Puzzle,
  RefreshCw,
  Shield,
} from "lucide-react";

import { authClient } from "~/lib/auth-client";
import { navigate } from "~/router";
import { useTRPC } from "~/lib/trpc";

type FleetOverview = {
  org: {
    id: string;
    name: string;
    plan: string;
    suspendedAt: Date | null;
  };
  deviceCount: number;
  extensionCount: number;
  flaggedCount: number;
  unreadAlertCount: number;
};

export function FleetDashboard({ overview }: { overview: FleetOverview }) {
  const trpc = useTRPC();

  const { data: extensionsData, isPending: extensionsPending } = useQuery(
    trpc.fleet.extensions.queryOptions({ page: 1, limit: 50 }),
  );

  async function handleSignOut() {
    await authClient.signOut();
    navigate("/");
  }

  // Flagged rows first, then sorted by risk score descending
  const sortedRows = extensionsData?.rows
    ? [...extensionsData.rows].sort((a, b) => {
        if (a.isFlagged !== b.isFlagged) return a.isFlagged ? -1 : 1;
        return (b.riskScore ?? 0) - (a.riskScore ?? 0);
      })
    : [];

  const hasThreats = overview.flaggedCount > 0;

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
          <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
            <Building2 className="h-4 w-4" />
            <span>{overview.org.name}</span>
            <Badge variant="outline" className="ml-1 text-xs capitalize">
              {overview.org.plan}
            </Badge>
          </div>
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
        {/* Suspended warning */}
        {overview.org.suspendedAt && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            This organisation is suspended. Device connections are disabled.
          </div>
        )}

        {/* Threat banner — only shown when there are active threats */}
        {hasThreats && (
          <div className="flex items-start gap-3 rounded-md border border-destructive/40 bg-destructive/10 px-4 py-3">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
            <div>
              <p className="text-sm font-semibold text-destructive">
                {overview.flaggedCount} malicious{" "}
                {overview.flaggedCount === 1 ? "extension" : "extensions"}{" "}
                detected across your fleet
              </p>
              <p className="text-muted-foreground mt-0.5 text-xs">
                Affected devices are highlighted below. Remove these extensions immediately.
              </p>
            </div>
          </div>
        )}

        {/* Stats row */}
        <div className="grid grid-cols-3 gap-4">
          <StatCard
            icon={<Monitor className="h-4 w-4" />}
            label="Devices"
            value={overview.deviceCount}
          />
          <StatCard
            icon={<Puzzle className="h-4 w-4" />}
            label="Extensions"
            value={overview.extensionCount}
          />
          <StatCard
            icon={<AlertTriangle className="h-4 w-4" />}
            label="Threats"
            value={overview.flaggedCount}
            highlight={hasThreats}
          />
        </div>

        {/* Extensions table */}
        <section className="space-y-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Puzzle className="h-4 w-4" />
            Fleet Extensions
            {hasThreats && (
              <Badge variant="destructive" className="ml-1">
                {overview.flaggedCount} threat{overview.flaggedCount !== 1 && "s"}
              </Badge>
            )}
          </h2>

          <Card className="overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Extension</TableHead>
                  <TableHead className="w-28">Risk</TableHead>
                  <TableHead className="w-24">Devices</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {extensionsPending && (
                  <TableRow>
                    <TableCell colSpan={3} className="py-12 text-center text-muted-foreground">
                      <RefreshCw className="mx-auto mb-2 h-6 w-6 animate-spin opacity-30" />
                      <p className="text-sm">Loading extensions…</p>
                    </TableCell>
                  </TableRow>
                )}
                {!extensionsPending && sortedRows.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={3} className="py-12 text-center text-sm text-muted-foreground">
                      No extensions found across fleet devices.
                    </TableCell>
                  </TableRow>
                )}
                {sortedRows.map((ext) => (
                  <TableRow
                    key={ext.chromeExtensionId}
                    className={ext.isFlagged ? "bg-destructive/5 border-l-2 border-l-destructive" : ""}
                  >
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {ext.isFlagged && (
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-destructive" />
                        )}
                        <span className={`text-sm font-medium ${ext.isFlagged ? "text-destructive" : ""}`}>
                          {ext.name ?? ext.chromeExtensionId}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <RiskScore score={ext.riskScore ?? 0} />
                    </TableCell>
                    <TableCell className="text-sm font-medium">
                      {ext.deviceCount}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </section>
      </div>
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  highlight = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  highlight?: boolean;
}) {
  return (
    <Card className={`p-4 ${highlight ? "border-destructive/50 bg-destructive/5" : ""}`}>
      <div className={`flex items-center gap-2 ${highlight ? "text-destructive" : "text-muted-foreground"}`}>
        {icon}
        <span className="text-xs font-medium uppercase tracking-wide">{label}</span>
      </div>
      <p className={`mt-2 text-2xl font-bold ${highlight ? "text-destructive" : "text-foreground"}`}>
        {value}
      </p>
    </Card>
  );
}

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 70 ? "bg-destructive"
    : score >= 40 ? "bg-orange-500"
    : "bg-emerald-500";

  const textColor =
    score >= 70 ? "text-destructive"
    : score >= 40 ? "text-orange-500"
    : "text-muted-foreground";

  return (
    <div className="flex items-center gap-2">
      <span className={`w-7 text-right text-xs font-semibold tabular-nums ${textColor}`}>
        {score}
      </span>
      <div className="h-1.5 w-16 rounded-full bg-muted overflow-hidden">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}
