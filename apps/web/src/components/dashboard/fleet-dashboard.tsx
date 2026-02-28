import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  Bell,
  Building2,
  CheckCheck,
  CheckCircle,
  Cloud,
  Copy,
  LogOut,
  Monitor,
  Plus,
  Puzzle,
  RefreshCw,
  Settings,
  Shield,
  ShieldCheck,
  Trash2,
  Webhook,
  X,
  Zap,
} from "lucide-react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import { Card } from "@amibeingpwned/ui/card";
import { Input } from "@amibeingpwned/ui/input";
import { Label } from "@amibeingpwned/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";

import { authClient } from "~/lib/auth-client";
import { useTRPC } from "~/lib/trpc";
import { navigate } from "~/router";

// ─── Types ───────────────────────────────────────────────────────────────────

interface FleetOverview {
  org: {
    id: string;
    name: string;
    plan: string;
    suspendedAt: Date | null;
    lastWorkspaceSyncAt: Date | null;
  };
  deviceCount: number;
  extensionCount: number;
  flaggedCount: number;
  unreadAlertCount: number;
}

type Tab = "overview" | "alerts" | "devices" | "extensions" | "settings";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const SEVERITY: Record<string, { bar: string; badge: string; text: string }> = {
  critical: {
    bar: "bg-destructive",
    badge: "bg-destructive/15 text-destructive border-destructive/30",
    text: "text-destructive",
  },
  high: {
    bar: "bg-orange-500",
    badge: "bg-orange-500/15 text-orange-500 border-orange-500/30",
    text: "text-orange-500",
  },
  medium: {
    bar: "bg-yellow-500",
    badge: "bg-yellow-500/15 text-yellow-600 border-yellow-500/30",
    text: "text-yellow-600",
  },
  low: {
    bar: "bg-blue-500",
    badge: "bg-blue-500/15 text-blue-500 border-blue-500/30",
    text: "text-blue-500",
  },
};
const SEVERITY_MEDIUM = {
  bar: "bg-yellow-500",
  badge: "bg-yellow-500/15 text-yellow-600 border-yellow-500/30",
  text: "text-yellow-600",
};
function sev(s: string) {
  return SEVERITY[s] ?? SEVERITY_MEDIUM;
}

function timeAgo(date: Date): string {
  const s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ─── Root component ───────────────────────────────────────────────────────────

export function FleetDashboard({ overview }: { overview: FleetOverview }) {
  const [tab, setTab] = useState<Tab>("overview");

  async function handleSignOut() {
    await authClient.signOut();
    navigate("/");
  }

  const tabs: { id: Tab; label: string; badge?: number }[] = [
    { id: "overview", label: "Overview" },
    {
      id: "alerts",
      label: "Alerts",
      badge: overview.unreadAlertCount || undefined,
    },
    { id: "devices", label: "Devices" },
    { id: "extensions", label: "Extensions" },
    { id: "settings", label: "Settings" },
  ];

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
          <div className="text-muted-foreground flex items-center gap-1.5 text-sm">
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

      {/* Tab nav */}
      <div className="border-border border-b px-6">
        <nav className="-mb-px flex gap-1">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 border-b-2 px-3 py-3 text-sm font-medium transition-colors ${
                tab === t.id
                  ? "border-foreground text-foreground"
                  : "text-muted-foreground hover:text-foreground border-transparent"
              }`}
            >
              {t.label}
              {t.badge != null && (
                <span className="bg-destructive text-destructive-foreground flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[10px] font-bold">
                  {t.badge}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Suspended warning */}
      {overview.org.suspendedAt && (
        <div className="mx-auto max-w-5xl px-6 pt-4">
          <div className="border-destructive/50 bg-destructive/10 text-destructive rounded-md border px-4 py-3 text-sm">
            This organisation is suspended. Device connections are disabled.
          </div>
        </div>
      )}

      {/* Tab content */}
      <div className="mx-auto max-w-5xl p-6">
        {tab === "overview" && (
          <OverviewTab overview={overview} onNavigate={setTab} />
        )}
        {tab === "alerts" && <AlertsTab />}
        {tab === "devices" && <DevicesTab overview={overview} />}
        {tab === "extensions" && <ExtensionsTab />}
        {tab === "settings" && <SettingsTab orgId={overview.org.id} />}
      </div>
    </div>
  );
}

// ─── Overview tab ─────────────────────────────────────────────────────────────

function OverviewTab({
  overview,
  onNavigate,
}: {
  overview: FleetOverview;
  onNavigate: (tab: Tab) => void;
}) {
  const trpc = useTRPC();

  const { data: alerts } = useQuery(trpc.fleet.alerts.queryOptions());
  const { data: threatenedDevices } = useQuery(
    trpc.fleet.threatenedDevices.queryOptions(),
  );

  const hasThreats = overview.flaggedCount > 0;
  const hasAlerts = (alerts?.length ?? overview.unreadAlertCount) > 0;
  const alertList = alerts?.slice(0, 3) ?? [];
  const threatList = threatenedDevices?.slice(0, 3) ?? [];

  return (
    <div className="space-y-5">
      {/* Stats strip — full width */}
      <div className="divide-border bg-card flex w-full gap-0 divide-x overflow-hidden rounded-lg border">
        <StatItem
          icon={<Monitor className="h-4 w-4" />}
          label="Devices"
          value={overview.deviceCount}
        />
        <StatItem
          icon={<Puzzle className="h-4 w-4" />}
          label="Extensions"
          value={overview.extensionCount}
        />
        <StatItem
          icon={<AlertTriangle className="h-4 w-4" />}
          label="Flagged"
          value={overview.flaggedCount}
          danger={hasThreats}
        />
      </div>

      {/* Summary cards row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/* Alerts card */}
        <SummaryCard
          icon={<Bell className="h-4 w-4" />}
          title="Alerts"
          badge={overview.unreadAlertCount || undefined}
          onViewAll={() => onNavigate("alerts")}
        >
          {!hasAlerts ? (
            <div className="text-muted-foreground flex items-center gap-2 text-sm">
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
              No unread alerts
            </div>
          ) : (
            <ul className="space-y-2">
              {alertList.map((a) => {
                const styles = sev(a.severity);
                return (
                  <li key={a.id} className="flex items-start gap-2">
                    <span
                      className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${styles.bar}`}
                    />
                    <div className="min-w-0">
                      <p
                        className={`truncate text-sm font-medium ${styles.text}`}
                      >
                        {a.title}
                      </p>
                      {a.extensionName && (
                        <p className="text-muted-foreground truncate text-xs">
                          {a.extensionName}
                        </p>
                      )}
                    </div>
                    <span className="text-muted-foreground ml-auto shrink-0 text-xs">
                      {timeAgo(a.createdAt)}
                    </span>
                  </li>
                );
              })}
              {(alerts?.length ?? 0) > 3 && (
                <li className="text-muted-foreground text-xs">
                  +{(alerts?.length ?? 0) - 3} more
                </li>
              )}
            </ul>
          )}
        </SummaryCard>

        {/* Threats card */}
        <SummaryCard
          icon={<AlertTriangle className="h-4 w-4" />}
          title="Threatened Devices"
          danger={hasThreats}
          // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing -- intentional: 0 should be treated as no badge
          badge={threatenedDevices?.length || undefined}
          onViewAll={() => onNavigate("devices")}
        >
          {!hasThreats ? (
            <div className="text-muted-foreground flex items-center gap-2 text-sm">
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
              No active threats detected
            </div>
          ) : (
            <ul className="space-y-2">
              {threatList.map((d) => (
                <li key={d.deviceId} className="flex items-start gap-2">
                  <Monitor className="text-muted-foreground mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium capitalize">
                      {d.platform}
                    </p>
                    <p className="text-muted-foreground truncate text-xs">
                      {d.threats
                        .map((t) => t.extensionName ?? t.chromeExtensionId)
                        .join(", ")}
                    </p>
                  </div>
                  <span className="text-destructive shrink-0 text-xs font-semibold">
                    {d.threats.length} threat{d.threats.length !== 1 && "s"}
                  </span>
                </li>
              ))}
              {(threatenedDevices?.length ?? 0) > 3 && (
                <li className="text-muted-foreground text-xs">
                  +{(threatenedDevices?.length ?? 0) - 3} more devices
                </li>
              )}
            </ul>
          )}
        </SummaryCard>
      </div>
    </div>
  );
}

function SummaryCard({
  icon,
  title,
  badge,
  danger,
  onViewAll,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  badge?: number;
  danger?: boolean;
  onViewAll: () => void;
  children: React.ReactNode;
}) {
  return (
    <Card className="flex flex-col gap-4 p-4">
      <div className="flex items-center justify-between">
        <div
          className={`flex items-center gap-2 text-sm font-semibold ${danger ? "text-destructive" : ""}`}
        >
          {icon}
          {title}
          {badge != null && (
            <span className="bg-destructive text-destructive-foreground flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[10px] font-bold">
              {badge}
            </span>
          )}
        </div>
        <button
          onClick={onViewAll}
          className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs transition-colors"
        >
          View all
          <ArrowRight className="h-3 w-3" />
        </button>
      </div>
      <div>{children}</div>
    </Card>
  );
}

function StatItem({
  icon,
  label,
  value,
  danger = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  danger?: boolean;
}) {
  return (
    <div className="flex flex-1 items-center gap-3 px-6 py-4">
      <span className={danger ? "text-destructive" : "text-muted-foreground"}>
        {icon}
      </span>
      <div>
        <p
          className={`text-2xl leading-none font-bold tabular-nums ${danger ? "text-destructive" : "text-foreground"}`}
        >
          {value}
        </p>
        <p className="text-muted-foreground mt-1 text-xs">{label}</p>
      </div>
    </div>
  );
}

// ─── Alerts tab ───────────────────────────────────────────────────────────────

function AlertsTab() {
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

// ─── Devices tab ──────────────────────────────────────────────────────────────

function DevicesTab({ overview }: { overview: FleetOverview }) {
  const trpc = useTRPC();

  const { data: threatenedDevices, isPending: threatsPending } = useQuery(
    trpc.fleet.threatenedDevices.queryOptions(),
  );
  const { data: allDevices, isPending: devicesPending } = useQuery(
    trpc.fleet.devices.queryOptions({ page: 1, limit: 50 }),
  );

  const hasThreats = overview.flaggedCount > 0;

  return (
    <div className="space-y-6">
      {/* Threatened devices */}
      {(hasThreats || threatsPending) && (
        <section className="space-y-3">
          <h2 className="text-destructive flex items-center gap-2 text-sm font-semibold">
            <AlertTriangle className="h-4 w-4" />
            Active Threats
          </h2>

          {threatsPending ? (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {[0, 1].map((i) => (
                <Card key={i} className="animate-pulse p-4">
                  <div className="bg-muted h-4 w-24 rounded" />
                  <div className="mt-3 space-y-2">
                    <div className="bg-muted h-3 w-full rounded" />
                    <div className="bg-muted h-3 w-3/4 rounded" />
                  </div>
                </Card>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {threatenedDevices?.map((device) => (
                <Card
                  key={device.deviceId}
                  className="border-destructive/30 overflow-hidden"
                >
                  <div className="bg-destructive/5 flex items-center gap-2 border-b px-4 py-2.5">
                    <Monitor className="text-muted-foreground h-3.5 w-3.5" />
                    <span className="text-sm font-medium capitalize">
                      {device.platform}
                    </span>
                    <span className="text-muted-foreground ml-auto text-xs">
                      {timeAgo(device.lastSeenAt)}
                    </span>
                  </div>
                  <div className="divide-y">
                    {device.threats.map((threat) => (
                      <div
                        key={threat.chromeExtensionId}
                        className="flex items-start gap-2 px-4 py-2.5"
                      >
                        <AlertTriangle className="text-destructive mt-0.5 h-3.5 w-3.5 shrink-0" />
                        <div className="min-w-0 flex-1">
                          <p className="text-destructive truncate text-sm font-medium">
                            {threat.extensionName ?? threat.chromeExtensionId}
                          </p>
                          {threat.flaggedReason && (
                            <p className="text-muted-foreground mt-0.5 text-xs">
                              {threat.flaggedReason}
                            </p>
                          )}
                        </div>
                        <RiskScore score={threat.riskScore} />
                      </div>
                    ))}
                  </div>
                </Card>
              ))}
            </div>
          )}
        </section>
      )}

      {/* All devices */}
      <section className="space-y-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <Monitor className="h-4 w-4" />
          All Devices
        </h2>
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Platform</TableHead>
                <TableHead className="w-32 text-right">Extensions</TableHead>
                <TableHead className="w-32 text-right">Flagged</TableHead>
                <TableHead className="w-36 text-right">Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {devicesPending && (
                <TableRow>
                  <TableCell
                    colSpan={4}
                    className="text-muted-foreground py-12 text-center"
                  >
                    <RefreshCw className="mx-auto mb-2 h-5 w-5 animate-spin opacity-30" />
                  </TableCell>
                </TableRow>
              )}
              {!devicesPending && (allDevices?.rows.length ?? 0) === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={4}
                    className="text-muted-foreground py-12 text-center text-sm"
                  >
                    No devices enrolled.
                  </TableCell>
                </TableRow>
              )}
              {allDevices?.rows.map((device) => (
                <TableRow
                  key={device.id}
                  className={
                    device.flaggedExtensionCount > 0
                      ? "border-l-destructive bg-destructive/5 border-l-2"
                      : ""
                  }
                >
                  <TableCell className="text-sm font-medium capitalize">
                    {device.platform}
                  </TableCell>
                  <TableCell className="text-right text-sm tabular-nums">
                    {device.extensionCount}
                  </TableCell>
                  <TableCell className="text-right">
                    {device.flaggedExtensionCount > 0 ? (
                      <span className="text-destructive text-sm font-semibold tabular-nums">
                        {device.flaggedExtensionCount}
                      </span>
                    ) : (
                      <span className="text-muted-foreground text-sm">-</span>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-right text-xs">
                    {timeAgo(device.lastSeenAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      </section>
    </div>
  );
}

// ─── Extensions tab ───────────────────────────────────────────────────────────

const INSTALL_TYPE_LABELS: Record<string, string> = {
  FORCED: "Forced",
  ADMIN: "Admin",
  NORMAL: "User",
  DEVELOPMENT: "Dev",
  SIDELOAD: "Sideloaded",
  OTHER: "Other",
  UNKNOWN: "Unknown",
};

function InstallTypeChip({ type }: { type: string | null }) {
  const label = INSTALL_TYPE_LABELS[type ?? ""] ?? type ?? "Unknown";
  const isForced = type === "FORCED" || type === "ADMIN";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold tracking-wide uppercase ${
        isForced
          ? "border border-blue-500/30 bg-blue-500/15 text-blue-600"
          : "bg-muted text-muted-foreground"
      }`}
    >
      {label}
    </span>
  );
}

function ExtensionsTab() {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const autoSyncFired = useRef(false);

  const { data: appsData, isPending } = useQuery(
    trpc.workspace.apps.queryOptions({ page: 1, limit: 100 }),
  );

  const syncMutation = useMutation(
    trpc.workspace.sync.mutationOptions({
      onSuccess: () => {
        void queryClient.invalidateQueries(trpc.workspace.apps.queryFilter());
      },
    }),
  );

  // Auto-sync on first visit if the org has never been synced
  useEffect(() => {
    if (!autoSyncFired.current && appsData?.lastSyncedAt === null) {
      autoSyncFired.current = true;
      syncMutation.mutate();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appsData]);

  const isSyncing = syncMutation.isPending;

  return (
    <div className="space-y-3">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="text-muted-foreground flex items-center gap-2 text-sm">
          <Cloud className="h-4 w-4" />
          {appsData?.lastSyncedAt ? (
            <span>Last synced {timeAgo(appsData.lastSyncedAt)}</span>
          ) : isSyncing ? (
            <span className="flex items-center gap-1.5">
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              Syncing from Google Workspace…
            </span>
          ) : (
            <span>Never synced</span>
          )}
        </div>
        <Button
          size="sm"
          variant="outline"
          className="gap-1.5"
          disabled={isSyncing}
          onClick={() => syncMutation.mutate()}
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${isSyncing ? "animate-spin" : ""}`}
          />
          {isSyncing ? "Syncing…" : "Sync now"}
        </Button>
      </div>

      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Extension</TableHead>
              <TableHead className="w-28">Install type</TableHead>
              <TableHead className="w-28">Risk</TableHead>
              <TableHead className="w-24 text-right">Devices</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(isPending || isSyncing) && (appsData?.rows.length ?? 0) === 0 && (
              <TableRow>
                <TableCell
                  colSpan={4}
                  className="text-muted-foreground py-12 text-center"
                >
                  <RefreshCw className="mx-auto h-5 w-5 animate-spin opacity-30" />
                </TableCell>
              </TableRow>
            )}
            {!isPending && !isSyncing && (appsData?.rows.length ?? 0) === 0 && (
              <TableRow>
                <TableCell
                  colSpan={4}
                  className="text-muted-foreground py-12 text-center text-sm"
                >
                  No extensions found. Click "Sync now" to fetch from Google
                  Workspace.
                </TableCell>
              </TableRow>
            )}
            {appsData?.rows.map((ext) => (
              <TableRow
                key={ext.chromeExtensionId}
                className={
                  ext.isFlagged
                    ? "border-l-destructive bg-destructive/5 border-l-2"
                    : ""
                }
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    {ext.isFlagged && (
                      <AlertTriangle className="text-destructive h-3.5 w-3.5 shrink-0" />
                    )}
                    <div className="min-w-0">
                      <p
                        className={`truncate text-sm font-medium ${ext.isFlagged ? "text-destructive" : ""}`}
                      >
                        {ext.displayName ?? ext.chromeExtensionId}
                      </p>
                      {ext.flaggedReason && (
                        <p className="text-muted-foreground truncate text-xs">
                          {ext.flaggedReason}
                        </p>
                      )}
                    </div>
                  </div>
                </TableCell>
                <TableCell>
                  <InstallTypeChip type={ext.installType} />
                </TableCell>
                <TableCell>
                  <RiskScore score={ext.riskScore ?? 0} />
                </TableCell>
                <TableCell className="text-right text-sm font-medium tabular-nums">
                  {ext.browserDeviceCount}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>

      {appsData && appsData.total > appsData.limit && (
        <p className="text-muted-foreground text-center text-xs">
          Showing {appsData.rows.length} of {appsData.total} extensions
        </p>
      )}
    </div>
  );
}

// ─── Settings tab ────────────────────────────────────────────────────────────

const ALL_EVENTS = [
  {
    id: "threat.detected",
    label: "Threat detected",
    description: "A device has a flagged extension installed",
  },
  {
    id: "alert.created",
    label: "Alert created",
    description: "A new security alert was raised for an org member",
  },
  {
    id: "device.enrolled",
    label: "Device enrolled",
    description: "A new device joins the organisation",
  },
] as const;

type WebhookEventId = (typeof ALL_EVENTS)[number]["id"];

function SettingsTab({ orgId: _orgId }: { orgId: string }) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();

  const { data: webhooks, isPending } = useQuery(
    trpc.webhooks.list.queryOptions(),
  );

  const invalidate = () =>
    void queryClient.invalidateQueries(trpc.webhooks.list.queryFilter());

  const deleteMutation = useMutation(
    trpc.webhooks.delete.mutationOptions({ onSuccess: invalidate }),
  );
  const toggleMutation = useMutation(
    trpc.webhooks.setEnabled.mutationOptions({ onSuccess: invalidate }),
  );
  const testMutation = useMutation(trpc.webhooks.test.mutationOptions());

  // ── Create form state ──
  const [showForm, setShowForm] = useState(false);
  const [formUrl, setFormUrl] = useState("");
  const [formDesc, setFormDesc] = useState("");
  const [formEvents, setFormEvents] = useState<WebhookEventId[]>([
    "threat.detected",
  ]);
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [testedId, setTestedId] = useState<string | null>(null);

  const createMutation = useMutation(
    trpc.webhooks.create.mutationOptions({
      onSuccess: (data) => {
        setNewSecret(data.secret);
        setShowForm(false);
        setFormUrl("");
        setFormDesc("");
        setFormEvents(["threat.detected"]);
        invalidate();
      },
    }),
  );

  function toggleEvent(id: WebhookEventId) {
    setFormEvents((prev) =>
      prev.includes(id) ? prev.filter((e) => e !== id) : [...prev, id],
    );
  }

  async function copySecret(secret: string) {
    await navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-6">
      {/* ── New secret banner ────────────────────────────────────────────── */}
      {newSecret && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-emerald-600">
            <CheckCircle className="h-4 w-4" />
            Webhook created - copy your secret now
          </div>
          <p className="text-muted-foreground mb-3 text-xs">
            This is the only time the full secret will be shown. Store it
            securely.
          </p>
          <div className="flex items-center gap-2">
            <code className="bg-muted flex-1 overflow-x-auto rounded px-3 py-2 font-mono text-xs">
              {newSecret}
            </code>
            <Button
              size="sm"
              variant="outline"
              className="shrink-0 gap-1.5"
              onClick={() => void copySecret(newSecret)}
            >
              {copied ? (
                <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <Button
            size="sm"
            variant="ghost"
            className="text-muted-foreground mt-2 text-xs"
            onClick={() => setNewSecret(null)}
          >
            I've saved it - dismiss
          </Button>
        </div>
      )}

      {/* ── Webhooks section ─────────────────────────────────────────────── */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Webhook className="h-4 w-4" />
            Webhooks
          </h2>
          {!showForm && (
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => setShowForm(true)}
            >
              <Plus className="h-3.5 w-3.5" />
              Add webhook
            </Button>
          )}
        </div>

        {/* Create form */}
        {showForm && (
          <Card className="space-y-4 p-4">
            <h3 className="text-sm font-semibold">New webhook</h3>

            <div className="space-y-2">
              <Label htmlFor="wh-url" className="text-xs">
                Endpoint URL
              </Label>
              <Input
                id="wh-url"
                placeholder="https://your-server.example.com/webhooks/aibp"
                value={formUrl}
                onChange={(e) => setFormUrl(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="wh-desc" className="text-xs">
                Description (optional)
              </Label>
              <Input
                id="wh-desc"
                placeholder="e.g. Slack alerts"
                value={formDesc}
                onChange={(e) => setFormDesc(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <p className="text-foreground text-xs font-medium">
                Events to subscribe
              </p>
              <div className="space-y-2">
                {ALL_EVENTS.map((ev) => (
                  <label
                    key={ev.id}
                    className="flex cursor-pointer items-start gap-3"
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={formEvents.includes(ev.id)}
                      onChange={() => toggleEvent(ev.id)}
                    />
                    <div>
                      <p className="text-sm font-medium">{ev.label}</p>
                      <p className="text-muted-foreground text-xs">
                        {ev.description}
                      </p>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex gap-2">
              <Button
                size="sm"
                disabled={
                  !formUrl ||
                  formEvents.length === 0 ||
                  createMutation.isPending
                }
                onClick={() =>
                  createMutation.mutate({
                    url: formUrl,
                    description: formDesc || undefined,
                    events: formEvents,
                  })
                }
              >
                {createMutation.isPending ? (
                  <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                ) : null}
                Create webhook
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setShowForm(false)}
              >
                Cancel
              </Button>
            </div>
          </Card>
        )}

        {/* List */}
        {isPending && (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-5 w-5 animate-spin opacity-30" />
          </div>
        )}

        {!isPending && (!webhooks || webhooks.length === 0) && !showForm && (
          <div className="text-muted-foreground flex flex-col items-center gap-2 py-12">
            <Webhook className="h-8 w-8 opacity-20" />
            <p className="text-sm">No webhooks configured yet.</p>
            <p className="text-xs">
              Add one to receive real-time event notifications on your server.
            </p>
          </div>
        )}

        {webhooks && webhooks.length > 0 && (
          <div className="space-y-2">
            {webhooks.map((wh) => (
              <Card
                key={wh.id}
                className={`p-4 ${!wh.enabled ? "opacity-60" : ""}`}
              >
                <div className="flex items-start gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate font-mono text-sm font-medium">
                        {wh.url}
                      </span>
                      {!wh.enabled && (
                        <Badge variant="secondary" className="text-xs">
                          Disabled
                        </Badge>
                      )}
                    </div>
                    {wh.description && (
                      <p className="text-muted-foreground mt-0.5 text-xs">
                        {wh.description}
                      </p>
                    )}
                    <div className="mt-2 flex flex-wrap gap-1">
                      {wh.events.map((ev) => (
                        <span
                          key={ev}
                          className="bg-muted text-muted-foreground rounded-full px-2 py-0.5 font-mono text-[10px]"
                        >
                          {ev}
                        </span>
                      ))}
                    </div>
                    <p className="text-muted-foreground mt-2 font-mono text-[11px]">
                      {wh.secretMasked}
                    </p>
                  </div>

                  <div className="flex shrink-0 gap-1">
                    {/* Test */}
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 gap-1.5 px-2 text-xs"
                      disabled={testMutation.isPending || !wh.enabled}
                      title="Send test event"
                      onClick={() => {
                        setTestedId(wh.id);
                        testMutation.mutate(
                          { webhookId: wh.id },
                          {
                            onSettled: () =>
                              setTimeout(() => setTestedId(null), 2000),
                          },
                        );
                      }}
                    >
                      {testedId === wh.id ? (
                        <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />
                      ) : (
                        <Zap className="h-3.5 w-3.5" />
                      )}
                      Test
                    </Button>
                    {/* Toggle enable */}
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 px-2 text-xs"
                      disabled={toggleMutation.isPending}
                      onClick={() =>
                        toggleMutation.mutate({
                          webhookId: wh.id,
                          enabled: !wh.enabled,
                        })
                      }
                    >
                      {wh.enabled ? "Disable" : "Enable"}
                    </Button>
                    {/* Delete */}
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-muted-foreground hover:text-destructive h-8 w-8 p-0"
                      disabled={deleteMutation.isPending}
                      onClick={() =>
                        deleteMutation.mutate({ webhookId: wh.id })
                      }
                      title="Delete webhook"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </section>

      {/* ── Signing guide ─────────────────────────────────────────────────── */}
      <section className="space-y-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <Settings className="h-4 w-4" />
          Verifying signatures
        </h2>
        <Card className="p-4">
          <p className="text-muted-foreground mb-3 text-xs leading-relaxed">
            Every delivery includes an{" "}
            <code className="bg-muted rounded px-1 py-0.5">
              X-AIBP-Signature
            </code>{" "}
            header. Verify it with HMAC-SHA256 to confirm the payload came from
            us and wasn't tampered with.
          </p>
          <pre className="bg-muted text-foreground overflow-x-auto rounded p-3 text-[11px] leading-relaxed">{`// Node.js / Express example
import { createHmac, timingSafeEqual } from "crypto";

function verifySignature(secret, rawBody, header) {
  const [tPart, v1Part] = header.split(",");
  const timestamp = tPart.replace("t=", "");
  const expected  = v1Part.replace("v1=", "");

  const mac = createHmac("sha256", secret)
    .update(\`\${timestamp}.\${rawBody}\`)
    .digest("hex");

  return timingSafeEqual(
    Buffer.from(mac),
    Buffer.from(expected),
  );
}`}</pre>
        </Card>
      </section>
    </div>
  );
}

// ─── Shared sub-components ────────────────────────────────────────────────────

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 70
      ? "bg-destructive"
      : score >= 40
        ? "bg-orange-500"
        : "bg-emerald-500";
  const textColor =
    score >= 70
      ? "text-destructive"
      : score >= 40
        ? "text-orange-500"
        : "text-muted-foreground";
  return (
    <div className="flex items-center gap-2">
      <span
        className={`w-7 text-right text-xs font-semibold tabular-nums ${textColor}`}
      >
        {score}
      </span>
      <div className="bg-muted h-1.5 w-16 overflow-hidden rounded-full">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}
