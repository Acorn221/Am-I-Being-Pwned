import type {
  Column,
  ColumnDef,
  Row,
  SortingState,
} from "@tanstack/react-table";
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import {
  AlertTriangle,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  ArrowUpDown,
  Bell,
  Braces,
  Building2,
  CheckCheck,
  CheckCircle,
  Cloud,
  Copy,
  Link2,
  LogOut,
  Monitor,
  Plus,
  Puzzle,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  ShieldCheck,
  Trash2,
  Webhook,
  X,
  Zap,
} from "lucide-react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@amibeingpwned/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@amibeingpwned/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@amibeingpwned/ui/dropdown-menu";
import { Field, FieldGroup, FieldLabel } from "@amibeingpwned/ui/field";
import { Input } from "@amibeingpwned/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@amibeingpwned/ui/table";
import { Skeleton } from "@amibeingpwned/ui/skeleton";
import { toast } from "@amibeingpwned/ui/toast";

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

type Tab =
  | "overview"
  | "alerts"
  | "devices"
  | "extensions"
  | "settings"
  | "webhooks";

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

// ─── Tab routing helpers ──────────────────────────────────────────────────────

const VALID_TABS = new Set<Tab>([
  "overview",
  "alerts",
  "devices",
  "extensions",
  "settings",
  "webhooks",
]);

function getTab(): Tab {
  const segment = window.location.pathname.split("/")[2];
  return VALID_TABS.has(segment as Tab) ? (segment as Tab) : "overview";
}

function subscribeToLocation(cb: () => void) {
  window.addEventListener("popstate", cb);
  return () => window.removeEventListener("popstate", cb);
}

function useTab(): [Tab, (t: Tab) => void] {
  const tab = useSyncExternalStore(subscribeToLocation, getTab);
  function setTab(t: Tab) {
    window.history.pushState(null, "", `/dashboard/${t}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }
  return [tab, setTab];
}

// ─── Root component ───────────────────────────────────────────────────────────

export function FleetDashboard({ overview }: { overview: FleetOverview }) {
  const [tab, setTab] = useTab();

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
          <img src="/logo.png" alt="" className="h-7 w-auto" />
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
        {tab === "webhooks" && <WebhooksPage />}
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

  const safeCount = overview.extensionCount - overview.flaggedCount;
  const extensionPieData = [
    { name: "Safe", value: safeCount, color: "#10b981" },
    { name: "Flagged", value: overview.flaggedCount, color: "#ef4444" },
  ].filter((d) => d.value > 0);

  const alertSeverityData = alerts
    ? (["critical", "warning", "info"] as const).map((s) => ({
        name: s.charAt(0).toUpperCase() + s.slice(1),
        count: alerts.filter((a) => a.severity === s).length,
        color:
          s === "critical" ? "#ef4444" : s === "warning" ? "#f97316" : "#6b7280",
      }))
    : [];

  return (
    <div className="space-y-5">
      {/* Stats strip - full width */}
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

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/* Extension health donut */}
        <Card className="p-4">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold">Extension Health</CardTitle>
            <CardDescription className="text-xs">
              Safe vs flagged across all devices
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {overview.extensionCount === 0 ? (
              <div className="text-muted-foreground flex h-32 items-center justify-center text-sm">
                No extensions detected yet
              </div>
            ) : (
              <div className="flex items-center gap-4">
                <ResponsiveContainer width="100%" height={130}>
                  <PieChart>
                    <Pie
                      data={extensionPieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={38}
                      outerRadius={58}
                      paddingAngle={extensionPieData.length > 1 ? 3 : 0}
                      dataKey="value"
                      strokeWidth={0}
                    >
                      {extensionPieData.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "var(--card)",
                        border: "1px solid var(--border)",
                        borderRadius: "6px",
                        fontSize: "12px",
                        color: "var(--foreground)",
                      }}
                      formatter={(value: number | undefined, name: string | undefined) => [value, name]}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="shrink-0 space-y-2 text-xs">
                  {extensionPieData.map((d) => (
                    <div key={d.name} className="flex items-center gap-2">
                      <span
                        className="h-2.5 w-2.5 shrink-0 rounded-full"
                        style={{ background: d.color }}
                      />
                      <span className="text-muted-foreground">{d.name}</span>
                      <span className="font-semibold tabular-nums">{d.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Alert severity breakdown */}
        <Card className="p-4">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold">Active Alerts</CardTitle>
            <CardDescription className="text-xs">
              Unread alerts by severity
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {!alerts || overview.unreadAlertCount === 0 ? (
              <div className="text-muted-foreground flex h-32 items-center justify-center gap-2 text-sm">
                <ShieldCheck className="h-4 w-4 text-emerald-500" />
                No active alerts
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={130}>
                <BarChart
                  data={alertSeverityData}
                  margin={{ top: 4, right: 8, left: -24, bottom: 0 }}
                  barSize={32}
                >
                  <XAxis
                    dataKey="name"
                    tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: "var(--muted)", opacity: 0.3 }}
                    contentStyle={{
                      background: "var(--card)",
                      border: "1px solid var(--border)",
                      borderRadius: "6px",
                      fontSize: "12px",
                      color: "var(--foreground)",
                    }}
                    formatter={(value: number | undefined) => [value, "alerts"]}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {alertSeverityData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
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

// ─── Workspace requirements gate ─────────────────────────────────────────────

function WorkspaceSetupCard({
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
              {isSyncing ? "Syncing…" : "Try again"}
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
                {isSyncing ? "Connecting…" : "Connect & Sync"}
              </Button>
            )}
          </>
        )}
      </Card>
    </div>
  );
}

// ─── Devices data tables ──────────────────────────────────────────────────────

type FleetDeviceSortBy = "extensionCount" | "flaggedCount" | "lastSeenAt";
type WorkspaceSortBy = "machineName" | "extensionCount" | "lastSyncedAt";

interface DeviceRow {
  id: string;
  displayName: string | null;
  platform: string | null;
  os: string | null;
  arch: string | null;
  identityEmail: string | null;
  extensionCount: number;
  flaggedExtensionCount: number | null;
  lastActivityAt: Date;
}


function DeviceSortableHeader({
  column,
  label,
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  column: Column<DeviceRow, any>;
  label: string;
}) {
  const sorted = column.getIsSorted();
  return (
    <button
      className="hover:text-foreground flex items-center gap-1 text-xs font-medium tracking-wide uppercase"
      onClick={() => column.toggleSorting(sorted === "asc")}
    >
      {label}
      {sorted === "asc" ? (
        <ArrowUp className="h-3 w-3" />
      ) : sorted === "desc" ? (
        <ArrowDown className="h-3 w-3" />
      ) : (
        <ArrowUpDown className="h-3 w-3 opacity-40" />
      )}
    </button>
  );
}

const FLEET_DEV_COL_SORT: Record<string, FleetDeviceSortBy> = {
  extensionCount: "extensionCount",
  flaggedExtensionCount: "flaggedCount",
  lastActivityAt: "lastSeenAt",
};

const WS_DEV_COL_SORT: Record<string, WorkspaceSortBy> = {
  displayName: "machineName",
  extensionCount: "extensionCount",
  lastActivityAt: "lastSyncedAt",
};

function FleetDevicesDataTable() {
  const trpc = useTRPC();
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [sortBy, setSortBy] = useState<FleetDeviceSortBy>("flaggedCount");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [platformFilter, setPlatformFilter] = useState("");

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(searchInput);
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  useEffect(() => {
    setPage(1);
  }, [platformFilter]);

  const { data, isFetching } = useQuery({
    ...trpc.fleet.devices.queryOptions({
      page,
      limit: pageSize,
      search: debouncedSearch || undefined,
      sortBy,
      sortDir,
      platform: platformFilter
        ? (platformFilter as "chrome" | "edge")
        : undefined,
    }),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const rows = useMemo<DeviceRow[]>(
    () =>
      (data?.rows ?? []).map((d) => {
        const displayName =
          d.identityEmail ??
          (d.os && d.arch ? `${d.os} ${d.arch}` : d.os ?? d.arch ?? null);
        return {
          id: d.id,
          displayName,
          platform: d.platform,
          os: d.os ?? null,
          arch: d.arch ?? null,
          identityEmail: d.identityEmail ?? null,
          extensionCount: d.extensionCount,
          flaggedExtensionCount: d.flaggedExtensionCount,
          lastActivityAt: d.lastSeenAt,
        };
      }),
    [data],
  );

  const colId =
    sortBy === "lastSeenAt"
      ? "lastActivityAt"
      : sortBy === "flaggedCount"
        ? "flaggedExtensionCount"
        : sortBy;
  const sorting: SortingState = [{ id: colId, desc: sortDir === "desc" }];

  const columns = useMemo<ColumnDef<DeviceRow>[]>(
    () => [
      {
        accessorKey: "id",
        header: "Device",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-muted-foreground font-mono text-xs">
            {row.original.id.slice(0, 20)}…
          </span>
        ),
      },
      {
        accessorKey: "identityEmail",
        header: "User",
        enableSorting: false,
        cell: ({ row }) => {
          const email = row.original.identityEmail;
          return email ? (
            <span className="text-sm">{email}</span>
          ) : (
            <span className="text-muted-foreground text-xs">-</span>
          );
        },
      },
      {
        accessorKey: "platform",
        header: "Platform",
        enableSorting: false,
        cell: ({ row }) => (
          <Badge variant="outline" className="text-xs capitalize">
            {row.original.platform}
          </Badge>
        ),
      },
      {
        accessorKey: "extensionCount",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Extensions" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-right text-sm tabular-nums">
            {row.original.extensionCount}
          </div>
        ),
      },
      {
        accessorKey: "flaggedExtensionCount",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Flagged" />
          </div>
        ),
        cell: ({ row }) => {
          const flagged = row.original.flaggedExtensionCount ?? 0;
          return (
            <div className="text-right text-sm tabular-nums">
              {flagged > 0 ? (
                <span className="text-destructive font-medium">{flagged}</span>
              ) : (
                <span className="text-muted-foreground">0</span>
              )}
            </div>
          );
        },
      },
      {
        accessorKey: "lastActivityAt",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Last seen" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-muted-foreground text-right text-xs">
            {timeAgo(row.original.lastActivityAt)}
          </div>
        ),
      },
    ],
    [],
  );

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, pagination: { pageIndex: page - 1, pageSize } },
    manualSorting: true,
    manualPagination: true,
    pageCount,
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      const first = next[0];
      if (first) {
        setSortBy(FLEET_DEV_COL_SORT[first.id] ?? "lastSeenAt");
        setSortDir(first.desc ? "desc" : "asc");
        setPage(1);
      }
    },
    onPaginationChange: (updater) => {
      const next =
        typeof updater === "function"
          ? updater({ pageIndex: page - 1, pageSize })
          : updater;
      setPage(next.pageIndex + 1);
      setPageSize(next.pageSize);
    },
    getCoreRowModel: getCoreRowModel(),
  });

  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div className="space-y-2">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="text-muted-foreground absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2" />
          <Input
            className="pl-8 focus-visible:ring-0"
            placeholder="Search by device ID..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          {isFetching && (
            <RefreshCw className="text-muted-foreground absolute top-1/2 right-2.5 h-3.5 w-3.5 -translate-y-1/2 animate-spin" />
          )}
        </div>
        <div className="flex items-center gap-2">
          <select
            value={platformFilter}
            onChange={(e) => setPlatformFilter(e.target.value)}
            className="border-input dark:bg-input/30 rounded-md border bg-transparent px-2 py-[7px] text-xs outline-none"
          >
            <option value="">All platforms</option>
            <option value="chrome">Chrome</option>
            <option value="edge">Edge</option>
          </select>
          {platformFilter && (
            <button
              onClick={() => setPlatformFilter("")}
              className="border-input dark:bg-input/30 text-muted-foreground hover:text-foreground rounded-md border bg-transparent p-[7px] transition-colors"
              title="Clear filters"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      <Card className="overflow-hidden py-0">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id} className="hover:bg-transparent">
                {hg.headers.map((header) => (
                  <TableHead key={header.id} className="h-9 px-3">
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {!data ? (
              Array.from({ length: pageSize }).map((_, i) => (
                <TableRow key={i} className="pointer-events-none">
                  {columns.map((_, j) => (
                    <TableCell key={j} className="px-3">
                      <Skeleton className="h-4 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="text-muted-foreground py-8 text-center text-sm"
                >
                  No devices found.
                </TableCell>
              </TableRow>
            ) : (
              <>
                {table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    className={row.index % 2 === 1 ? "bg-muted/20" : ""}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id} className="px-3">
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext(),
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
                {Array.from({
                  length: Math.max(
                    0,
                    pageSize - table.getRowModel().rows.length,
                  ),
                }).map((_, i) => (
                  <TableRow
                    key={`filler-${i}`}
                    aria-hidden
                    className="pointer-events-none select-none opacity-0"
                  >
                    <TableCell colSpan={columns.length}>&nbsp;</TableCell>
                  </TableRow>
                ))}
              </>
            )}
          </TableBody>
        </Table>
      </Card>

      {total > 0 && (
        <div className="flex items-center justify-between pt-1">
          <span className="text-muted-foreground text-xs">{`Showing ${start}-${end} of ${total}`}</span>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground text-xs">Rows per page</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                >
                  {pageSize} <ArrowDown className="h-3 w-3 opacity-50" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="min-w-16">
                <DropdownMenuRadioGroup
                  value={String(pageSize)}
                  onValueChange={(v) => {
                    setPageSize(Number(v));
                    setPage(1);
                  }}
                >
                  {[10, 25, 50].map((ps) => (
                    <DropdownMenuRadioItem
                      key={ps}
                      value={String(ps)}
                      className="text-xs"
                    >
                      {ps}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
            </Button>
            <span className="text-muted-foreground text-xs tabular-nums">
              {page} / {pageCount}
            </span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function WorkspaceDevicesDataTable() {
  const trpc = useTRPC();
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [sortBy, setSortBy] = useState<WorkspaceSortBy>("extensionCount");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(searchInput);
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  const { data, isFetching } = useQuery({
    ...trpc.workspace.devices.queryOptions({
      page,
      limit: pageSize,
      search: debouncedSearch || undefined,
      sortBy,
      sortDir,
    }),
    placeholderData: keepPreviousData,
  });

  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const rows = useMemo<DeviceRow[]>(
    () =>
      (data?.rows ?? []).map((d) => ({
        id: d.googleDeviceId,
        displayName: d.machineName,
        platform: null,
        os: null,
        arch: null,
        identityEmail: null,
        extensionCount: d.extensionCount,
        flaggedExtensionCount: null,
        lastActivityAt: d.lastSyncedAt,
      })),
    [data],
  );

  const wsColId =
    sortBy === "machineName"
      ? "displayName"
      : sortBy === "lastSyncedAt"
        ? "lastActivityAt"
        : sortBy;
  const sorting: SortingState = [{ id: wsColId, desc: sortDir === "desc" }];

  const columns = useMemo<ColumnDef<DeviceRow>[]>(
    () => [
      {
        accessorKey: "displayName",
        header: ({ column }) => (
          <DeviceSortableHeader column={column} label="Machine" />
        ),
        cell: ({ row }) =>
          row.original.displayName ? (
            <span className="text-sm font-medium">
              {row.original.displayName}
            </span>
          ) : (
            <span className="text-muted-foreground font-mono text-xs">
              {row.original.id.slice(0, 20)}…
            </span>
          ),
      },
      {
        accessorKey: "extensionCount",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Extensions" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-right text-sm tabular-nums">
            {row.original.extensionCount}
          </div>
        ),
      },
      {
        accessorKey: "lastActivityAt",
        header: ({ column }) => (
          <div className="text-right">
            <DeviceSortableHeader column={column} label="Last synced" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-muted-foreground text-right text-xs">
            {timeAgo(row.original.lastActivityAt)}
          </div>
        ),
      },
    ],
    [],
  );

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, pagination: { pageIndex: page - 1, pageSize } },
    manualSorting: true,
    manualPagination: true,
    pageCount,
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      const first = next[0];
      if (first) {
        setSortBy(WS_DEV_COL_SORT[first.id] ?? "extensionCount");
        setSortDir(first.desc ? "desc" : "asc");
        setPage(1);
      }
    },
    onPaginationChange: (updater) => {
      const next =
        typeof updater === "function"
          ? updater({ pageIndex: page - 1, pageSize })
          : updater;
      setPage(next.pageIndex + 1);
      setPageSize(next.pageSize);
    },
    getCoreRowModel: getCoreRowModel(),
  });

  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div className="space-y-2">
      <div className="relative">
        <Search className="text-muted-foreground absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2" />
        <Input
          className="pl-8 focus-visible:ring-0"
          placeholder="Search by machine name..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />
        {isFetching && (
          <RefreshCw className="text-muted-foreground absolute top-1/2 right-2.5 h-3.5 w-3.5 -translate-y-1/2 animate-spin" />
        )}
      </div>

      <Card className="overflow-hidden py-0">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id} className="hover:bg-transparent">
                {hg.headers.map((header) => (
                  <TableHead key={header.id} className="h-9 px-3">
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {!data ? (
              Array.from({ length: pageSize }).map((_, i) => (
                <TableRow key={i} className="pointer-events-none">
                  {columns.map((_, j) => (
                    <TableCell key={j} className="px-3">
                      <Skeleton className="h-4 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="text-muted-foreground py-8 text-center text-sm"
                >
                  No devices found.
                </TableCell>
              </TableRow>
            ) : (
              <>
                {table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    className={row.index % 2 === 1 ? "bg-muted/20" : ""}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id} className="px-3">
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext(),
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
                {Array.from({
                  length: Math.max(
                    0,
                    pageSize - table.getRowModel().rows.length,
                  ),
                }).map((_, i) => (
                  <TableRow
                    key={`filler-${i}`}
                    aria-hidden
                    className="pointer-events-none select-none opacity-0"
                  >
                    <TableCell colSpan={columns.length}>&nbsp;</TableCell>
                  </TableRow>
                ))}
              </>
            )}
          </TableBody>
        </Table>
      </Card>

      {total > 0 && (
        <div className="flex items-center justify-between pt-1">
          <span className="text-muted-foreground text-xs">{`Showing ${start}-${end} of ${total}`}</span>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground text-xs">Rows per page</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                >
                  {pageSize} <ArrowDown className="h-3 w-3 opacity-50" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="min-w-16">
                <DropdownMenuRadioGroup
                  value={String(pageSize)}
                  onValueChange={(v) => {
                    setPageSize(Number(v));
                    setPage(1);
                  }}
                >
                  {[10, 25, 50].map((ps) => (
                    <DropdownMenuRadioItem
                      key={ps}
                      value={String(ps)}
                      className="text-xs"
                    >
                      {ps}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
            </Button>
            <span className="text-muted-foreground text-xs tabular-nums">
              {page} / {pageCount}
            </span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Devices tab ──────────────────────────────────────────────────────────────

function DevicesTab({ overview: _overview }: { overview: FleetOverview }) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const [blockedReason, setBlockedReason] = useState<string | undefined>();

  // Lightweight existence checks - the data tables own their own full queries
  const { data: fleetCheck, isPending: fleetPending } = useQuery(
    trpc.fleet.devices.queryOptions({ page: 1, limit: 1 }),
  );
  const { data: wsCheck, isPending: wsPending } = useQuery(
    trpc.workspace.devices.queryOptions({ page: 1, limit: 1 }),
  );

  const syncMutation = useMutation(
    trpc.workspace.sync.mutationOptions({
      onSuccess: (data) => {
        void queryClient.invalidateQueries(
          trpc.workspace.devices.queryFilter(),
        );
        void queryClient.invalidateQueries(trpc.workspace.apps.queryFilter());
        if (data.appCount === 0) {
          toast.warning(
            "Sync complete but no data yet - Google's API can take a few hours to reflect newly enrolled browsers. Try again later.",
            { duration: 10000 },
          );
        } else {
          toast.success(
            `Sync complete - ${data.appCount} extensions, ${data.deviceCount} devices`,
          );
        }
      },
      onError: (err) => {
        if (err.message.includes("Could not resolve 'my_customer'")) {
          setBlockedReason(
            "This account isn't a Google Workspace super admin, or Chrome Browser Cloud Management (CBCM) isn't enabled on your domain. Contact your Workspace admin.",
          );
        } else {
          const msg =
            err.message.includes("401") || err.message.includes("403")
              ? "Google access denied - try signing out and back in to re-grant permissions."
              : `Sync failed: ${err.message}`;
          toast.error(msg, { duration: 8000 });
        }
      },
    }),
  );

  if (fleetPending || wsPending) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-5 w-5 animate-spin opacity-30" />
      </div>
    );
  }

  const hasFleetDevices = (fleetCheck?.total ?? 0) > 0;
  const hasWorkspaceDevices = (wsCheck?.total ?? 0) > 0;

  if (!hasFleetDevices && !hasWorkspaceDevices) {
    return (
      <WorkspaceSetupCard
        onSync={() => syncMutation.mutate()}
        isSyncing={syncMutation.isPending}
        blockedReason={blockedReason}
      />
    );
  }

  return (
    <div className="space-y-6">
      {hasFleetDevices && (
        <div className="space-y-3">
          <div className="text-muted-foreground flex items-center gap-2 text-sm">
            <Monitor className="h-4 w-4" />
            <span>Devices registered via extension</span>
          </div>
          <FleetDevicesDataTable />
        </div>
      )}

      {hasWorkspaceDevices && (
        <div className="space-y-3">
          <div className="text-muted-foreground flex items-center gap-2 text-sm">
            <Cloud className="h-4 w-4" />
            <span>Chrome browsers enrolled in Google Workspace</span>
          </div>
          <WorkspaceDevicesDataTable />
        </div>
      )}

      {hasFleetDevices && !hasWorkspaceDevices && (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Cloud className="h-4 w-4" />
              Connect Google Workspace
            </CardTitle>
            <CardDescription>
              Also sync managed Chrome browsers via the Chrome Management API
              for fuller device coverage.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              disabled={syncMutation.isPending}
              onClick={() => syncMutation.mutate()}
            >
              <RefreshCw
                className={`h-4 w-4 ${syncMutation.isPending ? "animate-spin" : ""}`}
              />
              {syncMutation.isPending ? "Connecting…" : "Connect & Sync"}
            </Button>
            {blockedReason && (
              <p className="text-destructive mt-2 text-xs">{blockedReason}</p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Extensions data table ────────────────────────────────────────────────────

interface ExtRow {
  chromeExtensionId: string;
  displayName: string | null;
  installType: string | null | undefined;
  flaggedReason: string | null | undefined;
  riskScore: number | null;
  isFlagged: boolean | null;
  deviceCount: number;
  enabledCount?: number;
}

function SortableHeader({
  column,
  label,
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  column: Column<ExtRow, any>;
  label: string;
}) {
  const sorted = column.getIsSorted();
  return (
    <button
      className="hover:text-foreground flex items-center gap-1 text-xs font-medium tracking-wide uppercase"
      onClick={() => column.toggleSorting(sorted === "asc")}
    >
      {label}
      {sorted === "asc" ? (
        <ArrowUp className="h-3 w-3" />
      ) : sorted === "desc" ? (
        <ArrowDown className="h-3 w-3" />
      ) : (
        <ArrowUpDown className="h-3 w-3 opacity-40" />
      )}
    </button>
  );
}

type SortBy = "name" | "riskScore" | "deviceCount";
type RiskLevel = "all" | "low" | "medium" | "high";

// Maps TanStack column IDs to the sortBy param the server expects
const COLUMN_TO_SORT: Record<string, SortBy> = {
  displayName: "name",
  riskScore: "riskScore",
  deviceCount: "deviceCount",
};

function ExtensionsDataTable({
  source,
  showInstallType = false,
}: {
  source: "fleet" | "workspace";
  showInstallType?: boolean;
}) {
  const trpc = useTRPC();

  // Filter / sort / pagination state
  const [searchInput, setSearchInput] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [sortBy, setSortBy] = useState<SortBy>("riskScore");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [showFlaggedOnly, setShowFlaggedOnly] = useState(false);
  const [riskFilter, setRiskFilter] = useState<RiskLevel>("all");
  const [installTypeFilter, setInstallTypeFilter] = useState("");
  const [onlyEnabled, setOnlyEnabled] = useState(false);

  // Debounce search - reset to page 1 when it fires
  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(searchInput);
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
  }, [showFlaggedOnly, riskFilter, installTypeFilter, onlyEnabled]);

  const sharedParams = {
    page,
    limit: pageSize,
    search: debouncedSearch || undefined,
    sortBy,
    sortDir,
    isFlagged: showFlaggedOnly ? true : undefined,
    riskLevel: riskFilter === "all" ? undefined : riskFilter,
  } as const;

  const fleetQuery = useQuery({
    ...trpc.fleet.extensions.queryOptions({
      ...sharedParams,
      onlyEnabled: onlyEnabled ? true : undefined,
    }),
    enabled: source === "fleet",
    placeholderData: keepPreviousData,
  });

  const workspaceQuery = useQuery({
    ...trpc.workspace.apps.queryOptions({
      ...sharedParams,
      installType: installTypeFilter || undefined,
    }),
    enabled: source === "workspace",
    placeholderData: keepPreviousData,
  });

  const activeQuery = source === "fleet" ? fleetQuery : workspaceQuery;
  const isFetching = activeQuery.isFetching;
  const total = activeQuery.data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const rows = useMemo<ExtRow[]>(() => {
    if (source === "fleet") {
      return (fleetQuery.data?.rows ?? []).map((r) => ({
        chromeExtensionId: r.chromeExtensionId,
        displayName: r.name,
        installType: undefined,
        flaggedReason: undefined,
        riskScore: r.riskScore,
        isFlagged: r.isFlagged,
        deviceCount: r.deviceCount,
        enabledCount: r.enabledCount,
      }));
    }
    return (workspaceQuery.data?.rows ?? []).map((r) => ({
      chromeExtensionId: r.chromeExtensionId,
      displayName: r.displayName,
      installType: r.installType,
      flaggedReason: r.flaggedReason,
      riskScore: r.riskScore,
      isFlagged: r.isFlagged,
      deviceCount: r.browserDeviceCount,
    }));
  }, [source, fleetQuery.data, workspaceQuery.data]);

  const columns = useMemo<ColumnDef<ExtRow>[]>(() => {
    const cols: ColumnDef<ExtRow>[] = [
      {
        accessorKey: "displayName",
        header: ({ column }) => (
          <SortableHeader column={column} label="Extension" />
        ),
        cell: ({ row }) => {
          const r = row.original;
          return (
            <div className="flex min-w-0 items-center gap-2">
              {r.isFlagged && (
                <AlertTriangle className="text-destructive h-3.5 w-3.5 shrink-0" />
              )}
              <div className="min-w-0">
                <p
                  className={`truncate text-sm font-medium ${r.isFlagged ? "text-destructive" : ""}`}
                >
                  {r.displayName ?? r.chromeExtensionId}
                </p>
                {r.flaggedReason && (
                  <p className="text-muted-foreground truncate text-xs">
                    {r.flaggedReason}
                  </p>
                )}
              </div>
            </div>
          );
        },
      },
      ...(showInstallType
        ? [
            {
              accessorKey: "installType" as const,
              header: "Install type",
              enableSorting: false,
              cell: ({ row }: { row: Row<ExtRow> }) => (
                <InstallTypeChip type={row.original.installType ?? null} />
              ),
            },
          ]
        : []),
      {
        accessorKey: "riskScore",
        header: ({ column }) => <SortableHeader column={column} label="Risk" />,
        cell: ({ row }) => <RiskScore score={row.original.riskScore ?? 0} />,
      },
      {
        accessorKey: "deviceCount",
        header: ({ column }) => (
          <div className="text-right">
            <SortableHeader column={column} label="Devices" />
          </div>
        ),
        cell: ({ row }) => (
          <div className="text-right text-sm font-medium tabular-nums">
            {row.original.deviceCount}
          </div>
        ),
      },
      ...(source === "fleet"
        ? [
            {
              accessorKey: "enabledCount" as const,
              header: () => (
                <div className="text-right text-xs font-medium tracking-wide uppercase">
                  Enabled
                </div>
              ),
              enableSorting: false,
              cell: ({ row }: { row: Row<ExtRow> }) => {
                const { enabledCount, deviceCount } = row.original;
                if (enabledCount === undefined) return null;
                return (
                  <div className="text-right">
                    <span className="text-muted-foreground text-xs tabular-nums">
                      {enabledCount}/{deviceCount}
                    </span>
                  </div>
                );
              },
            },
          ]
        : []),
    ];
    return cols;
  }, [source, showInstallType]);

  const sorting: SortingState = [
    {
      id: sortBy === "name" ? "displayName" : sortBy,
      desc: sortDir === "desc",
    },
  ];

  const table = useReactTable({
    data: rows,
    columns,
    state: {
      sorting,
      pagination: { pageIndex: page - 1, pageSize },
    },
    manualSorting: true,
    manualPagination: true,
    pageCount,
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      const first = next[0];
      if (first) {
        setSortBy(COLUMN_TO_SORT[first.id] ?? "deviceCount");
        setSortDir(first.desc ? "desc" : "asc");
        setPage(1);
      }
    },
    onPaginationChange: (updater) => {
      const next =
        typeof updater === "function"
          ? updater({ pageIndex: page - 1, pageSize })
          : updater;
      setPage(next.pageIndex + 1);
      setPageSize(next.pageSize);
    },
    getCoreRowModel: getCoreRowModel(),
  });

  const hasActiveFilters =
    showFlaggedOnly || riskFilter !== "all" || installTypeFilter !== "" || onlyEnabled;
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  return (
    <div className="space-y-2">
      {/* Toolbar */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="text-muted-foreground absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2" />
          <Input
            className="pl-8 focus-visible:ring-0"
            placeholder="Search by name or ID..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          {isFetching && (
            <RefreshCw className="text-muted-foreground absolute top-1/2 right-2.5 h-3.5 w-3.5 -translate-y-1/2 animate-spin" />
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFlaggedOnly(!showFlaggedOnly)}
            className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[7px] text-xs font-medium transition-colors ${
              showFlaggedOnly
                ? "border-destructive/50 bg-destructive/10 text-destructive"
                : "border-input text-muted-foreground hover:text-foreground dark:bg-input/30 bg-transparent"
            }`}
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            Flagged
          </button>
          {source === "fleet" && (
            <button
              onClick={() => setOnlyEnabled(!onlyEnabled)}
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[7px] text-xs font-medium transition-colors ${
                onlyEnabled
                  ? "border-green-500/50 bg-green-500/10 text-green-600 dark:text-green-400"
                  : "border-input text-muted-foreground hover:text-foreground dark:bg-input/30 bg-transparent"
              }`}
            >
              <CheckCircle className="h-3.5 w-3.5" />
              Enabled
            </button>
          )}
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value as typeof riskFilter)}
            className="border-input dark:bg-input/30 rounded-md border bg-transparent px-2 py-[7px] text-xs outline-none"
          >
            <option value="all">All risks</option>
            <option value="low">Low+</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
          </select>
          {showInstallType && (
            <select
              value={installTypeFilter}
              onChange={(e) => setInstallTypeFilter(e.target.value)}
              className="border-input dark:bg-input/30 rounded-md border bg-transparent px-2 py-[7px] text-xs outline-none"
            >
              <option value="">All types</option>
              <option value="FORCED">Forced</option>
              <option value="ADMIN">Admin</option>
              <option value="NORMAL">User</option>
              <option value="DEVELOPMENT">Dev</option>
              <option value="SIDELOAD">Sideloaded</option>
            </select>
          )}
          {hasActiveFilters && (
            <button
              onClick={() => {
                setShowFlaggedOnly(false);
                setRiskFilter("all");
                setInstallTypeFilter("");
                setOnlyEnabled(false);
              }}
              className="border-input dark:bg-input/30 text-muted-foreground hover:text-foreground rounded-md border bg-transparent p-[7px] transition-colors"
              title="Clear filters"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <Card className="overflow-hidden py-0">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id} className="hover:bg-transparent">
                {hg.headers.map((header) => (
                  <TableHead key={header.id} className="h-9 px-3">
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {!activeQuery.data ? (
              Array.from({ length: pageSize }).map((_, i) => (
                <TableRow key={i} className="pointer-events-none">
                  {columns.map((_, j) => (
                    <TableCell key={j} className="px-3">
                      <Skeleton className="h-4 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="text-muted-foreground py-8 text-center text-sm"
                >
                  No extensions match your filters.
                </TableCell>
              </TableRow>
            ) : (
              <>
                {table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    className={
                      row.original.isFlagged
                        ? "border-l-destructive bg-destructive/5 border-l-2"
                        : row.index % 2 === 1
                          ? "bg-muted/20"
                          : ""
                    }
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id} className="px-3">
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext(),
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
                {Array.from({
                  length: Math.max(
                    0,
                    pageSize - table.getRowModel().rows.length,
                  ),
                }).map((_, i) => (
                  <TableRow
                    key={`filler-${i}`}
                    aria-hidden
                    className="pointer-events-none select-none opacity-0"
                  >
                    <TableCell colSpan={columns.length}>&nbsp;</TableCell>
                  </TableRow>
                ))}
              </>
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between pt-1">
          <span className="text-muted-foreground text-xs">
            {`Showing ${start}-${end} of ${total}`}
          </span>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground text-xs">Rows per page</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1 px-2 text-xs"
                >
                  {pageSize}
                  <ArrowDown className="h-3 w-3 opacity-50" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="min-w-[4rem]">
                <DropdownMenuRadioGroup
                  value={String(pageSize)}
                  onValueChange={(v) => {
                    setPageSize(Number(v));
                    setPage(1);
                  }}
                >
                  {[10, 25, 50].map((ps) => (
                    <DropdownMenuRadioItem
                      key={ps}
                      value={String(ps)}
                      className="text-xs"
                    >
                      {ps}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
            </Button>
            <span className="text-muted-foreground text-xs tabular-nums">
              {page} / {pageCount}
            </span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              className="h-7 w-7 p-0"
            >
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}
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
  const [blockedReason, setBlockedReason] = useState<string | undefined>();

  // Lightweight existence checks - the tables own their own full queries
  const { data: appsData, isPending: appsLoading } = useQuery(
    trpc.workspace.apps.queryOptions({ page: 1, limit: 1 }),
  );

  const { data: fleetExtData, isPending: fleetLoading } = useQuery(
    trpc.fleet.extensions.queryOptions({ page: 1, limit: 1 }),
  );

  // Check if there are any fleet devices registered (even with no extensions yet)
  const { data: fleetDeviceCheck, isPending: fleetDeviceLoading } = useQuery(
    trpc.fleet.devices.queryOptions({ page: 1, limit: 1 }),
  );

  const syncMutation = useMutation(
    trpc.workspace.sync.mutationOptions({
      onSuccess: (data) => {
        void queryClient.invalidateQueries(trpc.workspace.apps.queryFilter());
        void queryClient.invalidateQueries(
          trpc.workspace.devices.queryFilter(),
        );
        if (data.appCount === 0) {
          toast.warning(
            "Sync complete but no data yet, Google's API can take a few hours to reflect newly enrolled browsers. Try again later.",
            { duration: 10000 },
          );
        } else {
          toast.success(
            `Sync complete, ${data.appCount} extensions, ${data.deviceCount} devices`,
          );
        }
      },
      onError: (err) => {
        if (err.message.includes("Could not resolve 'my_customer'")) {
          setBlockedReason(
            "This account isn't a Google Workspace super admin, or Chrome Browser Cloud Management (CBCM) isn't enabled on your domain. Contact your Workspace admin.",
          );
        } else {
          const msg =
            err.message.includes("401") || err.message.includes("403")
              ? "Google access denied, try signing out and back in to re-grant permissions."
              : `Sync failed: ${err.message}`;
          toast.error(msg, { duration: 8000 });
        }
      },
    }),
  );

  const isSyncing = syncMutation.isPending;
  const isPending = appsLoading || fleetLoading || fleetDeviceLoading;

  const hasWorkspaceData = (appsData?.rows.length ?? 0) > 0;
  const hasFleetData = (fleetExtData?.rows.length ?? 0) > 0;
  const hasFleetDevices = (fleetDeviceCheck?.total ?? 0) > 0;

  if (isPending) {
    return (
      <div className="flex justify-center py-12">
        <RefreshCw className="h-5 w-5 animate-spin opacity-30" />
      </div>
    );
  }

  if (!hasWorkspaceData && !hasFleetData && !hasFleetDevices) {
    const syncedButEmpty = appsData?.lastSyncedAt !== null;
    return (
      <WorkspaceSetupCard
        onSync={() => syncMutation.mutate()}
        isSyncing={isSyncing}
        blockedReason={blockedReason}
        syncedButEmpty={syncedButEmpty}
      />
    );
  }

  return (
    <div className="space-y-8">
      {/* Extension agent section */}
      {hasFleetDevices && !hasFleetData && (
        <div className="rounded-lg border border-dashed px-6 py-8 text-center">
          <Puzzle className="text-muted-foreground mx-auto mb-3 h-8 w-8" />
          <p className="text-sm font-medium">Extension connected, no extensions detected yet</p>
          <p className="text-muted-foreground mt-1 text-sm">
            The browser extension is registered. Extension inventory will appear here after the next sync.
          </p>
        </div>
      )}
      {hasFleetData && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Puzzle className="text-muted-foreground h-4 w-4" />
            <span className="text-sm font-medium">Installed Extensions</span>
          </div>
          <ExtensionsDataTable source="fleet" />
        </div>
      )}

      {/* Google Workspace section */}
      {hasWorkspaceData && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cloud className="text-muted-foreground h-4 w-4" />
              <span className="text-sm font-medium">Google Workspace</span>
              {appsData?.lastSyncedAt ? (
                <span className="text-muted-foreground text-xs">
                  - last synced {timeAgo(appsData.lastSyncedAt)}
                </span>
              ) : isSyncing ? (
                <span className="text-muted-foreground flex items-center gap-1 text-xs">
                  <RefreshCw className="h-3 w-3 animate-spin" />
                  Syncing…
                </span>
              ) : (
                <span className="text-muted-foreground text-xs">
                  - never synced
                </span>
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
          <ExtensionsDataTable source="workspace" showInstallType />
        </div>
      )}

      {/* Workspace setup nudge when only fleet data exists */}
      {hasFleetData && !hasWorkspaceData && (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Cloud className="h-4 w-4" />
              Connect Google Workspace
            </CardTitle>
            <CardDescription>
              Sync managed Chrome browsers via the Chrome Management API for
              install type info and per-device extension policies.
            </CardDescription>
            <CardAction>
              <Button
                size="sm"
                variant="outline"
                disabled={isSyncing}
                onClick={() => syncMutation.mutate()}
              >
                <RefreshCw
                  className={`h-3.5 w-3.5 ${isSyncing ? "animate-spin" : ""}`}
                />
                {isSyncing ? "Syncing…" : "Sync"}
              </Button>
            </CardAction>
          </CardHeader>
        </Card>
      )}
    </div>
  );
}

// ─── Settings tab ────────────────────────────────────────────────────────────

function SettingsTab({ orgId: _orgId }: { orgId: string }) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();

  // ── Invite link state ──
  const { data: inviteLinkData } = useQuery(
    trpc.org.hasInviteLink.queryOptions(),
  );
  const [inviteToken, setInviteToken] = useState<string | null>(null);
  const [inviteCopied, setInviteCopied] = useState(false);
  const [showRotateDialog, setShowRotateDialog] = useState(false);

  const rotateMutation = useMutation(
    trpc.org.rotateInviteLink.mutationOptions({
      onSuccess: (data) => {
        setInviteToken(data.token);
        setShowRotateDialog(false);
        void queryClient.invalidateQueries(
          trpc.org.hasInviteLink.queryFilter(),
        );
      },
    }),
  );

  const inviteUrl = inviteToken
    ? `${window.location.origin}/join/${inviteToken}`
    : null;

  async function copyInviteLink() {
    if (!inviteUrl) return;
    await navigator.clipboard.writeText(inviteUrl);
    setInviteCopied(true);
    setTimeout(() => setInviteCopied(false), 2000);
  }

  return (
    <div className="space-y-4">
      {/* Rotate confirmation dialog */}
      <Dialog open={showRotateDialog} onOpenChange={setShowRotateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate invite link?</DialogTitle>
            <DialogDescription>
              The current link will be revoked immediately. Anyone with the old
              link won't be able to use it.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button
              variant="destructive"
              disabled={rotateMutation.isPending}
              onClick={() => rotateMutation.mutate()}
            >
              {rotateMutation.isPending ? (
                <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
              ) : null}
              Rotate link
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Team Enrollment ──────────────────────────────────────────────── */}
      <Card
        footerActions={
          inviteToken && inviteUrl
            ? [
                {
                  label: inviteCopied ? "Copied" : "Copy link",
                  icon: inviteCopied ? CheckCircle : Copy,
                  variant: "outline",
                  onClick: () => void copyInviteLink(),
                },
                {
                  label: "Rotate",
                  icon: RotateCcw,
                  variant: "outline",
                  onClick: () => setShowRotateDialog(true),
                },
              ]
            : inviteLinkData?.hasActiveLink
              ? [
                  {
                    label: "Rotate link",
                    icon: RotateCcw,
                    variant: "outline",
                    onClick: () => setShowRotateDialog(true),
                  },
                ]
              : [
                  {
                    label: rotateMutation.isPending
                      ? "Generating..."
                      : "Generate invite link",
                    icon: rotateMutation.isPending ? RefreshCw : Link2,
                    disabled: rotateMutation.isPending,
                    onClick: () => rotateMutation.mutate(),
                  },
                ]
        }
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-4 w-4" />
            Team Enrollment
          </CardTitle>
          <CardDescription>
            Share an invite link with your team. Anyone who clicks it and
            installs the extension is automatically added to your fleet.
          </CardDescription>
        </CardHeader>

        {inviteToken && inviteUrl && (
          <CardContent>
            <code className="bg-muted block overflow-x-auto rounded px-3 py-2 font-mono text-xs">
              {inviteUrl}
            </code>
            <p className="text-muted-foreground mt-2 text-xs">
              Shown once - save it somewhere safe.
            </p>
          </CardContent>
        )}
      </Card>

      {/* ── Webhooks ─────────────────────────────────────────────────────── */}
      <Card
        className="hover:bg-accent/50 cursor-pointer transition-colors"
        onClick={() => navigate("/dashboard/webhooks")}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Webhook className="h-4 w-4" />
            Webhooks
          </CardTitle>
          <CardDescription>
            Send signed event payloads to your servers when threats are
            detected.
          </CardDescription>
          <CardAction>
            <ArrowRight className="text-muted-foreground h-4 w-4" />
          </CardAction>
        </CardHeader>
      </Card>
    </div>
  );
}

// ─── Webhooks page ────────────────────────────────────────────────────────────

const THREAT_PAYLOAD_EXAMPLE = JSON.stringify(
  {
    event: "threat.detected",
    timestamp: 1714000000,
    data: {
      deviceId: "dev_abc123",
      platform: "mac",
      threats: [
        {
          extensionName: "Dark Reader",
          chromeExtensionId: "eimadpbcbfnmbkopoojfekhnkhdbieeh",
          riskScore: 87,
          flaggedReason:
            "Reads all browsing history and sends it to a remote server",
        },
      ],
    },
  },
  null,
  2,
);

function WebhooksPage() {
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

  const [showForm, setShowForm] = useState(false);
  const [formUrl, setFormUrl] = useState("");
  const [formDesc, setFormDesc] = useState("");
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
        invalidate();
      },
    }),
  );

  async function copySecret(secret: string) {
    await navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-6">
      {/* Back nav */}
      <div>
        <button
          onClick={() => navigate("/dashboard/settings")}
          className="text-muted-foreground hover:text-foreground flex items-center gap-1.5 text-sm transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Settings
        </button>
        <h1 className="mt-3 flex items-center gap-2 text-lg font-semibold">
          <Webhook className="h-5 w-5" />
          Webhooks
        </h1>
      </div>

      {/* New secret Dialog */}
      <Dialog
        open={!!newSecret}
        onOpenChange={(open) => {
          if (!open) setNewSecret(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-emerald-600">
              <CheckCircle className="h-4 w-4" />
              Webhook created - save your secret
            </DialogTitle>
            <DialogDescription>
              This is the only time the full secret will be shown. Copy it now
              and store it securely.
            </DialogDescription>
          </DialogHeader>
          {newSecret && (
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
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" onClick={() => setNewSecret(null)}>
                I've saved it - dismiss
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Endpoints Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Webhook className="h-4 w-4" />
            Endpoints
          </CardTitle>
          <CardDescription>
            Receive signed POST notifications when security events occur in your
            org.
          </CardDescription>
          <CardAction>
            <Dialog
              open={showForm}
              onOpenChange={(open) => {
                setShowForm(open);
                if (!open) {
                  setFormUrl("");
                  setFormDesc("");
                }
              }}
            >
              <DialogTrigger asChild>
                <Button size="sm" variant="outline" className="gap-1.5">
                  <Plus className="h-3.5 w-3.5" />
                  Add webhook
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>New webhook</DialogTitle>
                  <DialogDescription>
                    Add an HTTPS endpoint to receive signed event payloads.
                  </DialogDescription>
                </DialogHeader>
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="wh-url">Endpoint URL</FieldLabel>
                    <Input
                      id="wh-url"
                      placeholder="https://your-server.example.com/webhooks/aibp"
                      value={formUrl}
                      onChange={(e) => setFormUrl(e.target.value)}
                    />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="wh-desc">
                      Description{" "}
                      <span className="text-muted-foreground font-normal">
                        (optional)
                      </span>
                    </FieldLabel>
                    <Input
                      id="wh-desc"
                      placeholder="e.g. Slack alerts"
                      value={formDesc}
                      onChange={(e) => setFormDesc(e.target.value)}
                    />
                  </Field>
                </FieldGroup>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button size="sm" variant="ghost">
                      Cancel
                    </Button>
                  </DialogClose>
                  <Button
                    size="sm"
                    disabled={!formUrl || createMutation.isPending}
                    onClick={() =>
                      createMutation.mutate({
                        url: formUrl,
                        description: formDesc || undefined,
                        events: ["threat.detected"],
                      })
                    }
                  >
                    {createMutation.isPending ? (
                      <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                    ) : null}
                    Create webhook
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </CardAction>
        </CardHeader>
        <CardContent>
          {isPending && (
            <div className="flex items-center justify-center py-10">
              <RefreshCw className="h-5 w-5 animate-spin opacity-30" />
            </div>
          )}
          {!isPending && (!webhooks || webhooks.length === 0) && (
            <div className="text-muted-foreground flex flex-col items-center gap-2 py-10">
              <Webhook className="h-8 w-8 opacity-20" />
              <p className="text-sm">No webhooks configured yet.</p>
              <p className="text-xs">
                Add one to start receiving real-time event notifications.
              </p>
            </div>
          )}
          {webhooks && webhooks.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-[148px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {webhooks.map((wh) => (
                  <TableRow
                    key={wh.id}
                    className={!wh.enabled ? "opacity-50" : ""}
                  >
                    <TableCell>
                      <div className="space-y-0.5">
                        <p className="font-mono text-xs">{wh.url}</p>
                        {wh.description && (
                          <p className="text-muted-foreground text-xs">
                            {wh.description}
                          </p>
                        )}
                        <p className="text-muted-foreground font-mono text-[10px]">
                          {wh.secretMasked}
                        </p>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={wh.enabled ? "default" : "secondary"}>
                        {wh.enabled ? "Active" : "Disabled"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        {/* Test */}
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 gap-1 px-2 text-xs"
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
                            <CheckCircle className="h-3 w-3 text-emerald-500" />
                          ) : (
                            <Zap className="h-3 w-3" />
                          )}
                          Test
                        </Button>
                        {/* Toggle */}
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 px-2 text-xs"
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
                        <Dialog>
                          <DialogTrigger asChild>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="text-muted-foreground hover:text-destructive h-7 w-7 p-0"
                              title="Delete webhook"
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </DialogTrigger>
                          <DialogContent>
                            <DialogHeader>
                              <DialogTitle>Delete webhook?</DialogTitle>
                              <DialogDescription>
                                This will permanently remove{" "}
                                <span className="text-foreground font-mono">
                                  {wh.url}
                                </span>
                                . Any deliveries in flight may still arrive.
                              </DialogDescription>
                            </DialogHeader>
                            <DialogFooter>
                              <DialogClose asChild>
                                <Button variant="outline">Cancel</Button>
                              </DialogClose>
                              <DialogClose asChild>
                                <Button
                                  variant="destructive"
                                  disabled={deleteMutation.isPending}
                                  onClick={() =>
                                    deleteMutation.mutate({ webhookId: wh.id })
                                  }
                                >
                                  {deleteMutation.isPending ? (
                                    <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                                  ) : null}
                                  Delete
                                </Button>
                              </DialogClose>
                            </DialogFooter>
                          </DialogContent>
                        </Dialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Event payloads Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Braces className="h-4 w-4" />
            Event payloads
          </CardTitle>
          <CardDescription>
            Your endpoint receives a POST with this JSON body whenever a flagged
            extension is detected on a device in your org.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="bg-muted overflow-x-auto rounded p-3 font-mono text-[11px] leading-relaxed">
            {THREAT_PAYLOAD_EXAMPLE}
          </pre>
        </CardContent>
      </Card>

      {/* Verifying signatures Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            Verifying signatures
          </CardTitle>
          <CardDescription>
            Every delivery includes an{" "}
            <code className="bg-muted rounded px-1 py-0.5 text-xs">
              X-AIBP-Signature
            </code>{" "}
            header. Verify it with HMAC-SHA256 to confirm the payload came from
            us and wasn't tampered with.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="bg-muted overflow-x-auto rounded p-3 font-mono text-[11px] leading-relaxed">{`// Node.js / Express example
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
        </CardContent>
      </Card>
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
