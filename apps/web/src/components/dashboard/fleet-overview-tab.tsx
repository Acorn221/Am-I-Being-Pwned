import type React from "react";
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
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  Bell,
  Monitor,
  Puzzle,
  ShieldCheck,
} from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@amibeingpwned/ui/card";

import { useTRPC } from "~/lib/trpc";
import { sev, timeAgo } from "./fleet-types";
import type { FleetOverview, Tab } from "./fleet-types";

export function OverviewTab({
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
