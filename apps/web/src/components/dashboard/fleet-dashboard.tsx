import { Building2, LogOut } from "lucide-react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";

import { authClient } from "~/lib/auth-client";
import { navigate } from "~/router";

import { useTab } from "./fleet-types";
import type { FleetOverview, Tab } from "./fleet-types";
import { OverviewTab } from "./fleet-overview-tab";
import { AlertsTab } from "./fleet-alerts-tab";
import { DevicesTab } from "./fleet-devices-tab";
import { ExtensionsTab } from "./fleet-extensions-tab";
import { PolicyTab } from "./fleet-policy-tab";
import { SettingsTab } from "./fleet-settings-tab";
import { WebhooksPage } from "./fleet-webhooks-page";

// Root component

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
    { id: "policy", label: "Policy" },
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
        {tab === "policy" && <PolicyTab />}
        {tab === "settings" && <SettingsTab orgId={overview.org.id} />}
        {tab === "webhooks" && <WebhooksPage />}
      </div>
    </div>
  );
}
