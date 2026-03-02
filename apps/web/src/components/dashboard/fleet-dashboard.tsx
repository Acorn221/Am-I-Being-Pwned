import { Building2, ChevronDown, LogOut, Shield } from "lucide-react";

import { Badge } from "@amibeingpwned/ui/badge";
import { Button } from "@amibeingpwned/ui/button";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { authClient } from "~/lib/auth-client";
import { getImpersonateOrgId, setImpersonateOrgId, useTRPC } from "~/lib/trpc";
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

// ---------------------------------------------------------------------------
// Admin org switcher - only shown when session role is "admin"
// ---------------------------------------------------------------------------

function AdminOrgSwitcher({ currentOrgName }: { currentOrgName: string }) {
  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);

  const { data } = useQuery(
    trpc.admin.orgs.list.queryOptions({ limit: 100 }),
  );

  function switchOrg(id: string) {
    setImpersonateOrgId(id);
    setOpen(false);
    void queryClient.invalidateQueries();
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="border-border bg-muted/50 hover:bg-muted flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors"
      >
        <Shield className="text-primary h-3.5 w-3.5" />
        <span className="text-foreground">{currentOrgName}</span>
        <ChevronDown className="text-muted-foreground h-3 w-3" />
      </button>
      {open && (
        <div className="border-border bg-popover absolute right-0 top-full z-50 mt-1 max-h-64 w-56 overflow-y-auto rounded-md border shadow-md">
          {data?.rows.map((org) => (
            <button
              key={org.id}
              onClick={() => switchOrg(org.id)}
              className={`flex w-full items-center justify-between px-3 py-2 text-left text-xs transition-colors ${
                getImpersonateOrgId() === org.id
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-foreground hover:bg-muted"
              }`}
            >
              <span className="truncate">{org.name}</span>
              {getImpersonateOrgId() === org.id && (
                <span className="text-primary ml-2 shrink-0">&#10003;</span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root component
// ---------------------------------------------------------------------------

export function FleetDashboard({ overview }: { overview: FleetOverview }) {
  const [tab, setTab] = useTab();
  const { data: session } = authClient.useSession();
  const isAdmin = session?.user.role === "admin";

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
          {isAdmin ? (
            <AdminOrgSwitcher currentOrgName={overview.org.name} />
          ) : (
            <div className="text-muted-foreground flex items-center gap-1.5 text-sm">
              <Building2 className="h-4 w-4" />
              <span>{overview.org.name}</span>
              <Badge variant="outline" className="ml-1 text-xs capitalize">
                {overview.org.plan}
              </Badge>
            </div>
          )}
          {isAdmin && (
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => navigate("/admin")}
            >
              <Shield className="h-3.5 w-3.5" />
              Admin
            </Button>
          )}
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
