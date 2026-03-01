import { useSyncExternalStore } from "react";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FleetOverview {
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

export type Tab =
  | "overview"
  | "alerts"
  | "devices"
  | "extensions"
  | "settings"
  | "webhooks";

// ─── Helpers ─────────────────────────────────────────────────────────────────

export const SEVERITY: Record<string, { bar: string; badge: string; text: string }> = {
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
export const SEVERITY_MEDIUM = {
  bar: "bg-yellow-500",
  badge: "bg-yellow-500/15 text-yellow-600 border-yellow-500/30",
  text: "text-yellow-600",
};
export function sev(s: string) {
  return SEVERITY[s] ?? SEVERITY_MEDIUM;
}

export function timeAgo(date: Date): string {
  const s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ─── Tab routing helpers ──────────────────────────────────────────────────────

export const VALID_TABS = new Set<Tab>([
  "overview",
  "alerts",
  "devices",
  "extensions",
  "settings",
  "webhooks",
]);

export function getTab(): Tab {
  const segment = window.location.pathname.split("/")[2];
  return VALID_TABS.has(segment as Tab) ? (segment as Tab) : "overview";
}

export function subscribeToLocation(cb: () => void) {
  window.addEventListener("popstate", cb);
  return () => window.removeEventListener("popstate", cb);
}

export function useTab(): [Tab, (t: Tab) => void] {
  const tab = useSyncExternalStore(subscribeToLocation, getTab);
  function setTab(t: Tab) {
    window.history.pushState(null, "", `/dashboard/${t}`);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }
  return [tab, setTab];
}
