import type { RiskLevel } from "@amibeingpwned/types";

export const riskConfig: Record<
  RiskLevel,
  { label: string; variant: "destructive" | "warning" | "caution" | "outline" | "secondary" }
> = {
  critical: { label: "Critical", variant: "destructive" },
  high: { label: "High", variant: "warning" },
  "medium-high": { label: "Med-High", variant: "warning" },
  medium: { label: "Medium", variant: "caution" },
  "medium-low": { label: "Med-Low", variant: "outline" },
  low: { label: "Low", variant: "outline" },
  clean: { label: "Clean", variant: "secondary" },
  unavailable: { label: "N/A", variant: "secondary" },
};

export const riskOrder: Record<RiskLevel, number> = {
  critical: 0,
  high: 1,
  "medium-high": 2,
  medium: 3,
  "medium-low": 4,
  low: 5,
  clean: 6,
  unavailable: 7,
};

// Probe scan risk constants (uppercase strings from service worker)
export const PROBE_RISK_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

export const PROBE_RISK_DOT: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-yellow-500",
};

const PROBE_RISK_PRIORITY = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function probeRiskRank(risk: string): number {
  const i = PROBE_RISK_PRIORITY.indexOf(risk);
  return i === -1 ? 99 : i;
}

export function formatUsers(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M+`;
  if (count >= 1_000) return `${Math.round(count / 1_000)}k+`;
  if (count === 0) return "N/A";
  return `${count}`;
}
