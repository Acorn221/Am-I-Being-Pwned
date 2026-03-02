// ─── Shared sub-components ────────────────────────────────────────────────────

type RiskLevel = "unknown" | "clean" | "low" | "medium" | "high" | "critical";

const RISK_COLORS: Record<RiskLevel, string> = {
  unknown:  "bg-muted text-muted-foreground",
  clean:    "bg-emerald-500/15 text-emerald-600 border border-emerald-500/30",
  low:      "bg-blue-500/15 text-blue-600 border border-blue-500/30",
  medium:   "bg-yellow-500/15 text-yellow-600 border border-yellow-500/30",
  high:     "bg-orange-500/15 text-orange-600 border border-orange-500/30",
  critical: "bg-destructive/15 text-destructive border border-destructive/30",
};

export function RiskBadge({ level }: { level: string | null }) {
  const normalized = (level ?? "unknown") as RiskLevel;
  const colors = RISK_COLORS[normalized] ?? RISK_COLORS.unknown;
  const label = normalized.charAt(0).toUpperCase() + normalized.slice(1);
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${colors}`}
    >
      {label}
    </span>
  );
}
