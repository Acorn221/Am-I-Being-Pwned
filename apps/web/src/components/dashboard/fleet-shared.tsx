// ─── Shared sub-components ────────────────────────────────────────────────────

export function RiskScore({ score }: { score: number }) {
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
