import { useMemo } from "react";

import { Badge } from "@amibeingpwned/ui/badge";

import type { ReportMap } from "~/hooks/use-extension-database";
import { formatUsers, riskConfig, riskOrder } from "~/lib/risk";

interface ExtensionPreviewCardsProps {
  reports: ReportMap;
}

const CARD_COUNT = 4;

const cardTransforms = [
  { rotate: -6, x: -12, y: 8, z: 0 },
  { rotate: -2, x: -4, y: 4, z: 1 },
  { rotate: 2, x: 4, y: -2, z: 2 },
  { rotate: 5, x: 10, y: -8, z: 3 },
];

export function ExtensionPreviewCards({ reports }: ExtensionPreviewCardsProps) {
  const selected = useMemo(() => {
    const entries = [...reports.values()];
    if (entries.length === 0) return [];

    // Sort by risk (worst first), then pick a diverse set
    const sorted = entries
      .filter((e) => e.risk !== "unavailable")
      .sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);

    const picks: typeof sorted = [];
    const usedRisks = new Set<string>();

    // First pass: pick one per risk tier (critical/high, medium, low, clean)
    const tiers = [
      ["critical", "high"],
      ["medium-high", "medium"],
      ["medium-low", "low"],
      ["clean"],
    ];

    for (const tier of tiers) {
      if (picks.length >= CARD_COUNT) break;
      const candidate = sorted.find(
        (e) => tier.includes(e.risk) && !usedRisks.has(e.extensionId),
      );
      if (candidate) {
        picks.push(candidate);
        usedRisks.add(candidate.extensionId);
      }
    }

    // Fill remaining slots
    for (const entry of sorted) {
      if (picks.length >= CARD_COUNT) break;
      if (!usedRisks.has(entry.extensionId)) {
        picks.push(entry);
        usedRisks.add(entry.extensionId);
      }
    }

    return picks;
  }, [reports]);

  if (selected.length === 0) return null;

  return (
    <div className="relative flex h-full items-center justify-center py-12">
      <div className="relative h-[280px] w-[300px]">
        {selected.map((ext, i) => {
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          const t = (cardTransforms[i] ?? cardTransforms[0])!;
          const risk = riskConfig[ext.risk];
          const perms = ext.permissions.slice(0, 5);

          return (
            <div
              key={ext.extensionId}
              className="border-border bg-card absolute inset-0 rounded-xl border p-5 shadow-lg transition-transform duration-300 hover:scale-105"
              style={{
                transform: `rotate(${t.rotate}deg) translate(${t.x}px, ${t.y}px)`,
                zIndex: t.z,
              }}
            >
              <div className="mb-3 flex items-start justify-between gap-2">
                <h3 className="text-card-foreground line-clamp-2 text-sm font-semibold leading-tight">
                  {ext.name}
                </h3>
                <Badge variant={risk.variant} className="shrink-0 text-[10px]">
                  {risk.label}
                </Badge>
              </div>

              <p className="text-muted-foreground mb-3 text-xs">
                {formatUsers(ext.userCount)} users
              </p>

              {perms.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {perms.map((p) => (
                    <span
                      key={p}
                      className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 font-mono text-[10px]"
                    >
                      {p}
                    </span>
                  ))}
                  {ext.permissions.length > 5 && (
                    <span className="text-muted-foreground px-1 py-0.5 text-[10px]">
                      +{ext.permissions.length - 5} more
                    </span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
