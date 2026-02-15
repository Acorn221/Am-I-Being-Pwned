import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { ExtensionReport } from "@amibeingpwned/types";
import { Badge } from "@amibeingpwned/ui/badge";

import { useHeroCycle } from "~/components/hero-cycle-context";
import type { ReportMap } from "~/hooks/use-extension-database";
import { formatUsers, riskConfig, riskOrder } from "~/lib/risk";

interface ExtensionPreviewCardsProps {
  reports: ReportMap;
}

const VISIBLE_COUNT = 4;
const CYCLE_INTERVAL = 4000;
const EXIT_DURATION = 600;

const cardTransforms = [
  { rotate: -6, x: -12, y: 8 },
  { rotate: -2, x: -4, y: 4 },
  { rotate: 2, x: 4, y: -2 },
  { rotate: 5, x: 10, y: -8 },
];

function CardContent({ ext }: { ext: ExtensionReport }) {
  const risk = riskConfig[ext.risk];
  const allPerms = [...ext.permissions, ...ext.hostPermissions];

  return (
    <>
      <div className="mb-4 flex items-start justify-between gap-3">
        <h3 className="text-card-foreground line-clamp-2 text-base font-semibold leading-snug">
          {ext.name}
        </h3>
        <Badge variant={risk.variant} className="shrink-0 text-xs">
          {risk.label}
        </Badge>
      </div>

      <p className="text-muted-foreground mb-4 text-sm">
        {formatUsers(ext.userCount)} users
      </p>

      {allPerms.length > 0 && (
        <div>
          <p className="text-muted-foreground mb-2 text-xs font-medium uppercase tracking-wide">
            Permissions
          </p>
          <div className="flex flex-wrap gap-1.5">
            {allPerms.slice(0, 8).map((p) => (
              <span
                key={p}
                className="bg-muted text-muted-foreground rounded-md px-2 py-1 font-mono text-xs"
              >
                {p}
              </span>
            ))}
            {allPerms.length > 8 && (
              <span className="text-muted-foreground px-1.5 py-1 text-xs">
                +{allPerms.length - 8} more
              </span>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export function ExtensionPreviewCards({ reports }: ExtensionPreviewCardsProps) {
  const pool = useMemo(() => {
    const entries = [...reports.values()];
    if (entries.length === 0) return [];

    const sorted = entries
      .filter((e) => e.risk !== "unavailable")
      .sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);

    const picks: typeof sorted = [];
    const used = new Set<string>();

    const tiers = [
      ["critical", "high"],
      ["medium-high", "medium"],
      ["medium-low", "low"],
      ["clean"],
    ];

    for (const tier of tiers) {
      const candidate = sorted.find(
        (e) => tier.includes(e.risk) && !used.has(e.extensionId),
      );
      if (candidate) {
        picks.push(candidate);
        used.add(candidate.extensionId);
      }
    }

    for (const entry of sorted) {
      if (picks.length >= 10) break;
      if (!used.has(entry.extensionId)) {
        picks.push(entry);
        used.add(entry.extensionId);
      }
    }

    return picks;
  }, [reports]);

  const { paused } = useHeroCycle();
  const [offset, setOffset] = useState(0);
  const [leaving, setLeaving] = useState<{
    ext: ExtensionReport;
    fromTransform: string;
  } | null>(null);
  const leavingSlot = useRef(VISIBLE_COUNT - 1);

  const cycle = useCallback(() => {
    if (pool.length <= VISIBLE_COUNT) return;

    const frontIdx = (offset + VISIBLE_COUNT - 1) % pool.length;
    const frontExt = pool[frontIdx]!;
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const ft = (cardTransforms[VISIBLE_COUNT - 1] ?? cardTransforms[0])!;

    setLeaving({
      ext: frontExt,
      fromTransform: `rotate(${ft.rotate}deg) translate(${ft.x}px, ${ft.y}px)`,
    });
    leavingSlot.current = VISIBLE_COUNT - 1;

    setOffset((o) => (o + 1) % pool.length);

    setTimeout(() => setLeaving(null), EXIT_DURATION);
  }, [pool, offset]);

  useEffect(() => {
    if (pool.length <= VISIBLE_COUNT || paused) return;
    const id = setInterval(cycle, CYCLE_INTERVAL);
    return () => clearInterval(id);
  }, [pool.length, cycle, paused]);

  const visible = useMemo(() => {
    if (pool.length === 0) return [];
    const count = Math.min(VISIBLE_COUNT, pool.length);
    return Array.from({ length: count }, (_, i) => ({
      ext: pool[(offset + i) % pool.length]!,
      slot: i,
    }));
  }, [pool, offset]);

  if (visible.length === 0) return null;

  return (
    <div className="relative flex h-full items-center justify-center py-12">
      <style>{`
        @keyframes card-exit {
          0% {
            opacity: 1;
          }
          40% {
            opacity: 0;
          }
          100% {
            opacity: 0;
            transform: translateX(-140%) rotate(-12deg) scale(0.95);
          }
        }
      `}</style>
      <div className="relative h-[380px] w-[340px]">
        {visible.map(({ ext, slot }) => {
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          const t = (cardTransforms[slot] ?? cardTransforms[0])!;
          return (
            <div
              key={ext.extensionId}
              className="border-border bg-card absolute inset-0 rounded-xl border p-6 shadow-lg transition-all duration-500 ease-out"
              style={{
                transform: `rotate(${t.rotate}deg) translate(${t.x}px, ${t.y}px)`,
                zIndex: slot,
              }}
            >
              <CardContent ext={ext} />
            </div>
          );
        })}
        {leaving && (
          <div
            key={`leaving-${leaving.ext.extensionId}`}
            className="border-border bg-card absolute inset-0 rounded-xl border p-6 shadow-lg"
            style={{
              zIndex: VISIBLE_COUNT + 1,
              animation: `card-exit ${EXIT_DURATION}ms ease-in forwards`,
            }}
          >
            <CardContent ext={leaving.ext} />
          </div>
        )}
      </div>
    </div>
  );
}
