import { useEffect, useMemo, useRef, useState } from "react";

import type { ExtensionReport } from "@amibeingpwned/types";
import { Badge } from "@amibeingpwned/ui/badge";

import { CircuitTraces } from "~/components/circuit-traces";
import { useHeroCycle } from "~/components/hero-cycle-context";
import { HERO_SLIDES } from "~/components/hero-slides";
import type { ReportMap } from "~/hooks/use-extension-database";
import { formatUsers, riskConfig } from "~/lib/risk";

interface ExtensionPreviewCardsProps {
  reports: ReportMap;
}

const VISIBLE_COUNT = 4;
const EXIT_DURATION = 600;

const cardTransforms = [
  { rotate: -6, x: -12, y: 8 },
  { rotate: -2, x: -4, y: 4 },
  { rotate: 2, x: 4, y: -2 },
  { rotate: 5, x: 10, y: -8 },
];

/** Permissions that enable common abuse patterns */
const SENSITIVE_PERMS = new Set([
  "cookies",
  "webRequest",
  "webRequestBlocking",
  "declarativeNetRequest",
  "tabs",
  "history",
  "bookmarks",
  "clipboardRead",
  "clipboardWrite",
  "management",
  "proxy",
  "debugger",
  "nativeMessaging",
  "privacy",
  "topSites",
  "browsingData",
]);

function isSensitivePerm(perm: string): boolean {
  if (SENSITIVE_PERMS.has(perm)) return true;
  if (
    perm === "<all_urls>" ||
    perm === "*://*/*" ||
    perm === "http://*/*" ||
    perm === "https://*/*"
  )
    return true;
  return false;
}

const isRisky = (risk: string) =>
  risk === "critical" ||
  risk === "high" ||
  risk === "medium-high" ||
  risk === "medium";

function CardContent({
  ext,
  highlight,
  isFront,
}: {
  ext: ExtensionReport;
  highlight?: boolean;
  isFront?: boolean;
}) {
  const risk = riskConfig[ext.risk];
  const allPerms = [...ext.permissions, ...ext.hostPermissions];

  const sorted = [...allPerms].sort((a, b) => {
    const aS = isSensitivePerm(a) ? 0 : 1;
    const bS = isSensitivePerm(b) ? 0 : 1;
    return aS - bS;
  });
  const shown = sorted.slice(0, 6);
  const extIsRisky = isRisky(ext.risk);

  return (
    <>
      <div className="mb-4 flex items-start justify-between gap-3">
        <h3 data-trace-obstacle className="text-card-foreground line-clamp-2 text-base font-semibold leading-snug">
          {ext.name}
        </h3>
        <Badge data-trace-obstacle variant={risk.variant} className="shrink-0 text-xs">
          {risk.label}
        </Badge>
      </div>

      <p data-trace-obstacle className="text-muted-foreground mb-4 text-sm">
        {formatUsers(ext.userCount)} users
      </p>

      {shown.length > 0 && (
        <div>
          <p data-trace-obstacle className="text-muted-foreground mb-2 text-xs font-medium uppercase tracking-wide">
            Permissions
          </p>
          <div className="flex flex-wrap gap-1.5">
            {shown.map((p) => {
              const dangerous = extIsRisky && isSensitivePerm(p);
              return (
                <span
                  key={p}
                  data-perm={isFront ? p : undefined}
                  className={`rounded-md px-2 py-1 font-mono text-xs transition-all duration-700 ${
                    dangerous && highlight
                      ? "bg-red-500/15 text-red-400 ring-1 ring-red-500/30"
                      : "bg-muted text-muted-foreground"
                  }`}
                >
                  {p}
                </span>
              );
            })}
            {allPerms.length > 6 && (
              <span data-trace-obstacle className="text-muted-foreground px-1.5 py-1 text-xs">
                +{allPerms.length - 6} more
              </span>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export function ExtensionPreviewCards({ reports }: ExtensionPreviewCardsProps) {
  const { slideIndex } = useHeroCycle();

  // Build the visible window: current front card + 3 behind it (wrapping)
  const visible = useMemo(() => {
    const count = Math.min(VISIBLE_COUNT, HERO_SLIDES.length);
    const cards: { ext: ExtensionReport; slot: number }[] = [];

    for (let i = 0; i < count; i++) {
      const idx =
        (slideIndex - (count - 1) + i + HERO_SLIDES.length) %
        HERO_SLIDES.length;
      const slide = HERO_SLIDES[idx];
      if (!slide) continue;
      const ext = reports.get(slide.extensionId);
      if (!ext) continue;
      cards.push({ ext, slot: i });
    }

    return cards;
  }, [slideIndex, reports]);

  // Track leaving card
  const [leaving, setLeaving] = useState<ExtensionReport | null>(null);
  const prevSlideRef = useRef(slideIndex);

  useEffect(() => {
    if (prevSlideRef.current === slideIndex) return;

    // The old front card is the one that was at the top
    const oldFrontIdx =
      (prevSlideRef.current + HERO_SLIDES.length) % HERO_SLIDES.length;
    const oldSlide = HERO_SLIDES[oldFrontIdx];
    if (oldSlide) {
      const ext = reports.get(oldSlide.extensionId);
      if (ext) {
        setLeaving(ext);
        setTimeout(() => setLeaving(null), EXIT_DURATION);
      }
    }

    prevSlideRef.current = slideIndex;
  }, [slideIndex, reports]);

  // Delayed highlight for the front card
  const [highlighted, setHighlighted] = useState(false);
  useEffect(() => {
    setHighlighted(false);
    const id = setTimeout(() => setHighlighted(true), 800);
    return () => clearTimeout(id);
  }, [slideIndex]);

  // Get the current slide's annotations
  const currentSlide = HERO_SLIDES[slideIndex % HERO_SLIDES.length];
  const annotations = currentSlide?.annotations ?? [];

  const containerRef = useRef<HTMLDivElement>(null);

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
      <div ref={containerRef} className="relative h-[440px] w-[480px]">
        {visible.map(({ ext, slot }) => {
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          const t = (cardTransforms[slot] ?? cardTransforms[0])!;
          const isFront =
            slot === VISIBLE_COUNT - 1 || slot === visible.length - 1;
          return (
            <div
              key={ext.extensionId}
              data-card-front={isFront || undefined}
              className="border-border bg-card absolute inset-x-[70px] top-[30px] h-[380px] rounded-xl border p-6 shadow-lg transition-all duration-500 ease-out"
              style={{
                transform: `rotate(${t.rotate}deg) translate(${t.x}px, ${t.y}px)`,
                zIndex: slot,
              }}
            >
              <CardContent ext={ext} highlight={isFront && highlighted} isFront={isFront} />
            </div>
          );
        })}
        {leaving && (
          <div
            key={`leaving-${leaving.extensionId}`}
            className="border-border bg-card absolute inset-x-[70px] top-[30px] h-[380px] rounded-xl border p-6 shadow-lg"
            style={{
              zIndex: VISIBLE_COUNT + 1,
              animation: `card-exit ${EXIT_DURATION}ms ease-in forwards`,
            }}
          >
            <CardContent ext={leaving} highlight />
          </div>
        )}
        {annotations.length > 0 && (
          <CircuitTraces
            annotations={annotations}
            highlighted={highlighted}
            containerRef={containerRef}
          />
        )}
      </div>
    </div>
  );
}
