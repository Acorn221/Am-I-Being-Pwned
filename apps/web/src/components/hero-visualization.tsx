"use no memo";

import { Suspense, lazy, useMemo } from "react";

import type { ReportMap } from "~/hooks/use-extension-database";
import { useExtension } from "~/hooks/use-extension";

import { demoPieces } from "./hero-visualization/demo-pieces";

const PuzzleScene = lazy(() =>
  import("./hero-visualization/puzzle-scene").then((m) => ({
    default: m.PuzzleScene,
  })),
);

interface HeroVisualizationProps {
  reports: ReportMap;
}

export function HeroVisualization({ reports }: HeroVisualizationProps) {
  const { status, extensions } = useExtension();

  const reducedMotion =
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const pieces = useMemo(() => {
    // Use real data if extension is connected and we have extensions
    if (status === "connected" && extensions && extensions.length > 0) {
      return extensions.map((ext) => {
        const report = reports.get(ext.id);
        return {
          id: ext.id,
          name: ext.name,
          risk: (report?.risk ?? "unavailable"),
        };
      });
    }

    // Fallback to demo data
    return demoPieces.map((d) => ({
      id: d.extension.id,
      name: d.extension.name,
      risk: d.risk,
    }));
  }, [status, extensions, reports]);

  return (
    <div className="h-full w-full" style={{ minHeight: 400 }}>
      <Suspense
        fallback={
          <div className="flex h-full items-center justify-center">
            <div className="border-muted-foreground h-8 w-8 animate-spin rounded-full border-2 border-t-transparent" />
          </div>
        }
      >
        <PuzzleScene pieces={pieces} reducedMotion={reducedMotion} />
      </Suspense>
    </div>
  );
}
