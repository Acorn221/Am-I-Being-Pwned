import { useEffect, useState } from "react";

import type { ExtensionReport } from "@amibeingpwned/types";

export type ReportMap = Map<string, ExtensionReport>;

export function useExtensionDatabase() {
  const [reports, setReports] = useState<ReportMap>(new Map());
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch("/extensions/index.json");
        const ids = await res.json() as string[];
        const entries = await Promise.all(
          ids.map(async (id) => {
            const r = await fetch(`/extensions/${id}.json`);
            const data = await r.json() as ExtensionReport;
            return [id, data] as const;
          }),
        );
        if (!cancelled) {
          setReports(new Map(entries));
        }
      } catch {
        // Static files — if they fail the site is down anyway
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  return { reports, loading } as const;
}
