import { useState } from "react";

import type { ExtensionReport } from "@amibeingpwned/types";

export type ReportMap = Map<string, ExtensionReport>;

export function useExtensionDatabase() {
  const [reports] = useState<ReportMap>(new Map());
  // TODO: re-enable when database is ready to ship
  // const [loading, setLoading] = useState(true);
  // useEffect(() => {
  //   let cancelled = false;
  //   async function load() {
  //     try {
  //       const res = await fetch("/extensions.json");
  //       const data = (await res.json()) as ExtensionDatabase;
  //       if (!cancelled) {
  //         const decode = (s: string) => s.replaceAll("&amp;", "&").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&#39;", "'").replaceAll("&quot;", '"');
  //         const entries = Object.entries(data).map(
  //           ([id, ext]) =>
  //             [id, { ...ext, risk: (ext.risk || "unavailable").toLowerCase() as RiskLevel, name: decode(ext.name ?? ""), summary: decode(ext.summary ?? ""), userCount: Number(ext.userCount) || 0 }] as const,
  //         );
  //         setReports(new Map(entries));
  //       }
  //     } catch {
  //       // Static file - if it fails the site is down anyway
  //     } finally {
  //       if (!cancelled) setLoading(false);
  //     }
  //   }
  //   void load();
  //   return () => { cancelled = true; };
  // }, []);
  const loading = false;

  return { reports, loading } as const;
}
