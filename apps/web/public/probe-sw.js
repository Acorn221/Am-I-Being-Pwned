self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) =>
  event.waitUntil(self.clients.claim()),
);

self.addEventListener("message", async (event) => {
  if (event.data?.type !== "PROBE_EXTENSIONS") return;

  const source = event.source;

  try {
    const res = await fetch("/extension_probes.json");
    const data = await res.json();

    const entries = Object.entries(data).filter(([, info]) => info.probe_resource);
    const checkedCount = entries.length;

    const results = await Promise.allSettled(
      entries.map(async ([id, info]) => {
        const r = await fetch(`chrome-extension://${id}/${info.probe_resource}`);
        if (!r.ok) return null;
        return {
          id,
          name: info.name,
          risk: info.risk,
          version: info.version ?? null,
          summary: info.summary,
          flags: info.flags ?? [],
        };
      }),
    );

    const detected = results
      .filter((r) => r.status === "fulfilled" && r.value !== null)
      .map((r) => r.value);

    source?.postMessage({ type: "PROBE_RESULTS", detected, checkedCount });
  } catch {
    source?.postMessage({ type: "PROBE_RESULTS", detected: [], checkedCount: 0 });
  }
});
