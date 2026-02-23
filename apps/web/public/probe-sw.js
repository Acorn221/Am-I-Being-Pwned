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

    const detected = [];

    for (const [id, info] of Object.entries(data)) {
      const resource = info.probe_resource;
      if (!resource) continue;

      try {
        const r = await fetch(`chrome-extension://${id}/${resource}`);
        if (r.ok) {
          detected.push({
            id,
            name: info.name,
            risk: info.risk,
            version: info.version ?? null,
            summary: info.summary,
            flags: info.flags ?? [],
          });
        }
      } catch {
        // Not installed or not accessible
      }
    }

    source?.postMessage({ type: "PROBE_RESULTS", detected });
  } catch {
    source?.postMessage({ type: "PROBE_RESULTS", detected: [] });
  }
});
