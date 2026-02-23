import { useEffect, useState } from "react";

export interface DetectedExtension {
  id: string;
  name: string;
  risk: string;
  summary: string;
  flags: string[];
}

type SWMessage =
  | { type: "PROBE_RESULTS"; detected: DetectedExtension[] }
  | { type: string };

export function useExtensionProbe() {
  const [detected, setDetected] = useState<DetectedExtension[]>([]);
  // Only start as probing if service workers are available
  const [probing, setProbing] = useState(() => "serviceWorker" in navigator);

  useEffect(() => {
    if (!("serviceWorker" in navigator)) return;

    let cancelled = false;

    const handler = (event: MessageEvent<SWMessage>) => {
      const { data } = event;
      if (data.type === "PROBE_RESULTS" && "detected" in data && !cancelled) {
        setDetected(data.detected);
        setProbing(false);
      }
    };

    navigator.serviceWorker.addEventListener("message", handler);

    navigator.serviceWorker
      .register("/probe-sw.js")
      .then(() => navigator.serviceWorker.ready)
      .then((registration) => {
        registration.active?.postMessage({ type: "PROBE_EXTENSIONS" });
      })
      .catch(() => {
        if (!cancelled) setProbing(false);
      });

    return () => {
      cancelled = true;
      navigator.serviceWorker.removeEventListener("message", handler);
    };
  }, []);

  return { detected, probing };
}
