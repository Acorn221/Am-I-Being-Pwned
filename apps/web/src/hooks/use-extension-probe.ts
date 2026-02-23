import { useEffect, useState } from "react";

export interface DetectedExtension {
  id: string;
  name: string;
  risk: string;
  version: string | null;
  summary: string;
  flags: string[];
}

interface ProbeResultsMessage {
  type: "PROBE_RESULTS";
  detected: DetectedExtension[];
  checkedCount: number;
}

function isProbeResults(data: unknown): data is ProbeResultsMessage {
  return (
    typeof data === "object" &&
    data !== null &&
    (data as Record<string, unknown>).type === "PROBE_RESULTS"
  );
}

export function useExtensionProbe(): {
  detected: DetectedExtension[];
  probing: boolean;
  checkedCount: number;
} {
  const [detected, setDetected] = useState<DetectedExtension[]>([]);
  const [checkedCount, setCheckedCount] = useState<number>(0);
  // Only start as probing if service workers are available
  const [probing, setProbing] = useState(() => "serviceWorker" in navigator);

  useEffect(() => {
    if (!("serviceWorker" in navigator)) return;

    let cancelled = false;

    const handler = (event: MessageEvent<unknown>) => {
      if (isProbeResults(event.data) && !cancelled) {
        setDetected(event.data.detected);
        setCheckedCount(event.data.checkedCount);
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

  return { detected, probing, checkedCount };
}
