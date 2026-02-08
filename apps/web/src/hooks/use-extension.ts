import { useCallback, useEffect, useRef, useState } from "react";

import type { InstalledExtensionInfo } from "@amibeingpwned/types";

import { detectExtension, sendToExtension } from "~/lib/extension-client";

export type ExtensionStatus = "detecting" | "connected" | "not_installed";

export function useExtension() {
  const [status, setStatus] = useState<ExtensionStatus>("detecting");
  const [extensions, setExtensions] = useState<InstalledExtensionInfo[] | null>(
    null,
  );
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const extensionIdRef = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    detectExtension().then((id) => {
      if (cancelled) return;
      if (id) {
        extensionIdRef.current = id;
        setStatus("connected");
      } else {
        setStatus("not_installed");
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const scan = useCallback(async () => {
    const id = extensionIdRef.current;
    if (!id) return;

    setScanning(true);
    setError(null);

    try {
      const response = await sendToExtension(id, {
        type: "GET_EXTENSIONS",
        version: 1,
      });

      if (response.type === "EXTENSIONS_RESULT") {
        setExtensions(response.extensions);
      } else if (response.type === "ERROR") {
        setError(response.message);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  }, []);

  return { status, extensions, scan, scanning, error } as const;
}
