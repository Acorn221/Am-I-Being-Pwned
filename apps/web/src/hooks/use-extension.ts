import { useCallback, useEffect, useState } from "react";

import type { InstalledExtensionInfo } from "@amibeingpwned/types";

import { extensionClient } from "~/lib/extension-client";

export type ExtensionStatus = "detecting" | "connected" | "not_installed";

export function useExtension() {
  const [status, setStatus] = useState<ExtensionStatus>("detecting");
  const [extensions, setExtensions] = useState<InstalledExtensionInfo[] | null>(
    null,
  );
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scan = useCallback(async () => {
    if (!extensionClient.id) return;

    setScanning(true);
    setError(null);

    try {
      const response = await extensionClient.send({
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

  useEffect(() => {
    let cancelled = false;
    void extensionClient.detect().then((id) => {
      if (cancelled) return;
      if (id) {
        setStatus("connected");
        void scan();
      } else {
        setStatus("not_installed");
      }
    });
    return () => {
      cancelled = true;
    };
  }, [scan]);

  return { status, extensions, scan, scanning, error } as const;
}
