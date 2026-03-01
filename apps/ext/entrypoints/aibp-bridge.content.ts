import type { BridgeReadyMessage } from "@amibeingpwned/types";
import { DEV_ORIGINS, PROD_ORIGINS } from "../lib/allowed-origins";

const origins = import.meta.env.DEV ? DEV_ORIGINS : PROD_ORIGINS;
// Chrome content script match patterns don't support ports - skip origins that specify one
const matches = origins
  .filter((o) => !new URL(o).port)
  .map((o) => `${o}/*`);

export default defineContentScript({
  matches,
  runAt: "document_start",
  main() {
    const message: BridgeReadyMessage = {
      channel: "AIBP_BRIDGE",
      type: "AIBP_EXTENSION_READY",
      extensionId: chrome.runtime.id,
    };

    // Broadcast immediately (may be missed if page JS hasn't mounted yet)
    window.postMessage(message, location.origin);

    // Also respond to on-demand requests so the page can ask after mount
    window.addEventListener("message", (event) => {
      if (event.source !== window) return;
      const data = event.data as Record<string, unknown> | null;
      if (
        data?.channel === "AIBP_BRIDGE" &&
        data.type === "AIBP_REQUEST_ID"
      ) {
        window.postMessage(message, location.origin);
      }
    });
  },
});
