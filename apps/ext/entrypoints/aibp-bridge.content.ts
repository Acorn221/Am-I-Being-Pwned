import type { BridgeReadyMessage } from "@amibeingpwned/types";

export default defineContentScript({
  matches: [
    "https://amibeingpwned.com/*",
    ...(import.meta.env.DEV ? ["http://localhost/*"] : []),
  ],
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
