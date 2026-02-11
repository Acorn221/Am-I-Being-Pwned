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
    window.postMessage(message, location.origin);
  },
});
