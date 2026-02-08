export default defineContentScript({
  matches: [
    "https://amibeingpwned.com/*",
    "http://localhost/*",
  ],
  runAt: "document_start",
  main() {
    window.postMessage(
      {
        channel: "AIBP_BRIDGE",
        type: "AIBP_EXTENSION_READY",
        extensionId: chrome.runtime.id,
      },
      "*",
    );
  },
});
