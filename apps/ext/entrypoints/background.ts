import type { ExtResponse, InstalledExtensionInfo } from "@acme/types";
import { ExtRequestSchema } from "@acme/validators";

const WEB_URL = import.meta.env.DEV
  ? "http://localhost:3000"
  : "https://amibeingpwned.com";

const ALLOWED_ORIGINS = import.meta.env.DEV
  ? ["https://amibeingpwned.com", "http://localhost:3000"]
  : ["https://amibeingpwned.com"];

// ---------------------------------------------------------------------------
// Rate limiter — sliding window, 10 requests per 60 seconds per origin
// ---------------------------------------------------------------------------
const RATE_LIMIT = 10;
const RATE_WINDOW_MS = 60_000;
const requestLog = new Map<string, number[]>();

function isRateLimited(origin: string): boolean {
  const now = Date.now();
  const timestamps = requestLog.get(origin) ?? [];
  const recent = timestamps.filter((t) => now - t < RATE_WINDOW_MS);
  if (recent.length >= RATE_LIMIT) {
    requestLog.set(origin, recent);
    return true;
  }
  recent.push(now);
  requestLog.set(origin, recent);
  return false;
}

// ---------------------------------------------------------------------------
// Background service worker
// ---------------------------------------------------------------------------
export default defineBackground(() => {
  // Open the web app when the extension icon is clicked (no popup)
  chrome.action.onClicked.addListener(() => {
    void chrome.tabs.create({ url: WEB_URL });
  });

  // Handle messages from the web page via externally_connectable
  chrome.runtime.onMessageExternal.addListener(
    (message: unknown, sender, sendResponse) => {
      // Defense-in-depth: validate sender origin even though Chrome filters
      const origin = sender.url ? new URL(sender.url).origin : "";
      if (!ALLOWED_ORIGINS.includes(origin)) {
        sendResponse({
          type: "ERROR",
          version: 1,
          code: "FORBIDDEN",
          message: "Origin not allowed",
        } satisfies ExtResponse);
        return;
      }

      // Rate limit
      if (isRateLimited(origin)) {
        sendResponse({
          type: "ERROR",
          version: 1,
          code: "RATE_LIMITED",
          message: "Too many requests. Try again later.",
        } satisfies ExtResponse);
        return;
      }

      // Validate message schema
      const parsed = ExtRequestSchema.safeParse(message);
      if (!parsed.success) {
        sendResponse({
          type: "ERROR",
          version: 1,
          code: "INVALID_MESSAGE",
          message: "Invalid message format",
        } satisfies ExtResponse);
        return;
      }

      const request = parsed.data;

      if (request.type === "PING") {
        sendResponse({ type: "PONG", version: 1 } satisfies ExtResponse);
        return;
      }

      if (request.type === "GET_EXTENSIONS") {
        // Async — return true to keep the message channel open
        chrome.management.getAll().then((installed) => {
          const extensions: InstalledExtensionInfo[] = installed
            .filter(
              (ext) =>
                ext.type === "extension" && ext.id !== chrome.runtime.id,
            )
            .map((ext) => ({
              id: ext.id,
              name: ext.name,
              enabled: ext.enabled,
            }));

          sendResponse({
            type: "EXTENSIONS_RESULT",
            version: 1,
            extensions,
          } satisfies ExtResponse);
        });
        return true; // keep channel open for async response
      }
    },
  );
});
