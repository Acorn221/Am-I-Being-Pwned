import type { ExtResponse, InstalledExtensionInfo, RiskLevel } from "@amibeingpwned/types";
import { TRPCClientError } from "@trpc/client";
import { ExtRequestSchema } from "@amibeingpwned/validators";

import { API_BASE_URL, lookupExtension, fetchExtensionDatabase } from "../lib/api";
import {
  clearToken,
  getStoredToken,
  registerDevice,
  storeToken,
  syncExtensions,
} from "../lib/device";
import { getNotifiedRisk, setNotifiedRisk } from "../lib/storage";

const WEB_URL = API_BASE_URL;

const ALLOWED_ORIGINS = import.meta.env.DEV
  ? ["https://amibeingpwned.com", API_BASE_URL]
  : ["https://amibeingpwned.com"];

// ---------------------------------------------------------------------------
// Rate limiter - sliding window, 10 requests per 60 seconds per origin
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
// Risk severity - higher number = worse. Only notify at NOTIFY_THRESHOLD+.
// ---------------------------------------------------------------------------
const RISK_SEVERITY: Record<RiskLevel, number> = {
  clean: 0,
  low: 1,
  "medium-low": 2,
  medium: 3,
  "medium-high": 4,
  high: 5,
  critical: 6,
  unavailable: -1,
};
const NOTIFY_THRESHOLD = RISK_SEVERITY.medium; // medium and above

// ---------------------------------------------------------------------------
// Background service worker
// ---------------------------------------------------------------------------
export default defineBackground(() => {
  // -------------------------------------------------------------------------
  // Local database scan + notifications
  // -------------------------------------------------------------------------

  async function checkAndNotify(extensionId: string, extensionName: string) {
    try {
      const report = await lookupExtension(extensionId);
      if (!report) return;

      const risk = report.risk.toLowerCase() as RiskLevel;
      const severity = RISK_SEVERITY[risk];
      if (severity < NOTIFY_THRESHOLD) return;

      // Skip if we already notified at this risk level or higher
      const lastNotified = await getNotifiedRisk(extensionId);
      if (lastNotified && RISK_SEVERITY[lastNotified] >= severity) return;

      const notifId = `aibp-alert-${extensionId}`;
      void chrome.notifications.create(notifId, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icon/128.png"),
        title: `${risk === "critical" ? "CRITICAL" : "Warning"}: ${extensionName}`,
        message: report.summary || `This extension has a ${risk} risk level.`,
        priority: risk === "critical" ? 2 : 1,
      });

      await setNotifiedRisk(extensionId, risk);
    } catch {
      // Network errors shouldn't break the extension - fail silently
    }
  }

  // Scan all installed extensions against the local/remote database
  async function scanAllExtensions() {
    try {
      await fetchExtensionDatabase();
    } catch {
      return; // Can't reach the server - skip scan
    }

    const installed = await chrome.management.getAll();
    for (const ext of installed) {
      if (ext.type !== "extension" || ext.id === chrome.runtime.id) continue;
      await checkAndNotify(ext.id, ext.name);
    }
  }

  // -------------------------------------------------------------------------
  // API: device registration
  // -------------------------------------------------------------------------

  /**
   * Tries to register this device with the AIBP API.
   * On success: stores the token and cancels the retry alarm.
   * On failure: schedules a retry alarm (fires every 30 min).
   *   B2C failure is usually "user not logged in yet" — harmless.
   */
  async function tryRegisterDevice() {
    try {
      const token = await registerDevice();
      await storeToken(token);
      await chrome.alarms.clear("registration-retry");
      console.log("[AIBP] Device registered");
    } catch (err) {
      // For B2C, UNAUTHORIZED just means the user hasn't logged in yet.
      // Don't log it as an error — schedule a quiet retry.
      const isUnauthed =
        err instanceof TRPCClientError && err.data?.httpStatus === 401;
      if (!isUnauthed) {
        console.warn("[AIBP] Device registration failed:", err);
      }
      void chrome.alarms.create("registration-retry", {
        periodInMinutes: 30,
      });
    }
  }

  // -------------------------------------------------------------------------
  // API: extension inventory sync
  // -------------------------------------------------------------------------

  /**
   * Syncs the current extension inventory with the API.
   *
   * - Registers the device first if not already registered.
   * - Rotates the device token on every successful sync.
   * - Disables extensions the server flags as malicious.
   * - If the token is rejected (revoked), clears it and re-registers.
   */
  async function syncWithApi() {
    let token = await getStoredToken();

    if (!token) {
      await tryRegisterDevice();
      token = await getStoredToken();
      if (!token) return; // Still not registered (user not logged in yet)
    }

    const installed = await chrome.management.getAll();
    const extensions = installed
      .filter((e) => e.type === "extension" && e.id !== chrome.runtime.id)
      .map((e) => ({
        chromeExtensionId: e.id,
        version: e.version,
        enabled: e.enabled,
        name: e.name,
      }));

    try {
      const result = await syncExtensions(token, extensions);

      // Rotate token immediately — server already invalidated the old one
      await storeToken(result.newToken);

      // Enforce the server's disable list
      for (const extId of result.disableList) {
        try {
          await chrome.management.setEnabled(extId, false);
          void chrome.notifications.create(`aibp-disabled-${extId}`, {
            type: "basic",
            iconUrl: chrome.runtime.getURL("icon/128.png"),
            title: "Malicious Extension Disabled",
            message:
              "Am I Being Pwned has disabled an extension flagged as malicious.",
            priority: 2,
          });
        } catch {
          // Extension may have already been removed — ignore
        }
      }
    } catch (err) {
      if (err instanceof TRPCClientError && err.data?.httpStatus === 401) {
        // Token was revoked server-side — clear and re-register
        console.warn("[AIBP] Device token rejected, re-registering");
        await clearToken();
        await tryRegisterDevice();
      } else {
        console.warn("[AIBP] Sync failed:", err);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Event listeners
  // -------------------------------------------------------------------------

  // When any extension is installed or updated: local check + API sync
  chrome.management.onInstalled.addListener((ext) => {
    if (ext.type !== "extension" || ext.id === chrome.runtime.id) return;
    void checkAndNotify(ext.id, ext.name);
    void syncWithApi();
  });

  // When any extension is uninstalled: sync so server marks it as removed
  chrome.management.onUninstalled.addListener((extId) => {
    if (extId === chrome.runtime.id) return;
    void syncWithApi();
  });

  // On first install: scan everything, open web app, register device
  // On update: ensure alarms still exist
  chrome.runtime.onInstalled.addListener((details) => {
    void chrome.alarms.create("daily-scan", { periodInMinutes: 24 * 60 });

    if (details.reason === "install") {
      void chrome.tabs.create({ url: WEB_URL });
      void scanAllExtensions();
      void tryRegisterDevice();
    }
  });

  // On service worker startup (browser launch, extension reload)
  chrome.runtime.onStartup.addListener(() => {
    void syncWithApi();
  });

  // Alarm handler
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "daily-scan") {
      void scanAllExtensions();
      void syncWithApi();
    } else if (alarm.name === "registration-retry") {
      void tryRegisterDevice();
    }
  });

  // Open report page when a notification is clicked
  chrome.notifications.onClicked.addListener((notifId) => {
    if (notifId.startsWith("aibp-alert-")) {
      const extensionId = notifId.replace("aibp-alert-", "");
      void chrome.tabs.create({ url: `${WEB_URL}/report/${extensionId}` });
      void chrome.notifications.clear(notifId);
    } else if (notifId.startsWith("aibp-disabled-")) {
      void chrome.tabs.create({ url: WEB_URL });
      void chrome.notifications.clear(notifId);
    }
  });

  // -------------------------------------------------------------------------
  // External messaging (web app ↔ extension bridge)
  // -------------------------------------------------------------------------

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

      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      if (request.type === "GET_EXTENSIONS") {
        // Async - return true to keep the message channel open
        void chrome.management.getAll().then((installed) => {
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
