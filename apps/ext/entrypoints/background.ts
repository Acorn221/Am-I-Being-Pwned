import type { ExtResponse, InstalledExtensionInfo, RiskLevel } from "@amibeingpwned/types";
import { TRPCClientError } from "@trpc/client";
import { ExtRequestSchema } from "@amibeingpwned/validators";

import { API_BASE_URL, lookupExtension, fetchExtensionDatabase } from "../lib/api";
import {
  clearToken,
  getDisableList,
  getOrgPolicy,
  getQuarantineList,
  getStoredToken,
  registerDevice,
  setDisableList,
  setOrgPolicy,
  setQuarantineList,
  storeInviteToken,
  storeToken,
  syncExtensions,
} from "../lib/device";
import { getNotifiedRisk, setNotifiedRisk } from "../lib/storage";

import { DEV_ORIGINS, PROD_ORIGINS } from "../lib/allowed-origins";
import {
  ALARM_DAILY_SCAN,
  ALARM_POLICY_SYNC,
  ALARM_REGISTRATION_RETRY,
  INTERVAL_DAILY_SCAN_MINUTES,
  INTERVAL_POLICY_SYNC_MINUTES,
  INTERVAL_REGISTRATION_RETRY_MINUTES,
  LAST_SYNC_KEY,
  RATE_LIMIT_REQUESTS,
  RATE_LIMIT_WINDOW_MS,
} from "../lib/constants";
import { enqueueSyncWithApi } from "../lib/sync-queue";

const WEB_URL = API_BASE_URL;

const ALLOWED_ORIGINS: readonly string[] = import.meta.env.DEV ? DEV_ORIGINS : PROD_ORIGINS;


// ---------------------------------------------------------------------------
// Rate limiter - sliding window per origin
// ---------------------------------------------------------------------------
const RATE_LIMIT = RATE_LIMIT_REQUESTS;
const RATE_WINDOW_MS = RATE_LIMIT_WINDOW_MS;
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
  // Offline-safe disable enforcement
  //
  // Re-applied on every SW wake from the locally persisted list.
  // This means a DoS attack against the API cannot leave users exposed -
  // once the server flags an extension, the decision is enforced locally
  // until the server explicitly removes it from the disable list.
  // -------------------------------------------------------------------------

  async function enforceDisableList() {
    const list = await getDisableList();
    if (list.length === 0) return;
    for (const extId of list) {
      try {
        const info = await chrome.management.get(extId);
        if (info.enabled) {
          await chrome.management.setEnabled(extId, false);
        }
      } catch {
        // Extension may have been uninstalled - ignore
      }
    }
  }

  // -------------------------------------------------------------------------
  // API: device registration
  // -------------------------------------------------------------------------

  /**
   * Tries to register this device with the AIBP API.
   * On success: stores the token and cancels the retry alarm.
   * On failure: schedules a retry alarm (fires every 30 min).
   *   B2C failure is usually "user not logged in yet", harmless.
   */
  async function tryRegisterDevice({ syncAfter = false } = {}) {
    try {
      const { deviceToken: token } = await registerDevice();
      await storeToken(token);
      await chrome.alarms.clear("registration-retry");
      console.log("[AIBP] Device registered");
      if (syncAfter) await enqueueSyncWithApi(syncWithApi);
    } catch (err) {
      // For B2C, UNAUTHORIZED just means the user hasn't logged in yet.
      // Don't log it as an error - schedule a quiet retry.
      const isUnauthed =
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        err instanceof TRPCClientError && ("httpStatus" in err.data && err.data.httpStatus === 401);
      if (!isUnauthed) {
        console.warn("[AIBP] Device registration failed:", err);
      }
      void chrome.alarms.create(ALARM_REGISTRATION_RETRY, {
        periodInMinutes: INTERVAL_REGISTRATION_RETRY_MINUTES,
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

      // Rotate token immediately - server already invalidated the old one
      await storeToken(result.newToken);

      // --- Disable list (permanent, additive-only) ---
      // Only ever grows locally - DoS can't shrink it.
      const existingDisabled = await getDisableList();
      const mergedDisabled = [...new Set([...existingDisabled, ...result.disableList])];
      await setDisableList(mergedDisabled);

      for (const extId of result.disableList) {
        if (!existingDisabled.includes(extId)) {
          void chrome.notifications.create(`aibp-disabled-${extId}`, {
            type: "basic",
            iconUrl: chrome.runtime.getURL("icon/128.png"),
            title: "Malicious Extension Disabled",
            message:
              "Am I Being Pwned has disabled an extension flagged as malicious.",
            priority: 2,
          });
        }
      }
      await enforceDisableList();

      // --- Quarantine list (temporary, fully server-authoritative) ---
      // Extensions dropped from the list have been scanned clean - re-enable
      // them unless they're also on the permanent disable list.
      const prevQuarantine = await getQuarantineList();
      const newQuarantine = result.quarantineList;
      await setQuarantineList(newQuarantine);

      // Re-enable anything that cleared quarantine and isn't permanently flagged
      const cleared = prevQuarantine.filter(
        (id) => !newQuarantine.includes(id) && !mergedDisabled.includes(id),
      );
      for (const extId of cleared) {
        try {
          await chrome.management.setEnabled(extId, true);
        } catch {
          // Extension may have been uninstalled - ignore
        }
      }

      // Disable newly quarantined extensions and notify
      for (const extId of newQuarantine) {
        if (!prevQuarantine.includes(extId)) {
          try {
            await chrome.management.setEnabled(extId, false);
            void chrome.notifications.create(`aibp-quarantine-${extId}`, {
              type: "basic",
              iconUrl: chrome.runtime.getURL("icon/128.png"),
              title: "Extension Quarantined Pending Scan",
              message:
                "An extension updated to an unscanned version and has been temporarily disabled.",
              priority: 1,
            });
          } catch {
            // Extension may have been uninstalled - ignore
          }
        }
      }

      // All enforcement complete - mark sync as successful and cache org policy
      // for immediate offline enforcement on the next new install event.
      await chrome.storage.local.set({ [LAST_SYNC_KEY]: Date.now() });
      await setOrgPolicy(result.orgPolicy);
    } catch (err) {

      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      if (err instanceof TRPCClientError && err.data?.httpStatus === 401) {
        // Token was revoked server-side - clear and re-register
        console.warn("[AIBP] Device token rejected, re-registering");
        await clearToken();
        await tryRegisterDevice();
      } else {
        console.warn("[AIBP] Sync failed:", err);
      }
    }
  }

  // -------------------------------------------------------------------------
  // New extension install handler (org devices: block-first, verify, re-enable)
  // -------------------------------------------------------------------------

  async function handleNewExtension(ext: chrome.management.ExtensionInfo) {
    // Always re-enforce the static disable list first
    await enforceDisableList();

    const orgPolicy = await getOrgPolicy();
    if (!orgPolicy) {
      // B2C device - just notify on risk, no blocking
      void checkAndNotify(ext.id, ext.name);
      return;
    }

    // Org device: block immediately, then verify against local DB
    try {
      await chrome.management.setEnabled(ext.id, false);
    } catch {
      return; // Already uninstalled
    }

    // Static blocklist - policy says this ID is always blocked
    if (orgPolicy.blockedExtensionIds.includes(ext.id)) {
      void chrome.notifications.create(`aibp-policy-${ext.id}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icon/128.png"),
        title: "Extension blocked by policy",
        message: `${ext.name} is blocked by your organisation's policy.`,
        priority: 1,
      });
      return;
    }

    // Check local DB - network may be needed if cache is cold.
    // If the lookup throws (offline, fetch failed), re-enable the extension
    // and fall back to a standard risk notification rather than leaving the
    // user permanently blocked until the next sync.
    let report;
    try {
      report = await lookupExtension(ext.id);
    } catch {
      try {
        await chrome.management.setEnabled(ext.id, true);
      } catch { /* uninstalled during check */ }
      void checkAndNotify(ext.id, ext.name);
      return;
    }

    if (!report) {
      // Not in DB - needs scanning, stay blocked and notify user
      void chrome.notifications.create(`aibp-unknown-${ext.id}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icon/128.png"),
        title: "Extension blocked - pending scan",
        message: `${ext.name} hasn't been scanned yet. Contact your IT admin to get it approved.`,
        priority: 1,
      });
      return;
    }

    // In DB - check risk score against policy threshold
    const risk = report.risk.toLowerCase() as RiskLevel;
    const severity = RISK_SEVERITY[risk];
    if (orgPolicy.maxRiskScore !== null && severity >= orgPolicy.maxRiskScore) {
      void chrome.notifications.create(`aibp-policy-risk-${ext.id}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icon/128.png"),
        title: "Extension blocked - risk too high",
        message: `${ext.name} has a ${risk} risk level and has been blocked by your organisation's policy.`,
        priority: 2,
      });
      return;
    }

    // Passes all policy checks - re-enable only if not on the persistent
    // disable list (e.g. reinstall of a previously AIBP-flagged extension).
    const disableList = await getDisableList();
    if (disableList.includes(ext.id)) {
      return;
    }

    try {
      await chrome.management.setEnabled(ext.id, true);
    } catch {
      // Uninstalled during check - ignore
    }
    void checkAndNotify(ext.id, ext.name);
  }

  // -------------------------------------------------------------------------
  // Event listeners
  // -------------------------------------------------------------------------

  // When any extension is installed or updated: re-enforce immediately
  // (catches the case where a user reinstalls a flagged extension),
  // then check and sync with API.
  chrome.management.onInstalled.addListener((ext) => {
    if (ext.type !== "extension" || ext.id === chrome.runtime.id) return;
    void handleNewExtension(ext);
    void enqueueSyncWithApi(syncWithApi);
  });

  // When any extension is uninstalled: sync so server marks it as removed
  chrome.management.onUninstalled.addListener((extId) => {
    if (extId === chrome.runtime.id) return;
    void enqueueSyncWithApi(syncWithApi);
  });

  // On first install: scan everything, open web app, register device
  // On update: ensure alarms still exist
  chrome.runtime.onInstalled.addListener((details) => {
    void chrome.alarms.create(ALARM_DAILY_SCAN, {
      periodInMinutes: INTERVAL_DAILY_SCAN_MINUTES,
    });
    void chrome.alarms.create(ALARM_POLICY_SYNC, {
      periodInMinutes: INTERVAL_POLICY_SYNC_MINUTES,
      delayInMinutes: INTERVAL_POLICY_SYNC_MINUTES,
    });

    if (details.reason === "install") {
      void scanAllExtensions();
      void tryRegisterDevice({ syncAfter: true });
    }
  });

  // On service worker startup: enforce from local cache only (offline-safe).
  // All network sync happens via alarms so we don't hammer the API on every
  // browser launch - the next policy-sync alarm handles recovery if needed.
  chrome.runtime.onStartup.addListener(() => {
    void enforceDisableList();
  });

  // Alarm handler - single point for all network sync decisions.
  // On each policy-sync wake, check if the last successful sync is stale
  // (e.g. SW was killed mid-sync, or a previous alarm misfired) and recover.
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === ALARM_DAILY_SCAN) {
      void scanAllExtensions();
      void enqueueSyncWithApi(syncWithApi);
    } else if (alarm.name === ALARM_POLICY_SYNC) {
      // Always sync on this alarm - it exists to pick up policy changes promptly.
      // Also check for a stale lastSyncAt: if the previous cycle was missed
      // (SW killed mid-sync before the timestamp was written), the enqueue
      // here already covers recovery so no extra action needed.
      void enqueueSyncWithApi(syncWithApi);
    } else if (alarm.name === ALARM_REGISTRATION_RETRY) {
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

      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      if (request.type === "REGISTER_WITH_INVITE") {
        void (async () => {
          try {
            await storeInviteToken(request.token);
            const result = await registerDevice();
            await storeToken(result.deviceToken);
            void enqueueSyncWithApi(syncWithApi);
            if (!result.webSessionToken) {
              sendResponse({
                type: "ERROR",
                version: 1,
                code: "REGISTRATION_FAILED",
                message: "Registration succeeded but no session token was issued.",
              } satisfies ExtResponse);
              return;
            }
            sendResponse({
              type: "INVITE_REGISTERED",
              version: 1,
              webSessionToken: result.webSessionToken,
            } satisfies ExtResponse);
          } catch (err) {
            console.warn("[AIBP] Invite registration failed:", err);
            sendResponse({
              type: "ERROR",
              version: 1,
              code: "REGISTRATION_FAILED",
              message: "Registration failed. Please try again.",
            } satisfies ExtResponse);
          }
        })();
        return true; // keep channel open for async response
      }
    },
  );
});
