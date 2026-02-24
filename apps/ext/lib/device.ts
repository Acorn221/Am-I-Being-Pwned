/**
 * Device registration and token management for the extension.
 *
 * Registration flows:
 *   B2B — IT admin pushes `orgApiKey` via MDM (chrome.storage.managed).
 *          No user session needed; device binds to the org.
 *   B2C — Requires an active amibeingpwned.com session cookie.
 *          Retried automatically until the user logs in.
 *
 * The device token ("aibp_dev_…") is rotated on every sync — the server
 * returns `newToken` and we replace the stored one immediately.
 */

import { makeB2BClient, makeDeviceClient, publicClient } from "./trpc";

// ---------------------------------------------------------------------------
// chrome.storage.local keys
// ---------------------------------------------------------------------------

const FINGERPRINT_KEY = "aibp_fingerprint";
const TOKEN_KEY = "aibp_device_token";

// ---------------------------------------------------------------------------
// Fingerprint — stable per-install UUID
// ---------------------------------------------------------------------------

/**
 * Returns the device fingerprint, generating and persisting one on first call.
 * Stored in chrome.storage.local so it survives extension updates.
 */
export async function getFingerprint(): Promise<string> {
  const stored = await chrome.storage.local.get(FINGERPRINT_KEY);
  if (typeof stored[FINGERPRINT_KEY] === "string") {
    return stored[FINGERPRINT_KEY] as string;
  }
  const id = crypto.randomUUID();
  await chrome.storage.local.set({ [FINGERPRINT_KEY]: id });
  return id;
}

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

export async function getStoredToken(): Promise<string | null> {
  const stored = await chrome.storage.local.get(TOKEN_KEY);
  return typeof stored[TOKEN_KEY] === "string"
    ? (stored[TOKEN_KEY] as string)
    : null;
}

export async function storeToken(token: string): Promise<void> {
  await chrome.storage.local.set({ [TOKEN_KEY]: token });
}

export async function clearToken(): Promise<void> {
  await chrome.storage.local.remove(TOKEN_KEY);
}

// ---------------------------------------------------------------------------
// Org API key (B2B managed storage)
// ---------------------------------------------------------------------------

/**
 * Reads the org API key pushed by IT via MDM policy.
 * chrome.storage.managed throws if no managed storage is configured,
 * so we catch and return null for unmanaged (B2C) installs.
 */
export async function getOrgApiKey(): Promise<string | null> {
  try {
    const managed = await chrome.storage.managed.get("orgApiKey");
    return typeof managed.orgApiKey === "string" ? managed.orgApiKey : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Attempts to register this device with the AIBP API.
 *
 * Tries B2B first (org API key in managed storage), then falls back to B2C
 * (session cookie). Returns the raw device token on success.
 *
 * Throws if:
 *   - B2B: the org API key is invalid/revoked
 *   - B2C: the user is not logged in (UNAUTHORIZED) — caller should schedule
 *     a retry alarm rather than propagating this error
 */
export async function registerDevice(): Promise<string> {
  const fingerprint = await getFingerprint();
  const input = {
    deviceFingerprint: fingerprint,
    extensionVersion: chrome.runtime.getManifest().version,
    platform: "chrome" as const,
  };

  // B2B takes priority — org API key from MDM managed storage
  const orgApiKey = await getOrgApiKey();
  if (orgApiKey) {
    const { deviceToken } = await makeB2BClient(orgApiKey).devices.registerB2B.mutate(input);
    return deviceToken;
  }

  // B2C — session cookie forwarded via credentials: "include"
  const { deviceToken } = await publicClient.devices.registerB2C.mutate(input);
  return deviceToken;
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

export interface SyncExtension {
  chromeExtensionId: string;
  version: string;
  enabled: boolean;
  name?: string;
}

export interface SyncResult {
  /** Extension IDs the server wants disabled on this device. */
  disableList: string[];
  /** Rotated device token — must be stored immediately. */
  newToken: string;
}

/**
 * Sends the current extension inventory to the API and returns the disable
 * list + rotated token. Callers must store `newToken` right away.
 */
export async function syncExtensions(
  token: string,
  extensions: SyncExtension[],
): Promise<SyncResult> {
  const client = makeDeviceClient(token);
  return client.devices.sync.mutate({ extensions });
}
