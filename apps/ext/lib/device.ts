/**
 * Device registration and token management for the extension.
 *
 * Registration flows:
 *   B2B MDM  - IT admin pushes `orgApiKey` via GPO/CBCM managed storage.
 *   B2B Invite - Employee clicks a /join/:token link from their org admin.
 *
 * The device token ("aibp_dev_...") is rotated on every sync - the server
 * returns `newToken` and we replace the stored one immediately.
 */

import { makeB2BClient, makeDeviceClient, publicClient } from "./trpc";

// ---------------------------------------------------------------------------
// chrome.storage.local keys
// ---------------------------------------------------------------------------

const FINGERPRINT_KEY = "aibp_fingerprint";
const DISABLE_LIST_KEY = "aibp_disable_list";
const QUARANTINE_LIST_KEY = "aibp_quarantine_list";
const TOKEN_KEY = "aibp_device_token";
const INVITE_TOKEN_KEY = "aibp_invite_token";
const WEB_SESSION_KEY = "aibp_web_session_token";

// ---------------------------------------------------------------------------
// Fingerprint - stable per-install UUID
// ---------------------------------------------------------------------------

/**
 * Returns the device fingerprint, generating and persisting one on first call.
 * Stored in chrome.storage.local so it survives extension updates.
 */
export async function getFingerprint(): Promise<string> {
  const stored = await chrome.storage.local.get(FINGERPRINT_KEY);
  if (typeof stored[FINGERPRINT_KEY] === "string") {
    return stored[FINGERPRINT_KEY];
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
    ? (stored[TOKEN_KEY])
    : null;
}

export async function storeToken(token: string): Promise<void> {
  await chrome.storage.local.set({ [TOKEN_KEY]: token });
}

export async function clearToken(): Promise<void> {
  await chrome.storage.local.remove(TOKEN_KEY);
}

// ---------------------------------------------------------------------------
// Invite token storage (B2B self-enrollment via shareable link)
// ---------------------------------------------------------------------------

export async function getInviteToken(): Promise<string | null> {
  const stored = await chrome.storage.local.get(INVITE_TOKEN_KEY);
  return typeof stored[INVITE_TOKEN_KEY] === "string"
    ? (stored[INVITE_TOKEN_KEY])
    : null;
}

export async function storeInviteToken(token: string): Promise<void> {
  await chrome.storage.local.set({ [INVITE_TOKEN_KEY]: token });
}

export async function clearInviteToken(): Promise<void> {
  await chrome.storage.local.remove(INVITE_TOKEN_KEY);
}

// ---------------------------------------------------------------------------
// Web session token (issued at invite enrollment for dashboard access)
// ---------------------------------------------------------------------------

export async function getStoredWebSessionToken(): Promise<string | null> {
  const stored = await chrome.storage.sync.get(WEB_SESSION_KEY);
  return typeof stored[WEB_SESSION_KEY] === "string"
    ? stored[WEB_SESSION_KEY]
    : null;
}

export async function storeWebSessionToken(token: string): Promise<void> {
  await chrome.storage.sync.set({ [WEB_SESSION_KEY]: token });
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
 * Tries MDM API key first, then invite token. Throws UNAUTHORIZED if neither
 * credential is available - caller should schedule a retry alarm.
 */
export interface RegisterResult {
  deviceToken: string;
  webSessionToken?: string;
}

async function getPlatformMeta(): Promise<{ os: string; arch: string }> {
  const info = await chrome.runtime.getPlatformInfo();
  return { os: info.os, arch: info.arch };
}

async function getIdentityEmail(): Promise<string | undefined> {
  try {
    const info = await chrome.identity.getProfileUserInfo({ accountStatus: "ANY" });
    return info.email || undefined;
  } catch {
    return undefined;
  }
}

export async function registerDevice(): Promise<RegisterResult> {
  const fingerprint = await getFingerprint();
  const [{ os, arch }, identityEmail] = await Promise.all([
    getPlatformMeta(),
    getIdentityEmail(),
  ]);
  const input = {
    deviceFingerprint: fingerprint,
    extensionVersion: chrome.runtime.getManifest().version,
    platform: "chrome" as const,
    os,
    arch,
    identityEmail,
  };

  // Priority 1: Org API key from MDM managed storage (enterprise GPO/CBCM)
  const orgApiKey = await getOrgApiKey();
  if (orgApiKey) {
    const { deviceToken } = await makeB2BClient(orgApiKey).devices.registerB2B.mutate(input);
    return { deviceToken };
  }

  // Priority 2: Invite token from shareable /join/:token link (SMB self-enrollment)
  const inviteToken = await getInviteToken();
  if (inviteToken) {
    const { deviceToken, webSessionToken } =
      await publicClient.devices.registerWithInvite.mutate({
        inviteToken,
        deviceFingerprint: fingerprint,
        extensionVersion: chrome.runtime.getManifest().version,
        platform: "chrome",
        os,
        arch,
        identityEmail,
      });
    await clearInviteToken();
    await storeWebSessionToken(webSessionToken);
    return { deviceToken, webSessionToken };
  }

  throw new Error("No registration credential available (no org API key or invite token)");
}

// ---------------------------------------------------------------------------
// Disable list - persisted locally so enforcement survives API downtime.
//
// The server is authoritative, but once it says "disable X", we store that
// decision and re-enforce it on every SW wake regardless of API availability.
// A DoS attack against the API cannot un-disarm an already-flagged extension.
// ---------------------------------------------------------------------------

export async function getDisableList(): Promise<string[]> {
  const stored = await chrome.storage.local.get(DISABLE_LIST_KEY);
  const val = stored[DISABLE_LIST_KEY];
  return Array.isArray(val) ? (val as string[]) : [];
}

export async function setDisableList(list: string[]): Promise<void> {
  await chrome.storage.local.set({ [DISABLE_LIST_KEY]: list });
}

// ---------------------------------------------------------------------------
// Quarantine list - server-authoritative, fully replaced on each sync.
//
// Unlike the disable list (additive-only), the quarantine list can shrink:
// once a scan completes clean, the extension drops off and gets re-enabled.
// If a scan comes back malicious, the server moves it to the disable list.
// ---------------------------------------------------------------------------

export async function getQuarantineList(): Promise<string[]> {
  const stored = await chrome.storage.local.get(QUARANTINE_LIST_KEY);
  const val = stored[QUARANTINE_LIST_KEY];
  return Array.isArray(val) ? (val as string[]) : [];
}

export async function setQuarantineList(list: string[]): Promise<void> {
  await chrome.storage.local.set({ [QUARANTINE_LIST_KEY]: list });
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
  /** Confirmed malicious - permanently disabled until admin un-flags. */
  disableList: string[];
  /** Unscanned updates - temporarily disabled until scan completes clean. */
  quarantineList: string[];
  /** Rotated device token - must be stored immediately. */
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
