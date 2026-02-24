/**
 * Token utilities using the Web Crypto API.
 * Works in Cloudflare Workers, browsers, and Node.js 18+ — no Node-specific imports.
 */

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function randomBase64url(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  // btoa needs a binary string
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function sha256hex(value: string): Promise<string> {
  const encoded = new TextEncoder().encode(value);
  const buf = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Device token  — "aibp_dev_<32 random bytes base64url>"
// Issued to every registered device. Rotated on every successful sync.
// Short-lived: 7 days. Revocation is instant — just flip Device.revokedAt.
// ---------------------------------------------------------------------------

const DEVICE_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export async function generateDeviceToken() {
  const raw = `aibp_dev_${randomBase64url()}`;
  const hash = await sha256hex(raw);
  const expiresAt = new Date(Date.now() + DEVICE_TOKEN_TTL_MS);
  return { raw, hash, expiresAt };
}

// ---------------------------------------------------------------------------
// Org API Key  — "aibp_org_<32 random bytes base64url>"
// Provisioning credential. Never rotates automatically — admin rotates manually.
// ---------------------------------------------------------------------------

export async function generateOrgApiKey() {
  const raw = `aibp_org_${randomBase64url()}`;
  const hash = await sha256hex(raw);
  return { raw, hash };
}

// ---------------------------------------------------------------------------
// Hash any raw token for DB lookup
// ---------------------------------------------------------------------------

export async function hashToken(raw: string): Promise<string> {
  return sha256hex(raw);
}
