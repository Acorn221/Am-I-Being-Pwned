/**
 * Single source of truth for origins that may communicate with the extension.
 *
 * `wxt.config.ts` converts these to path patterns (appends `/*`) for the
 * `externally_connectable.matches` manifest field. `background.ts` uses them
 * directly for a defense-in-depth origin check on incoming messages.
 */

export const PROD_ORIGINS = ["https://amibeingpwned.com"] as const;

export const DEV_ORIGINS = [
  "https://amibeingpwned.com",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "https://deathmail-mac.j4a.uk",
] as const;
