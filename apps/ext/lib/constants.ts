// ---------------------------------------------------------------------------
// Alarm names
// ---------------------------------------------------------------------------
export const ALARM_POLICY_SYNC = "policy-sync";
export const ALARM_REGISTRATION_RETRY = "registration-retry";

// ---------------------------------------------------------------------------
// Alarm intervals (minutes)
// ---------------------------------------------------------------------------

/** Lightweight server sync to pick up org policy changes. */
export const INTERVAL_POLICY_SYNC_MINUTES = 4 * 60;

/** Retry interval when device registration has not yet succeeded. */
export const INTERVAL_REGISTRATION_RETRY_MINUTES = 30;

// ---------------------------------------------------------------------------
// Sync staleness
// ---------------------------------------------------------------------------

/** Storage key for the last successful sync timestamp (ms since epoch). */
export const LAST_SYNC_KEY = "aibp_last_sync_at";

/**
 * If the last successful sync is older than this, the alarm handler treats it
 * as a missed sync and runs one immediately on wake.
 * Set to slightly less than the policy-sync interval so a single missed cycle
 * is always caught on the next alarm fire.
 */
export const SYNC_STALE_MS = INTERVAL_POLICY_SYNC_MINUTES * 60 * 1000 - 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// Rate limiting (external message bridge)
// ---------------------------------------------------------------------------
export const RATE_LIMIT_REQUESTS = 10;
export const RATE_LIMIT_WINDOW_MS = 60_000;
