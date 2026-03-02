import { withBackoff } from "./backoff";

/**
 * Sequential sync queue.
 *
 * Ensures at-most-one active `syncWithApi` call at a time. If a sync is
 * already in progress when a new trigger fires (e.g. alarm fires during an
 * extension install sync), the new request waits for the current one to
 * finish rather than running in parallel.
 *
 * Each queued sync is wrapped with exponential backoff so transient network
 * errors are retried automatically before giving up.
 */

let queue: Promise<void> = Promise.resolve();

export function enqueueSyncWithApi(syncFn: () => Promise<void>): Promise<void> {
  queue = queue
    .then(() => withBackoff(syncFn))
    .catch((err) => {
      // withBackoff exhausted all retries - log and keep the queue alive.
      console.warn("[AIBP] Sync failed after retries:", err);
    });
  return queue;
}
