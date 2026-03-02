interface BackoffOptions {
  maxAttempts?: number;
  baseMs?: number;
  maxMs?: number;
}

/**
 * Retries `fn` with exponential backoff on failure.
 * Suitable for short in-process retries (seconds) - the service worker stays
 * alive during an active async operation so setTimeout works fine here.
 * Longer retry cadences (minutes) should use alarms instead.
 */
export async function withBackoff<T>(
  fn: () => Promise<T>,
  // maxMs capped at 8s - MV3 service workers can be killed after ~30s of
  // inactivity, so long setTimeout delays risk the retry never firing.
  { maxAttempts = 4, baseMs = 1_000, maxMs = 8_000 }: BackoffOptions = {},
): Promise<T> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt === maxAttempts - 1) throw err;
      const delay =
        Math.min(baseMs * 2 ** attempt, maxMs) + Math.random() * 200;
      await new Promise<void>((r) => setTimeout(r, delay));
    }
  }
  // Unreachable - loop always throws on the final attempt
  throw new Error("withBackoff: exhausted attempts");
}
