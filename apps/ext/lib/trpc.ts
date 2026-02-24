/**
 * tRPC client for the extension background service worker.
 *
 * We use `import type { AppRouter }` which Vite strips at build time — no
 * server-side code is bundled into the extension. Types are resolved from
 * the api package's generated dist/index.d.ts.
 *
 * Three client factories, one per auth mode:
 *   publicClient      — session cookie (B2C, user must be logged in)
 *   makeB2BClient     — org API key header (B2B, no user session needed)
 *   makeDeviceClient  — device token header (sync and device procedures)
 */
import type { AppRouter } from "@amibeingpwned/api";
import { createTRPCClient, httpLink } from "@trpc/client";
import superjson from "superjson";

import { API_BASE_URL } from "./api";

function makeClient(headers: () => Record<string, string>) {
  return createTRPCClient<AppRouter>({
    links: [
      httpLink({
        url: `${API_BASE_URL}/api/trpc`,
        transformer: superjson,
        headers,
        // credentials: "include" forwards the better-auth session cookie,
        // enabling B2C registration from the extension.
        fetch: (url, options) =>
          fetch(url, { ...options, credentials: "include" }),
      }),
    ],
  });
}

/** Unauthenticated / session-cookie client (B2C registration, public reads). */
export const publicClient = makeClient(() => ({}));

/** B2B registration client — sends the org API key from managed storage. */
export function makeB2BClient(orgApiKey: string) {
  return makeClient(() => ({ "x-org-api-key": orgApiKey }));
}

/** Device-authenticated client — used for sync and other device procedures. */
export function makeDeviceClient(token: string) {
  return makeClient(() => ({ Authorization: `Bearer ${token}` }));
}
