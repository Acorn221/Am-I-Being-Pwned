import { fetchRequestHandler } from "@trpc/server/adapters/fetch";

import { appRouter, createTRPCContext } from "@amibeingpwned/api";
import { initAuth } from "@amibeingpwned/auth";

export interface Env {
  ASSETS?: Fetcher;
  POSTGRES_URL: string;
  AUTH_SECRET: string;
  AUTH_GOOGLE_ID: string;
  AUTH_GOOGLE_SECRET: string;
  // Canonical public origin — used as better-auth baseUrl.
  // Must come from a trusted env var, NOT from request headers (which an
  // attacker can spoof, poisoning the auth singleton for an entire isolate).
  APP_URL: string;
  // TODO: add RATE_LIMIT_KV: KVNamespace when rate limiting is implemented
}

// ---------------------------------------------------------------------------
// Security headers
// Applied to every response — critical for a security-focused product.
// ---------------------------------------------------------------------------

function applySecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);

  // Prevent MIME-type sniffing attacks
  headers.set("X-Content-Type-Options", "nosniff");

  // Deny all framing — prevents clickjacking
  headers.set("X-Frame-Options", "DENY");

  // Force HTTPS for 2 years, include subdomains
  headers.set(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains; preload",
  );

  // Prevent browsers leaking full URL in Referer header to third parties
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");

  // Lock down browser features we don't use
  headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=()",
  );

  // Cross-Origin isolation — prevents Spectre-style attacks
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-site");

  // Content Security Policy
  // - default-src 'self': only load resources from our own origin by default
  // - script-src 'self' 'strict-dynamic': no inline scripts, hashes/nonces propagate
  // - object-src 'none': no plugins (Flash, etc.)
  // - base-uri 'self': prevent base tag hijacking
  // - frame-ancestors 'none': belt-and-suspenders with X-Frame-Options
  headers.set(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'strict-dynamic'",
      "style-src 'self' 'unsafe-inline'", // unsafe-inline needed until CSS-in-JS nonces are wired in
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ].join("; "),
  );

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// ---------------------------------------------------------------------------
// Auth singleton — cached per worker isolate (safe: CF creates fresh isolates
// per deployment, not per request).
// ---------------------------------------------------------------------------

let auth: ReturnType<typeof initAuth> | undefined;

function getAuth(env: Env) {
  if (!auth) {
    auth = initAuth({
      // APP_URL comes from a trusted env var — never from request headers.
      baseUrl: env.APP_URL,
      secret: env.AUTH_SECRET,
      googleClientId: env.AUTH_GOOGLE_ID,
      googleClientSecret: env.AUTH_GOOGLE_SECRET,
    });
  }
  return auth;
}

// ---------------------------------------------------------------------------
// Main fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    const currentAuth = getAuth(env);

    let response: Response;

    // Auth routes — better-auth handles all /api/auth/* paths
    if (pathname.startsWith("/api/auth")) {
      response = await currentAuth.handler(request);
    }

    // tRPC routes
    else if (pathname.startsWith("/api/trpc")) {
      response = await fetchRequestHandler({
        endpoint: "/api/trpc",
        req: request,
        router: appRouter,
        createContext: () =>
          createTRPCContext({ headers: request.headers, auth: currentAuth }),
      });
    }

    // Serve static assets (production — Cloudflare Pages injects ASSETS)
    else if (env.ASSETS) {
      response = await env.ASSETS.fetch(request);
    } else {
      response = new Response("Not found", { status: 404 });
    }

    return applySecurityHeaders(response);
  },
};
