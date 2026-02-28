import { t } from "../trpc";

/**
 * Rate limiting middleware backed by Cloudflare KV.
 *
 * TODO: implement when ready. Flip RATE_LIMIT_ENABLED to true and provide
 * the KV namespace via `ctx.env.RATE_LIMIT_KV` (add to Env in packages/worker
 * and thread it through createTRPCContext).
 *
 * Suggested strategy: fixed window per (userId | IP) per minute.
 *
 *   const key = `rl:${ctx.session?.user.id ?? ctx.clientIp}:${Math.floor(Date.now() / 60_000)}`;
 *   const raw = await ctx.env.RATE_LIMIT_KV.get(key);
 *   const count = parseInt(raw ?? "0", 10);
 *   if (count >= LIMIT) throw new TRPCError({ code: "TOO_MANY_REQUESTS" });
 *   await ctx.env.RATE_LIMIT_KV.put(key, String(count + 1), { expirationTtl: 120 });
 */
const RATE_LIMIT_ENABLED = false;
const REQUESTS_PER_MINUTE = 60;

export const rateLimitMiddleware = t.middleware(async ({ ctx, next }) => {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (!RATE_LIMIT_ENABLED) return next();

  // Authenticated users are keyed by user ID; unauthenticated by IP (best-effort).
  const identity = ctx.session?.user.id;

  if (!identity) {
    // Unauthenticated requests are always allowed through for now.
    // Tighten this once IP forwarding is confirmed working in CF Workers.
    return next();
  }

  // CF KV implementation — uncomment and wire ctx.env.RATE_LIMIT_KV when ready.
  // const window = Math.floor(Date.now() / 60_000);
  // const key = `rl:${identity}:${window}`;
  // const raw = await ctx.env.RATE_LIMIT_KV.get(key);
  // const count = parseInt(raw ?? "0", 10);
  // if (count >= REQUESTS_PER_MINUTE) {
  //   throw new TRPCError({
  //     code: "TOO_MANY_REQUESTS",
  //     message: "Rate limit exceeded. Try again in a moment.",
  //   });
  // }
  // await ctx.env.RATE_LIMIT_KV.put(key, String(count + 1), { expirationTtl: 120 });

  void REQUESTS_PER_MINUTE; // suppress unused warning until implemented
  return next();
});
