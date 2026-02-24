import { TRPCError } from "@trpc/server";
import { and, eq, gt, isNotNull, isNull, or } from "drizzle-orm";

import { Device, Organization, eqi } from "@amibeingpwned/db";

import { hashToken } from "../lib/tokens";
import { t } from "../trpc";

/**
 * Resolves a `Bearer aibp_dev_*` token from the Authorization header into
 * a validated, non-revoked Device row.
 *
 * Accepts both the current token hash and the previous token hash (while it
 * is still within its 5-minute grace period) so the extension is never locked
 * out if it receives a new token but crashes before persisting it.
 *
 * Attaches `ctx.device` so downstream procedures don't need to re-query.
 */
export const deviceAuthMiddleware = t.middleware(async ({ ctx, next }) => {
  const authorization = ctx.headers.get("authorization");

  if (!authorization?.startsWith("Bearer aibp_dev_")) {
    console.warn("[device-auth] Missing or malformed Authorization header");
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "Missing or invalid device token",
    });
  }

  const raw = authorization.slice("Bearer ".length);
  const tokenHash = await hashToken(raw);
  const now = new Date();

  const [device] = await ctx.db
    .select()
    .from(Device)
    .where(
      and(
        isNull(Device.revokedAt),
        or(
          // Current token — must not be expired
          and(eq(Device.tokenHash, tokenHash), gt(Device.tokenExpiresAt, now)),
          // Previous token — still within its grace period after rotation
          and(
            eq(Device.previousTokenHash, tokenHash),
            gt(Device.previousTokenExpiresAt, now),
          ),
        ),
      ),
    )
    .limit(1);

  if (!device) {
    // Log enough to spot brute-force attempts without leaking the raw token
    console.warn(
      `[device-auth] Token rejected — hash prefix: ${tokenHash.slice(0, 8)}… at ${now.toISOString()}`,
    );
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "Device token is invalid, expired, or revoked",
    });
  }

  // B2B devices: reject immediately if the org has been suspended
  if (device.orgId) {
    const [org] = await ctx.db
      .select({ suspendedAt: Organization.suspendedAt })
      .from(Organization)
      .where(and(eqi(Organization.id, device.orgId), isNotNull(Organization.suspendedAt)))
      .limit(1);

    if (org) {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: "Organization is suspended",
      });
    }
  }

  return next({
    ctx: {
      ...ctx,
      device,
    },
  });
});

/**
 * Device-authenticated procedure.
 *
 * Use this for all endpoints called by the Chrome extension directly.
 * Registration is the exception — it uses publicProcedure/protectedProcedure
 * with an org API key or user session, and issues the device token.
 */
export const deviceProcedure = t.procedure.use(deviceAuthMiddleware);
