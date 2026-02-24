import { and, count, desc, eq, isNull } from "drizzle-orm";
import { z } from "zod/v4";

import { Device, Extension, ExtensionScan, user } from "@amibeingpwned/db";

import { adminProcedure, createTRPCRouter } from "../../trpc";

export const adminStatsRouter = createTRPCRouter({
  /**
   * Cheap aggregate counts for the admin dashboard overview panel.
   * All queries run in parallel.
   */
  overview: adminProcedure.query(async ({ ctx }) => {
    const [
      userCountResult,
      deviceCountResult,
      extensionCountResult,
      flaggedCountResult,
      pendingScansResult,
    ] = await Promise.all([
      ctx.db.select({ total: count() }).from(user),
      ctx.db
        .select({ total: count() })
        .from(Device)
        .where(isNull(Device.revokedAt)),
      ctx.db.select({ total: count() }).from(Extension),
      ctx.db
        .select({ total: count() })
        .from(Extension)
        .where(eq(Extension.isFlagged, true)),
      ctx.db
        .select({ total: count() })
        .from(ExtensionScan)
        .where(eq(ExtensionScan.status, "pending")),
    ]);

    return {
      totalUsers: userCountResult[0]?.total ?? 0,
      activeDevices: deviceCountResult[0]?.total ?? 0,
      totalExtensions: extensionCountResult[0]?.total ?? 0,
      flaggedExtensions: flaggedCountResult[0]?.total ?? 0,
      pendingScanJobs: pendingScansResult[0]?.total ?? 0,
    };
  }),

  recentFlags: adminProcedure
    .input(
      z.object({
        limit: z.number().int().min(1).max(50).default(10),
      }),
    )
    .query(async ({ ctx, input }) => {
      return ctx.db
        .select()
        .from(Extension)
        .where(eq(Extension.isFlagged, true))
        .orderBy(desc(Extension.lastUpdatedAt))
        .limit(input.limit);
    }),
});
