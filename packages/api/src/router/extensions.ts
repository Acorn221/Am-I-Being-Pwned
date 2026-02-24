import { TRPCError } from "@trpc/server";
import { and, desc, eq, isNull } from "drizzle-orm";
import { z } from "zod/v4";

import {
  Device,
  Extension,
  ExtensionScan,
  ExtensionVersion,
  UserExtension,
  eqi,
} from "@amibeingpwned/db";

import { createTRPCRouter, protectedProcedure } from "../trpc";

export const extensionsRouter = createTRPCRouter({
  list: protectedProcedure.query(async ({ ctx }) => {
    const userId = ctx.session.user.id;

    // Fetch all non-removed extensions across all active devices for this user,
    // ordered newest-seen-first so deduplication keeps the most recent row.
    const rows = await ctx.db
      .select({
        chromeExtensionId: UserExtension.chromeExtensionId,
        name: Extension.name,
        versionAtLastSync: UserExtension.versionAtLastSync,
        enabled: UserExtension.enabled,
        disabledByAibp: UserExtension.disabledByAibp,
        disabledReason: UserExtension.disabledReason,
        lastSeenAt: UserExtension.lastSeenAt,
        riskScore: Extension.riskScore,
        isFlagged: Extension.isFlagged,
      })
      .from(UserExtension)
      .innerJoin(Device, eqi(UserExtension.deviceId, Device.id))
      .leftJoin(
        Extension,
        eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId),
      )
      .where(
        and(
          eq(Device.userId, userId),
          isNull(Device.revokedAt),
          isNull(UserExtension.removedAt),
        ),
      )
      .orderBy(desc(UserExtension.lastSeenAt));

    // Deduplicate by chromeExtensionId — rows are already newest-first.
    const seen = new Map<string, (typeof rows)[number]>();
    for (const row of rows) {
      if (!seen.has(row.chromeExtensionId)) {
        seen.set(row.chromeExtensionId, row);
      }
    }

    return Array.from(seen.values());
  }),

  get: protectedProcedure
    .input(z.object({ chromeExtensionId: z.string() }))
    .query(async ({ ctx, input }) => {
      const userId = ctx.session.user.id;

      const rows = await ctx.db
        .select({
          chromeExtensionId: UserExtension.chromeExtensionId,
          name: Extension.name,
          versionAtLastSync: UserExtension.versionAtLastSync,
          enabled: UserExtension.enabled,
          disabledByAibp: UserExtension.disabledByAibp,
          disabledReason: UserExtension.disabledReason,
          lastSeenAt: UserExtension.lastSeenAt,
          riskScore: Extension.riskScore,
          isFlagged: Extension.isFlagged,
          extensionDbId: Extension.id,
        })
        .from(UserExtension)
        .innerJoin(Device, eqi(UserExtension.deviceId, Device.id))
        .leftJoin(
          Extension,
          eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId),
        )
        .where(
          and(
            eq(Device.userId, userId),
            isNull(Device.revokedAt),
            isNull(UserExtension.removedAt),
            eq(UserExtension.chromeExtensionId, input.chromeExtensionId),
          ),
        )
        .orderBy(desc(UserExtension.lastSeenAt))
        .limit(1);

      const base = rows[0];
      if (!base) throw new TRPCError({ code: "NOT_FOUND" });

      // Fetch versions and latest scan per version if Extension is in the registry.
      type VersionWithScan = typeof ExtensionVersion.$inferSelect & {
        latestScan: typeof ExtensionScan.$inferSelect | null;
      };
      let versions: VersionWithScan[] = [];

      if (base.extensionDbId) {
        const extensionDbId = base.extensionDbId;
        const versionRows = await ctx.db
          .select()
          .from(ExtensionVersion)
          .where(eqi(ExtensionVersion.extensionId, extensionDbId))
          .orderBy(desc(ExtensionVersion.detectedAt));

        versions = await Promise.all(
          versionRows.map(async (v) => {
            const scans = await ctx.db
              .select()
              .from(ExtensionScan)
              .where(eqi(ExtensionScan.extensionVersionId, v.id))
              .orderBy(desc(ExtensionScan.completedAt))
              .limit(1);
            return { ...v, latestScan: scans[0] ?? null };
          }),
        );
      }

      return { ...base, versions };
    }),
});
