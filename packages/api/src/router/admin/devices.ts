import { TRPCError } from "@trpc/server";
import { and, count, desc, eq, inArray, isNotNull, isNull, lt } from "drizzle-orm";
import { z } from "zod/v4";

import { Device, UserExtension, UserExtensionEvent, eqi } from "@amibeingpwned/db";

import { adminProcedure, createTRPCRouter } from "../../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

export const adminDevicesRouter = createTRPCRouter({
  list: adminProcedure
    .input(
      PaginationSchema.extend({
        orgId: z.string().optional(),
        endUserId: z.string().optional(),
        platform: z.enum(["chrome", "edge"]).optional(),
        isRevoked: z.boolean().optional(),
        // ISO datetime string — devices not seen since this date
        lastSeenBefore: z.string().datetime().optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const offset = (input.page - 1) * input.limit;

      const where = and(
        input.orgId !== undefined ? eqi(Device.orgId, input.orgId) : undefined,
        input.endUserId !== undefined ? eqi(Device.endUserId, input.endUserId) : undefined,
        input.platform !== undefined ? eq(Device.platform, input.platform) : undefined,
        input.isRevoked !== undefined
          ? input.isRevoked
            ? isNotNull(Device.revokedAt)
            : isNull(Device.revokedAt)
          : undefined,
        input.lastSeenBefore !== undefined
          ? lt(Device.lastSeenAt, new Date(input.lastSeenBefore))
          : undefined,
      );

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select()
          .from(Device)
          .where(where)
          .orderBy(desc(Device.lastSeenAt))
          .limit(input.limit)
          .offset(offset),
        ctx.db.select({ total: count() }).from(Device).where(where),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),

  get: adminProcedure
    .input(z.object({ deviceId: z.string() }))
    .query(async ({ ctx, input }) => {
      const [device] = await ctx.db
        .select()
        .from(Device)
        .where(eqi(Device.id, input.deviceId))
        .limit(1);

      if (!device) throw new TRPCError({ code: "NOT_FOUND" });

      const [extensions, recentEvents] = await Promise.all([
        ctx.db
          .select()
          .from(UserExtension)
          .where(
            and(
              eqi(UserExtension.deviceId, device.id),
              isNull(UserExtension.removedAt),
            ),
          )
          .orderBy(UserExtension.chromeExtensionId),
        // Last 50 events across all extensions on this device
        ctx.db
          .select({
            id: UserExtensionEvent.id,
            eventType: UserExtensionEvent.eventType,
            previousVersion: UserExtensionEvent.previousVersion,
            newVersion: UserExtensionEvent.newVersion,
            createdAt: UserExtensionEvent.createdAt,
            chromeExtensionId: UserExtension.chromeExtensionId,
          })
          .from(UserExtensionEvent)
          .innerJoin(
            UserExtension,
            eqi(UserExtensionEvent.userExtensionId, UserExtension.id),
          )
          .where(eqi(UserExtension.deviceId, device.id))
          .orderBy(desc(UserExtensionEvent.createdAt))
          .limit(50),
      ]);

      return { device, extensions, recentEvents };
    }),

  revoke: adminProcedure
    .input(z.object({ deviceId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Device)
        .set({ revokedAt: new Date() })
        .where(and(eqi(Device.id, input.deviceId), isNull(Device.revokedAt)));
    }),

  bulkRevoke: adminProcedure
    .input(
      z.object({
        deviceIds: z.array(z.string()).min(1).max(500),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const revoked = await ctx.db
        .update(Device)
        .set({ revokedAt: new Date() })
        .where(and(inArray(Device.id, input.deviceIds), isNull(Device.revokedAt)))
        .returning({ id: Device.id });

      return { revokedCount: revoked.length };
    }),
});
