import { and, count, desc, eq } from "drizzle-orm";
import { z } from "zod/v4";

import { Extension, UserAlert, eqi } from "@amibeingpwned/db";

import { createTRPCRouter, protectedProcedure } from "../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

export const alertsRouter = createTRPCRouter({
  list: protectedProcedure
    .input(
      PaginationSchema.extend({
        unreadOnly: z.boolean().optional(),
        dismissed: z.boolean().optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const offset = (input.page - 1) * input.limit;
      const userId = ctx.session.user.id;

      const where = and(
        eq(UserAlert.userId, userId),
        input.unreadOnly ? eq(UserAlert.read, false) : undefined,
        input.dismissed !== undefined
          ? eq(UserAlert.dismissed, input.dismissed)
          : undefined,
      );

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select({
            id: UserAlert.id,
            alertType: UserAlert.alertType,
            severity: UserAlert.severity,
            title: UserAlert.title,
            body: UserAlert.body,
            read: UserAlert.read,
            dismissed: UserAlert.dismissed,
            createdAt: UserAlert.createdAt,
            extensionId: UserAlert.extensionId,
            extensionName: Extension.name,
            chromeExtensionId: Extension.chromeExtensionId,
          })
          .from(UserAlert)
          .leftJoin(Extension, eqi(UserAlert.extensionId, Extension.id))
          .where(where)
          .orderBy(desc(UserAlert.createdAt))
          .limit(input.limit)
          .offset(offset),
        ctx.db.select({ total: count() }).from(UserAlert).where(where),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),

  markRead: protectedProcedure
    .input(z.object({ alertId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(UserAlert)
        .set({ read: true })
        .where(
          and(
            eqi(UserAlert.id, input.alertId),
            eq(UserAlert.userId, ctx.session.user.id),
          ),
        );
    }),

  dismiss: protectedProcedure
    .input(z.object({ alertId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(UserAlert)
        .set({ dismissed: true })
        .where(
          and(
            eqi(UserAlert.id, input.alertId),
            eq(UserAlert.userId, ctx.session.user.id),
          ),
        );
    }),

  markAllRead: protectedProcedure.mutation(async ({ ctx }) => {
    await ctx.db
      .update(UserAlert)
      .set({ read: true })
      .where(
        and(
          eq(UserAlert.userId, ctx.session.user.id),
          eq(UserAlert.read, false),
        ),
      );
  }),
});
