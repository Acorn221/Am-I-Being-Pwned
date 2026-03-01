import { TRPCError } from "@trpc/server";
import { and, count, desc, eq, ilike, or } from "drizzle-orm";
import { z } from "zod/v4";

import { UserAlert, UserSubscription, user } from "@amibeingpwned/db";

import { adminProcedure, createTRPCRouter } from "../../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

export const adminUsersRouter = createTRPCRouter({
  list: adminProcedure
    .input(
      PaginationSchema.extend({
        search: z.string().optional(),
        role: z.enum(["user", "admin"]).optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const offset = (input.page - 1) * input.limit;

      const where = and(
        input.search
          ? or(
              ilike(user.email, `%${input.search}%`),
              ilike(user.name, `%${input.search}%`),
            )
          : undefined,
        input.role !== undefined ? eq(user.role, input.role) : undefined,
      );

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select()
          .from(user)
          .where(where)
          .orderBy(desc(user.createdAt))
          .limit(input.limit)
          .offset(offset),
        ctx.db.select({ total: count() }).from(user).where(where),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),

  get: adminProcedure
    .input(z.object({ userId: z.string() }))
    .query(async ({ ctx, input }) => {
      // user.id is a plain text column from better-auth — use eq, not eqi
      const [userRow] = await ctx.db
        .select()
        .from(user)
        .where(eq(user.id, input.userId))
        .limit(1);

      if (!userRow) throw new TRPCError({ code: "NOT_FOUND" });

      const [subscription] = await ctx.db
        .select()
        .from(UserSubscription)
        .where(eq(UserSubscription.userId, input.userId))
        .limit(1);

      const [unreadAlertResult] = await ctx.db
        .select({ total: count() })
        .from(UserAlert)
        .where(and(eq(UserAlert.userId, input.userId), eq(UserAlert.read, false)));

      return {
        user: userRow,
        subscription: subscription ?? null,
        unreadAlertCount: unreadAlertResult?.total ?? 0,
      };
    }),

  setRole: adminProcedure
    .input(
      z.object({
        userId: z.string(),
        role: z.enum(["user", "admin"]),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      if (input.userId === ctx.session.user.id && input.role !== "admin") {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "Cannot demote your own admin role",
        });
      }

      await ctx.db
        .update(user)
        .set({ role: input.role })
        .where(eq(user.id, input.userId));

      // Session invalidation: better-auth (with Drizzle adapter) fetches the user
      // record fresh on every getSession call, so the role change is visible on the
      // very next request without needing to revoke existing session tokens.
    }),

});
