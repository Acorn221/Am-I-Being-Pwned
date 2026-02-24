import { eq } from "drizzle-orm";

import { UserSubscription } from "@amibeingpwned/db";

import { createTRPCRouter, protectedProcedure } from "../trpc";

export const subscriptionRouter = createTRPCRouter({
  get: protectedProcedure.query(async ({ ctx }) => {
    const userId = ctx.session.user.id;

    const rows = await ctx.db
      .select()
      .from(UserSubscription)
      .where(eq(UserSubscription.userId, userId))
      .limit(1);

    const sub = rows[0];
    if (!sub) return null;

    const isActive =
      sub.currentPeriodEnd === null || sub.currentPeriodEnd > new Date();

    return { ...sub, isActive };
  }),
});
