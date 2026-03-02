import { TRPCError } from "@trpc/server";
import { and, count, desc, eq } from "drizzle-orm";
import { z } from "zod/v4";

import { ExtensionScan, ExtensionVersion, eqi } from "@amibeingpwned/db";

import { adminProcedure, createTRPCRouter } from "../../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

export const adminScansRouter = createTRPCRouter({
  list: adminProcedure
    .input(
      PaginationSchema.extend({
        status: z.enum(["pending", "running", "completed", "failed"]).optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const offset = (input.page - 1) * input.limit;
      const where =
        input.status !== undefined ? eq(ExtensionScan.status, input.status) : undefined;

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select()
          .from(ExtensionScan)
          .where(where)
          .orderBy(desc(ExtensionScan.createdAt))
          .limit(input.limit)
          .offset(offset),
        ctx.db.select({ total: count() }).from(ExtensionScan).where(where),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),

  get: adminProcedure
    .input(z.object({ scanId: z.string() }))
    .query(async ({ ctx, input }) => {
      const [scan] = await ctx.db
        .select()
        .from(ExtensionScan)
        .where(eqi(ExtensionScan.id, input.scanId))
        .limit(1);

      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });

      const [version] = await ctx.db
        .select()
        .from(ExtensionVersion)
        .where(eqi(ExtensionVersion.id, scan.extensionVersionId))
        .limit(1);

      return { scan, version: version ?? null };
    }),

  retry: adminProcedure
    .input(z.object({ scanId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const [scan] = await ctx.db
        .select({ id: ExtensionScan.id, status: ExtensionScan.status })
        .from(ExtensionScan)
        .where(eqi(ExtensionScan.id, input.scanId))
        .limit(1);

      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });

      if (scan.status !== "failed") {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: `Can only retry failed scans (current status: ${scan.status})`,
        });
      }

      await ctx.db
        .update(ExtensionScan)
        .set({ status: "pending", startedAt: null, completedAt: null })
        .where(and(eqi(ExtensionScan.id, scan.id), eq(ExtensionScan.status, "failed")));
    }),
});
