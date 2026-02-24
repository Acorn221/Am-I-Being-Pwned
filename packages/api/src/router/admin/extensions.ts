import { TRPCError } from "@trpc/server";
import { and, count, desc, eq, gte, ilike, inArray, or } from "drizzle-orm";
import { z } from "zod/v4";

import {
  Extension,
  ExtensionScan,
  ExtensionVersion,
  eqi,
} from "@amibeingpwned/db";

import { adminProcedure, createTRPCRouter } from "../../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

export const adminExtensionsRouter = createTRPCRouter({
  list: adminProcedure
    .input(
      PaginationSchema.extend({
        search: z.string().optional(),
        isFlagged: z.boolean().optional(),
        minRiskScore: z.number().int().min(0).max(100).optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const offset = (input.page - 1) * input.limit;

      const where = and(
        input.search
          ? or(
              ilike(Extension.name, `%${input.search}%`),
              ilike(Extension.publisher, `%${input.search}%`),
              ilike(Extension.chromeExtensionId, `%${input.search}%`),
            )
          : undefined,
        input.isFlagged !== undefined
          ? eq(Extension.isFlagged, input.isFlagged)
          : undefined,
        input.minRiskScore !== undefined
          ? gte(Extension.riskScore, input.minRiskScore)
          : undefined,
      );

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select()
          .from(Extension)
          .where(where)
          .orderBy(desc(Extension.riskScore), desc(Extension.lastUpdatedAt))
          .limit(input.limit)
          .offset(offset),
        ctx.db.select({ total: count() }).from(Extension).where(where),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),

  get: adminProcedure
    .input(z.object({ extensionId: z.string() }))
    .query(async ({ ctx, input }) => {
      const [extension] = await ctx.db
        .select()
        .from(Extension)
        .where(eqi(Extension.id, input.extensionId))
        .limit(1);

      if (!extension) throw new TRPCError({ code: "NOT_FOUND" });

      const versions = await ctx.db
        .select()
        .from(ExtensionVersion)
        .where(eqi(ExtensionVersion.extensionId, extension.id))
        .orderBy(desc(ExtensionVersion.detectedAt));

      const scans =
        versions.length > 0
          ? await ctx.db
              .select()
              .from(ExtensionScan)
              .where(
                inArray(
                  ExtensionScan.extensionVersionId,
                  versions.map((v) => v.id),
                ),
              )
              .orderBy(desc(ExtensionScan.completedAt))
          : [];

      return { extension, versions, scans };
    }),

  flag: adminProcedure
    .input(
      z.object({
        extensionId: z.string(),
        reason: z.string().min(1),
        riskScore: z.number().int().min(0).max(100).optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Extension)
        .set({
          isFlagged: true,
          flaggedReason: input.reason,
          ...(input.riskScore !== undefined ? { riskScore: input.riskScore } : {}),
          lastUpdatedAt: new Date(),
        })
        .where(eqi(Extension.id, input.extensionId));
    }),

  unflag: adminProcedure
    .input(z.object({ extensionId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Extension)
        .set({
          isFlagged: false,
          flaggedReason: null,
          lastUpdatedAt: new Date(),
        })
        .where(eqi(Extension.id, input.extensionId));
    }),

  setRiskScore: adminProcedure
    .input(
      z.object({
        extensionId: z.string(),
        riskScore: z.number().int().min(0).max(100),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Extension)
        .set({ riskScore: input.riskScore, lastUpdatedAt: new Date() })
        .where(eqi(Extension.id, input.extensionId));
    }),

  /**
   * Enqueue (or re-enqueue) a scan for a specific extension version.
   * If a scan row already exists, it's reset to "pending" so the scanner
   * worker picks it up again.
   */
  triggerScan: adminProcedure
    .input(z.object({ extensionVersionId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const [existing] = await ctx.db
        .select({ id: ExtensionScan.id })
        .from(ExtensionScan)
        .where(eqi(ExtensionScan.extensionVersionId, input.extensionVersionId))
        .limit(1);

      if (existing) {
        await ctx.db
          .update(ExtensionScan)
          .set({ status: "pending", startedAt: null, completedAt: null, findings: null })
          .where(eqi(ExtensionScan.id, existing.id));
      } else {
        await ctx.db
          .insert(ExtensionScan)
          .values({ extensionVersionId: input.extensionVersionId });
      }
    }),

  /**
   * Called by the scanner worker to write results back.
   * Updates both the scan row and the parent ExtensionVersion verdict/riskScore.
   *
   * TODO: replace adminProcedure with a dedicated scannerProcedure authenticated
   * by a scanner service API key rather than an admin session.
   */
  submitScanResult: adminProcedure
    .input(
      z.object({
        scanId: z.string(),
        status: z.enum(["completed", "failed"]),
        verdict: z.enum(["safe", "suspicious", "malicious", "unknown"]).optional(),
        riskScore: z.number().int().min(0).max(100).optional(),
        findings: z.record(z.string(), z.unknown()).optional(),
        scanner: z.string().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const now = new Date();

      const [scan] = await ctx.db
        .select({ id: ExtensionScan.id, extensionVersionId: ExtensionScan.extensionVersionId })
        .from(ExtensionScan)
        .where(eqi(ExtensionScan.id, input.scanId))
        .limit(1);

      if (!scan) throw new TRPCError({ code: "NOT_FOUND" });

      await ctx.db
        .update(ExtensionScan)
        .set({
          status: input.status,
          findings: input.findings ?? null,
          scanner: input.scanner ?? null,
          completedAt: now,
        })
        .where(eqi(ExtensionScan.id, scan.id));

      if (input.status === "completed" && input.verdict !== undefined) {
        await ctx.db
          .update(ExtensionVersion)
          .set({
            verdict: input.verdict,
            riskScore: input.riskScore ?? 0,
            analyzedAt: now,
          })
          .where(eqi(ExtensionVersion.id, scan.extensionVersionId));
      }
    }),
});
