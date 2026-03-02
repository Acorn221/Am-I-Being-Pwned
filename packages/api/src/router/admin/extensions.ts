import { TRPCError } from "@trpc/server";
import { and, count, desc, eq, ilike, inArray, or } from "drizzle-orm";
import { z } from "zod/v4";

import {
  Extension,
  ExtensionAnalysisReport,
  ExtensionScan,
  ExtensionVersion,
  eqi,
} from "@amibeingpwned/db";

import { adminProcedure, createTRPCRouter } from "../../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

const RISK_LEVELS = ["unknown", "clean", "low", "medium", "high", "critical"] as const;
type RiskLevel = (typeof RISK_LEVELS)[number];

// Extensions at or above the given risk level (inclusive)
const RISK_LEVEL_AND_ABOVE: Record<RiskLevel, RiskLevel[]> = {
  unknown: ["unknown", "clean", "low", "medium", "high", "critical"],
  clean:   ["clean", "low", "medium", "high", "critical"],
  low:     ["low", "medium", "high", "critical"],
  medium:  ["medium", "high", "critical"],
  high:    ["high", "critical"],
  critical: ["critical"],
};

export const adminExtensionsRouter = createTRPCRouter({
  list: adminProcedure
    .input(
      PaginationSchema.extend({
        search: z.string().optional(),
        isFlagged: z.boolean().optional(),
        minRiskLevel: z.enum(RISK_LEVELS).optional(),
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
        input.minRiskLevel !== undefined
          ? inArray(Extension.riskLevel, RISK_LEVEL_AND_ABOVE[input.minRiskLevel])
          : undefined,
      );

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select()
          .from(Extension)
          .where(where)
          .orderBy(desc(Extension.riskLevel), desc(Extension.lastUpdatedAt))
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

      const [scans, analysisReports] = await Promise.all([
        versions.length > 0
          ? ctx.db
              .select()
              .from(ExtensionScan)
              .where(
                inArray(
                  ExtensionScan.extensionVersionId,
                  versions.map((v) => v.id),
                ),
              )
              .orderBy(desc(ExtensionScan.completedAt))
          : [],
        versions.length > 0
          ? ctx.db
              .select()
              .from(ExtensionAnalysisReport)
              .where(
                inArray(
                  ExtensionAnalysisReport.extensionVersionId,
                  versions.map((v) => v.id),
                ),
              )
              .orderBy(desc(ExtensionAnalysisReport.analyzedAt))
          : [],
      ]);

      return { extension, versions, scans, analysisReports };
    }),

  flag: adminProcedure
    .input(
      z.object({
        extensionId: z.string(),
        reason: z.string().min(1),
        riskLevel: z.enum(RISK_LEVELS).optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Extension)
        .set({
          isFlagged: true,
          flaggedReason: input.reason,
          ...(input.riskLevel !== undefined ? { riskLevel: input.riskLevel } : {}),
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

  setRiskLevel: adminProcedure
    .input(
      z.object({
        extensionId: z.string(),
        riskLevel: z.enum(RISK_LEVELS),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Extension)
        .set({ riskLevel: input.riskLevel, lastUpdatedAt: new Date() })
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
          .set({ status: "pending", startedAt: null, completedAt: null })
          .where(eqi(ExtensionScan.id, existing.id));
      } else {
        await ctx.db
          .insert(ExtensionScan)
          .values({ extensionVersionId: input.extensionVersionId });
      }
    }),

  /**
   * Called by the scanner worker to write results back.
   * Writes the LLM analysis report to ExtensionAnalysisReport, updates the
   * ExtensionVersion risk level/summary, and rolls up to Extension.riskLevel.
   *
   * TODO: replace adminProcedure with a dedicated scannerProcedure authenticated
   * by a scanner service API key rather than an admin session.
   */
  submitScanResult: adminProcedure
    .input(
      z.object({
        scanId: z.string(),
        status: z.enum(["completed", "failed"]),
        scanner: z.string().optional(),
        riskLevel: z.enum(RISK_LEVELS).optional(),
        summary: z.string().optional(),
        flagCategories: z.array(z.string()).optional(),
        vulnCountLow: z.number().int().min(0).optional(),
        vulnCountMedium: z.number().int().min(0).optional(),
        vulnCountHigh: z.number().int().min(0).optional(),
        vulnCountCritical: z.number().int().min(0).optional(),
        endpoints: z.array(z.string()).optional(),
        reportContent: z.string().optional(),
        canPublish: z.boolean().optional(),
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
          scanner: input.scanner ?? null,
          completedAt: now,
        })
        .where(eqi(ExtensionScan.id, scan.id));

      if (input.status === "completed" && input.riskLevel !== undefined) {
        // Update ExtensionVersion with normalized risk level + summary
        await ctx.db
          .update(ExtensionVersion)
          .set({
            riskLevel: input.riskLevel,
            summary: input.summary ?? null,
            flagCategories: input.flagCategories ?? [],
            analyzedAt: now,
          })
          .where(eqi(ExtensionVersion.id, scan.extensionVersionId));

        // Write the LLM analysis report if content was provided
        if (input.reportContent) {
          await ctx.db
            .insert(ExtensionAnalysisReport)
            .values({
              extensionVersionId: scan.extensionVersionId,
              reportType: "llm_analysis",
              content: input.reportContent,
              summary: input.summary ?? null,
              riskLevel: input.riskLevel,
              flagCategories: input.flagCategories ?? [],
              vulnCountLow: input.vulnCountLow ?? 0,
              vulnCountMedium: input.vulnCountMedium ?? 0,
              vulnCountHigh: input.vulnCountHigh ?? 0,
              vulnCountCritical: input.vulnCountCritical ?? 0,
              endpoints: input.endpoints ?? [],
              canPublish: input.canPublish ?? true,
              analyzedAt: now,
            })
            .onConflictDoUpdate({
              target: [
                ExtensionAnalysisReport.extensionVersionId,
                ExtensionAnalysisReport.reportType,
              ],
              set: {
                content: input.reportContent,
                summary: input.summary ?? null,
                riskLevel: input.riskLevel,
                flagCategories: input.flagCategories ?? [],
                vulnCountLow: input.vulnCountLow ?? 0,
                vulnCountMedium: input.vulnCountMedium ?? 0,
                vulnCountHigh: input.vulnCountHigh ?? 0,
                vulnCountCritical: input.vulnCountCritical ?? 0,
                endpoints: input.endpoints ?? [],
                canPublish: input.canPublish ?? true,
                analyzedAt: now,
              },
            });
        }

        // Roll up riskLevel to the parent Extension row
        const [version] = await ctx.db
          .select({ extensionId: ExtensionVersion.extensionId })
          .from(ExtensionVersion)
          .where(eqi(ExtensionVersion.id, scan.extensionVersionId))
          .limit(1);

        if (version) {
          await ctx.db
            .update(Extension)
            .set({ riskLevel: input.riskLevel, lastUpdatedAt: now })
            .where(eqi(Extension.id, version.extensionId));
        }
      }
    }),
});
