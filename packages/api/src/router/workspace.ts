import { and, asc, count, desc, eq, gte, ilike, or, sql } from "drizzle-orm";
import { z } from "zod/v4";

import { Extension, WorkspaceApp, WorkspaceDevice, eqi } from "@amibeingpwned/db";

import { TRPCError } from "@trpc/server";

import { syncWorkspaceApps } from "../services/workspace-sync";
import { createTRPCRouter, managerProcedure } from "../trpc";

export const workspaceRouter = createTRPCRouter({
  /**
   * Trigger a Google Workspace extension sync for the manager's org.
   * Fetches all installed Chrome extensions via the Chrome Management API
   * and upserts them into the database.
   */
  sync: managerProcedure.mutation(async ({ ctx }) => {
    try {
      return await syncWorkspaceApps({
        db: ctx.db,
        userId: ctx.session.user.id,
        orgId: ctx.org.id,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("[workspace.sync] error:", message);
      if (err instanceof TRPCError) throw err;
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message });
    }
  }),

  /**
   * Paginated list of enrolled Chrome browser devices discovered during the
   * last workspace sync via findInstalledAppDevices.
   */
  devices: managerProcedure
    .input(
      z.object({
        page: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(100).default(25),
        search: z.string().optional(),
        sortBy: z.enum(["machineName", "extensionCount", "lastSyncedAt"]).default("extensionCount"),
        sortDir: z.enum(["asc", "desc"]).default("desc"),
      }),
    )
    .query(async ({ ctx, input }) => {
      const orgId = ctx.org.id;
      const offset = (input.page - 1) * input.limit;

      const whereClause = and(
        eqi(WorkspaceDevice.orgId, orgId),
        input.search ? ilike(WorkspaceDevice.machineName, `%${input.search}%`) : undefined,
      );

      const orderByExpr = (() => {
        switch (input.sortBy) {
          case "machineName":
            return input.sortDir === "asc"
              ? sql`${WorkspaceDevice.machineName} ASC NULLS LAST`
              : sql`${WorkspaceDevice.machineName} DESC NULLS LAST`;
          case "lastSyncedAt":
            return input.sortDir === "asc"
              ? asc(WorkspaceDevice.lastSyncedAt)
              : desc(WorkspaceDevice.lastSyncedAt);
          default:
            return input.sortDir === "asc"
              ? asc(WorkspaceDevice.extensionCount)
              : desc(WorkspaceDevice.extensionCount);
        }
      })();

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select({
            googleDeviceId: WorkspaceDevice.googleDeviceId,
            machineName: WorkspaceDevice.machineName,
            extensionCount: WorkspaceDevice.extensionCount,
            lastSyncedAt: WorkspaceDevice.lastSyncedAt,
          })
          .from(WorkspaceDevice)
          .where(whereClause)
          .orderBy(orderByExpr)
          .limit(input.limit)
          .offset(offset),

        ctx.db
          .select({ total: count() })
          .from(WorkspaceDevice)
          .where(whereClause),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),

  /**
   * Paginated list of Chrome extensions across the org's managed devices,
   * sourced from the Google Workspace sync. Enriched with risk data from
   * the global extension registry where available.
   *
   * Also returns lastSyncedAt from the org row so the UI can show the
   * last sync time and decide whether to auto-trigger a sync.
   */
  apps: managerProcedure
    .input(
      z.object({
        page: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(100).default(25),
        search: z.string().optional(),
        sortBy: z.enum(["name", "riskScore", "deviceCount"]).default("deviceCount"),
        sortDir: z.enum(["asc", "desc"]).default("desc"),
        isFlagged: z.boolean().optional(),
        riskLevel: z.enum(["low", "medium", "high"]).optional(),
        installType: z.string().optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const orgId = ctx.org.id;
      const offset = (input.page - 1) * input.limit;

      const whereClause = and(
        eqi(WorkspaceApp.orgId, orgId),
        input.search
          ? or(
              ilike(WorkspaceApp.displayName, `%${input.search}%`),
              ilike(WorkspaceApp.chromeExtensionId, `%${input.search}%`),
            )
          : undefined,
        input.isFlagged !== undefined
          ? eq(Extension.isFlagged, input.isFlagged)
          : undefined,
        input.riskLevel === "low"
          ? gte(sql<number>`COALESCE(${Extension.riskScore}, 0)`, 1)
          : input.riskLevel === "medium"
            ? gte(sql<number>`COALESCE(${Extension.riskScore}, 0)`, 40)
            : input.riskLevel === "high"
              ? gte(sql<number>`COALESCE(${Extension.riskScore}, 0)`, 70)
              : undefined,
        input.installType ? eq(WorkspaceApp.installType, input.installType) : undefined,
      );

      const orderByExpr = (() => {
        const d = input.sortDir;
        switch (input.sortBy) {
          case "name":
            return d === "asc"
              ? sql`${WorkspaceApp.displayName} ASC NULLS LAST`
              : sql`${WorkspaceApp.displayName} DESC NULLS LAST`;
          case "riskScore":
            return d === "asc"
              ? sql`${Extension.riskScore} ASC NULLS LAST`
              : sql`${Extension.riskScore} DESC NULLS LAST`;
          default:
            return d === "asc"
              ? asc(WorkspaceApp.browserDeviceCount)
              : desc(WorkspaceApp.browserDeviceCount);
        }
      })();

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select({
            chromeExtensionId: WorkspaceApp.chromeExtensionId,
            displayName: WorkspaceApp.displayName,
            installType: WorkspaceApp.installType,
            browserDeviceCount: WorkspaceApp.browserDeviceCount,
            osUserCount: WorkspaceApp.osUserCount,
            iconUrl: WorkspaceApp.iconUrl,
            riskScore: Extension.riskScore,
            isFlagged: Extension.isFlagged,
            flaggedReason: Extension.flaggedReason,
          })
          .from(WorkspaceApp)
          .leftJoin(
            Extension,
            eq(WorkspaceApp.chromeExtensionId, Extension.chromeExtensionId),
          )
          .where(whereClause)
          .orderBy(orderByExpr)
          .limit(input.limit)
          .offset(offset),

        ctx.db
          .select({ total: count() })
          .from(WorkspaceApp)
          .leftJoin(
            Extension,
            eq(WorkspaceApp.chromeExtensionId, Extension.chromeExtensionId),
          )
          .where(whereClause),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
        lastSyncedAt: ctx.org.lastWorkspaceSyncAt ?? null,
      };
    }),
});
