import { count, desc, eq, sql } from "drizzle-orm";
import { z } from "zod/v4";

import { Extension, Organization, WorkspaceApp, eqi } from "@amibeingpwned/db";

import { syncWorkspaceApps } from "../services/workspace-sync";
import { createTRPCRouter, managerProcedure } from "../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(50),
});

export const workspaceRouter = createTRPCRouter({
  /**
   * Trigger a Google Workspace extension sync for the manager's org.
   * Fetches all installed Chrome extensions via the Chrome Management API
   * and upserts them into the database.
   */
  sync: managerProcedure.mutation(async ({ ctx }) => {
    return syncWorkspaceApps({
      db: ctx.db,
      userId: ctx.session.user.id,
      orgId: ctx.org.id,
    });
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
    .input(PaginationSchema)
    .query(async ({ ctx, input }) => {
      const orgId = ctx.org.id;
      const offset = (input.page - 1) * input.limit;

      const [rows, totalResult, orgResult] = await Promise.all([
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
          .where(eqi(WorkspaceApp.orgId, orgId))
          .orderBy(
            desc(sql`COALESCE(${Extension.isFlagged}, false)`),
            desc(sql`COALESCE(${Extension.riskScore}, 0)`),
            desc(WorkspaceApp.browserDeviceCount),
          )
          .limit(input.limit)
          .offset(offset),

        ctx.db
          .select({ total: count() })
          .from(WorkspaceApp)
          .where(eqi(WorkspaceApp.orgId, orgId)),

        ctx.db
          .select({ lastWorkspaceSyncAt: Organization.lastWorkspaceSyncAt })
          .from(Organization)
          .where(eqi(Organization.id, orgId))
          .limit(1),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
        lastSyncedAt: orgResult[0]?.lastWorkspaceSyncAt ?? null,
      };
    }),
});
