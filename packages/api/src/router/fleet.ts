import { and, asc, count, countDistinct, desc, eq, gte, ilike, isNull, or, sql } from "drizzle-orm";
import { z } from "zod/v4";

import type { db as DbType } from "@amibeingpwned/db/client";
import {
  Device,
  Extension,
  OrgMember,
  Organization,
  UserAlert,
  UserExtension,
  WorkspaceApp,
  WorkspaceDevice,
  eqi,
} from "@amibeingpwned/db";

import { TRPCError } from "@trpc/server";
import { createTRPCRouter, managerProcedure, protectedProcedure } from "../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

// ---------------------------------------------------------------------------
// Shared helper — look up the manager's org membership
// ---------------------------------------------------------------------------

async function getManagerMembership(db: typeof DbType, userId: string) {
  const [membership] = await db
    .select({
      orgId: OrgMember.orgId,
      orgRole: OrgMember.role,
      orgName: Organization.name,
      orgPlan: Organization.plan,
      orgSuspendedAt: Organization.suspendedAt,
      orgLastWorkspaceSyncAt: Organization.lastWorkspaceSyncAt,
    })
    .from(OrgMember)
    .innerJoin(Organization, eqi(OrgMember.orgId, Organization.id))
    .where(
      and(
        eq(OrgMember.userId, userId),
        or(eq(OrgMember.role, "owner"), eq(OrgMember.role, "admin")),
      ),
    )
    .limit(1);
  return membership ?? null;
}

export const fleetRouter = createTRPCRouter({
  /**
   * High-level stats for the manager's organisation.
   * Returns null (HTTP 200) when the user is not a manager — avoids a 401
   * console error for regular users on every dashboard load.
   */
  overview: protectedProcedure.query(async ({ ctx }) => {
    const membership = await getManagerMembership(ctx.db, ctx.session.user.id);
    if (!membership) return null;

    const orgId = membership.orgId;

    const [
      extDeviceCountResult,
      extExtensionCountResult,
      extFlaggedCountResult,
      workspaceDeviceCountResult,
      workspaceExtensionCountResult,
      workspaceFlaggedCountResult,
      unreadAlertResult,
    ] = await Promise.all([
      // Extension-synced device count
      ctx.db
        .select({ total: count() })
        .from(Device)
        .where(and(eqi(Device.orgId, orgId), isNull(Device.revokedAt))),

      // Extension-synced extension count
      ctx.db
        .select({ total: countDistinct(UserExtension.chromeExtensionId) })
        .from(UserExtension)
        .innerJoin(Device, eqi(UserExtension.deviceId, Device.id))
        .where(
          and(
            eqi(Device.orgId, orgId),
            isNull(Device.revokedAt),
            isNull(UserExtension.removedAt),
          ),
        ),

      // Extension-synced flagged count
      ctx.db
        .select({ total: countDistinct(UserExtension.chromeExtensionId) })
        .from(UserExtension)
        .innerJoin(Device, eqi(UserExtension.deviceId, Device.id))
        .innerJoin(Extension, eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId))
        .where(
          and(
            eqi(Device.orgId, orgId),
            isNull(Device.revokedAt),
            isNull(UserExtension.removedAt),
            eq(Extension.isFlagged, true),
          ),
        ),

      // OAuth workspace device count
      ctx.db
        .select({ total: count() })
        .from(WorkspaceDevice)
        .where(eqi(WorkspaceDevice.orgId, orgId)),

      // OAuth workspace extension count
      ctx.db
        .select({ total: count() })
        .from(WorkspaceApp)
        .where(eqi(WorkspaceApp.orgId, orgId)),

      // OAuth workspace flagged extension count
      ctx.db
        .select({ total: count() })
        .from(WorkspaceApp)
        .innerJoin(Extension, eq(WorkspaceApp.chromeExtensionId, Extension.chromeExtensionId))
        .where(and(eqi(WorkspaceApp.orgId, orgId), eq(Extension.isFlagged, true))),

      // Unread alerts
      ctx.db
        .select({ total: count() })
        .from(UserAlert)
        .innerJoin(OrgMember, eq(UserAlert.userId, OrgMember.userId))
        .where(
          and(
            eqi(OrgMember.orgId, orgId),
            eq(UserAlert.read, false),
            eq(UserAlert.dismissed, false),
          ),
        ),
    ]);

    return {
      org: {
        id: membership.orgId,
        name: membership.orgName,
        plan: membership.orgPlan,
        suspendedAt: membership.orgSuspendedAt,
        lastWorkspaceSyncAt: membership.orgLastWorkspaceSyncAt,
      },
      deviceCount:
        (extDeviceCountResult[0]?.total ?? 0) +
        (workspaceDeviceCountResult[0]?.total ?? 0),
      extensionCount:
        (extExtensionCountResult[0]?.total ?? 0) +
        (workspaceExtensionCountResult[0]?.total ?? 0),
      flaggedCount:
        (extFlaggedCountResult[0]?.total ?? 0) +
        (workspaceFlaggedCountResult[0]?.total ?? 0),
      unreadAlertCount: unreadAlertResult[0]?.total ?? 0,
    };
  }),

  /**
   * Unread alerts for all members of the manager's org.
   */
  alerts: managerProcedure.query(async ({ ctx }) => {
    const orgId = ctx.org.id;

    return ctx.db
      .select({
        id: UserAlert.id,
        alertType: UserAlert.alertType,
        severity: UserAlert.severity,
        title: UserAlert.title,
        body: UserAlert.body,
        createdAt: UserAlert.createdAt,
        extensionName: Extension.name,
        chromeExtensionId: Extension.chromeExtensionId,
      })
      .from(UserAlert)
      .innerJoin(OrgMember, eq(UserAlert.userId, OrgMember.userId))
      .leftJoin(Extension, eqi(UserAlert.extensionId, Extension.id))
      .where(
        and(
          eqi(OrgMember.orgId, orgId),
          eq(UserAlert.read, false),
          eq(UserAlert.dismissed, false),
        ),
      )
      .orderBy(desc(UserAlert.createdAt))
      .limit(20);
  }),

  /**
   * Mark a single alert as read + dismissed.
   */
  dismissAlert: managerProcedure
    .input(z.object({ alertId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const orgId = ctx.org.id;

      // Verify the alert belongs to a member of this org before touching it
      const [alert] = await ctx.db
        .select({ id: UserAlert.id })
        .from(UserAlert)
        .innerJoin(OrgMember, eq(UserAlert.userId, OrgMember.userId))
        .where(
          and(
            eqi(UserAlert.id, input.alertId),
            eqi(OrgMember.orgId, orgId),
          ),
        )
        .limit(1);

      if (!alert) throw new TRPCError({ code: "NOT_FOUND" });

      await ctx.db
        .update(UserAlert)
        .set({ read: true, dismissed: true })
        .where(eqi(UserAlert.id, input.alertId));
    }),

  /**
   * Devices that currently have ≥1 flagged extension installed.
   * Used to show the "affected devices" section.
   */
  threatenedDevices: managerProcedure.query(async ({ ctx }) => {
    const orgId = ctx.org.id;

    const rows = await ctx.db
      .select({
        deviceId: Device.id,
        platform: Device.platform,
        lastSeenAt: Device.lastSeenAt,
        extensionName: Extension.name,
        chromeExtensionId: Extension.chromeExtensionId,
        riskScore: Extension.riskScore,
        flaggedReason: Extension.flaggedReason,
      })
      .from(Device)
      .innerJoin(
        UserExtension,
        and(eqi(UserExtension.deviceId, Device.id), isNull(UserExtension.removedAt)),
      )
      .innerJoin(
        Extension,
        and(
          eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId),
          eq(Extension.isFlagged, true),
        ),
      )
      .where(and(eqi(Device.orgId, orgId), isNull(Device.revokedAt)))
      .orderBy(desc(Device.lastSeenAt));

    // Group threats by device
    const deviceMap = new Map<string, {
      deviceId: string;
      platform: "chrome" | "edge";
      lastSeenAt: Date;
      threats: {
        extensionName: string | null;
        chromeExtensionId: string;
        riskScore: number;
        flaggedReason: string | null;
      }[];
    }>();

    for (const row of rows) {
      if (!deviceMap.has(row.deviceId)) {
        deviceMap.set(row.deviceId, {
          deviceId: row.deviceId,
          platform: row.platform,
          lastSeenAt: row.lastSeenAt,
          threats: [],
        });
      }
      deviceMap.get(row.deviceId)?.threats.push({
        extensionName: row.extensionName,
        chromeExtensionId: row.chromeExtensionId,
        riskScore: row.riskScore,
        flaggedReason: row.flaggedReason,
      });
    }

    return Array.from(deviceMap.values());
  }),

  /**
   * Paginated list of all devices belonging to the manager's org.
   */
  devices: managerProcedure
    .input(
      z.object({
        page: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(100).default(25),
        search: z.string().optional(),
        sortBy: z.enum(["extensionCount", "flaggedCount", "lastSeenAt"]).default("lastSeenAt"),
        sortDir: z.enum(["asc", "desc"]).default("desc"),
        platform: z.enum(["chrome", "edge"]).optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const orgId = ctx.org.id;
      const offset = (input.page - 1) * input.limit;

      const whereClause = and(
        eqi(Device.orgId, orgId),
        isNull(Device.revokedAt),
        input.search
          ? or(
              ilike(Device.id, `%${input.search}%`),
              ilike(Device.identityEmail, `%${input.search}%`),
            )
          : undefined,
        input.platform ? eq(Device.platform, input.platform) : undefined,
      );

      const extCount = count(UserExtension.chromeExtensionId);
      const flaggedCount = sql<number>`CAST(COUNT(DISTINCT CASE WHEN ${Extension.isFlagged} THEN ${UserExtension.chromeExtensionId} END) AS int)`;

      const orderByExpr = (() => {
        switch (input.sortBy) {
          case "extensionCount":
            return input.sortDir === "asc" ? asc(extCount) : desc(extCount);
          case "flaggedCount":
            return input.sortDir === "asc"
              ? sql`CAST(COUNT(DISTINCT CASE WHEN ${Extension.isFlagged} THEN ${UserExtension.chromeExtensionId} END) AS int) ASC`
              : sql`CAST(COUNT(DISTINCT CASE WHEN ${Extension.isFlagged} THEN ${UserExtension.chromeExtensionId} END) AS int) DESC`;
          default:
            return input.sortDir === "asc" ? asc(Device.lastSeenAt) : desc(Device.lastSeenAt);
        }
      })();

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select({
            id: Device.id,
            platform: Device.platform,
            os: Device.os,
            arch: Device.arch,
            identityEmail: Device.identityEmail,
            lastSeenAt: Device.lastSeenAt,
            extensionCount: extCount,
            flaggedExtensionCount: flaggedCount,
          })
          .from(Device)
          .leftJoin(
            UserExtension,
            and(eqi(UserExtension.deviceId, Device.id), isNull(UserExtension.removedAt)),
          )
          .leftJoin(
            Extension,
            eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId),
          )
          .where(whereClause)
          .groupBy(Device.id)
          .orderBy(orderByExpr)
          .limit(input.limit)
          .offset(offset),

        ctx.db
          .select({ total: count() })
          .from(Device)
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
   * Paginated deduplicated extension list across all org devices.
   */
  extensions: managerProcedure
    .input(
      z.object({
        page: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(100).default(25),
        search: z.string().optional(),
        sortBy: z.enum(["name", "riskScore", "deviceCount"]).default("deviceCount"),
        sortDir: z.enum(["asc", "desc"]).default("desc"),
        isFlagged: z.boolean().optional(),
        riskLevel: z.enum(["low", "medium", "high"]).optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const orgId = ctx.org.id;
      const offset = (input.page - 1) * input.limit;

      const whereClause = and(
        eqi(Device.orgId, orgId),
        isNull(Device.revokedAt),
        isNull(UserExtension.removedAt),
        input.search
          ? or(
              ilike(Extension.name, `%${input.search}%`),
              ilike(UserExtension.chromeExtensionId, `%${input.search}%`),
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
      );

      const orderByExpr = (() => {
        const d = input.sortDir;
        switch (input.sortBy) {
          case "name":
            return d === "asc"
              ? sql`${Extension.name} ASC NULLS LAST`
              : sql`${Extension.name} DESC NULLS LAST`;
          case "riskScore":
            return d === "asc"
              ? sql`${Extension.riskScore} ASC NULLS LAST`
              : sql`${Extension.riskScore} DESC NULLS LAST`;
          default:
            return d === "asc"
              ? asc(countDistinct(UserExtension.deviceId))
              : desc(countDistinct(UserExtension.deviceId));
        }
      })();

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select({
            chromeExtensionId: UserExtension.chromeExtensionId,
            name: Extension.name,
            riskScore: Extension.riskScore,
            isFlagged: Extension.isFlagged,
            deviceCount: countDistinct(UserExtension.deviceId),
            enabledCount: sql<number>`CAST(COUNT(DISTINCT CASE WHEN ${UserExtension.enabled} THEN ${UserExtension.deviceId} END) AS int)`,
          })
          .from(UserExtension)
          .innerJoin(Device, eqi(UserExtension.deviceId, Device.id))
          .leftJoin(Extension, eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId))
          .where(whereClause)
          .groupBy(
            UserExtension.chromeExtensionId,
            Extension.name,
            Extension.riskScore,
            Extension.isFlagged,
          )
          .orderBy(orderByExpr)
          .limit(input.limit)
          .offset(offset),

        ctx.db
          .select({ total: countDistinct(UserExtension.chromeExtensionId) })
          .from(UserExtension)
          .innerJoin(Device, eqi(UserExtension.deviceId, Device.id))
          .leftJoin(Extension, eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId))
          .where(whereClause),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),
});
