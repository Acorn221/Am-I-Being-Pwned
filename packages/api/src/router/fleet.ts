import { and, count, countDistinct, desc, eq, isNull, or } from "drizzle-orm";
import { z } from "zod/v4";

import type { db as DbType } from "@amibeingpwned/db/client";
import {
  Device,
  Extension,
  OrgMember,
  Organization,
  UserAlert,
  UserExtension,
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

    const [deviceCountResult, extensionCountResult, flaggedCountResult, unreadAlertResult] =
      await Promise.all([
        ctx.db
          .select({ total: count() })
          .from(Device)
          .where(and(eqi(Device.orgId, orgId), isNull(Device.revokedAt))),

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
      deviceCount: deviceCountResult[0]?.total ?? 0,
      extensionCount: extensionCountResult[0]?.total ?? 0,
      flaggedCount: flaggedCountResult[0]?.total ?? 0,
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
    .input(PaginationSchema)
    .query(async ({ ctx, input }) => {
      const orgId = ctx.org.id;
      const offset = (input.page - 1) * input.limit;

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select({
            id: Device.id,
            platform: Device.platform,
            lastSeenAt: Device.lastSeenAt,
            extensionCount: count(UserExtension.chromeExtensionId),
            flaggedExtensionCount: countDistinct(UserExtension.chromeExtensionId),
          })
          .from(Device)
          .leftJoin(
            UserExtension,
            and(eqi(UserExtension.deviceId, Device.id), isNull(UserExtension.removedAt)),
          )
          .leftJoin(
            Extension,
            and(
              eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId),
              eq(Extension.isFlagged, true),
            ),
          )
          .where(and(eqi(Device.orgId, orgId), isNull(Device.revokedAt)))
          .groupBy(Device.id)
          .orderBy(desc(Device.lastSeenAt))
          .limit(input.limit)
          .offset(offset),

        ctx.db
          .select({ total: count() })
          .from(Device)
          .where(and(eqi(Device.orgId, orgId), isNull(Device.revokedAt))),
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
    .input(PaginationSchema)
    .query(async ({ ctx, input }) => {
      const orgId = ctx.org.id;
      const offset = (input.page - 1) * input.limit;

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select({
            chromeExtensionId: UserExtension.chromeExtensionId,
            name: Extension.name,
            riskScore: Extension.riskScore,
            isFlagged: Extension.isFlagged,
            deviceCount: countDistinct(UserExtension.deviceId),
          })
          .from(UserExtension)
          .innerJoin(Device, eqi(UserExtension.deviceId, Device.id))
          .leftJoin(Extension, eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId))
          .where(
            and(
              eqi(Device.orgId, orgId),
              isNull(Device.revokedAt),
              isNull(UserExtension.removedAt),
            ),
          )
          .groupBy(
            UserExtension.chromeExtensionId,
            Extension.name,
            Extension.riskScore,
            Extension.isFlagged,
          )
          .orderBy(desc(countDistinct(UserExtension.deviceId)))
          .limit(input.limit)
          .offset(offset),

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
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),
});
