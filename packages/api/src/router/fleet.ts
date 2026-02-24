import { and, count, countDistinct, desc, eq, isNull, or } from "drizzle-orm";
import { z } from "zod/v4";

import {
  Device,
  Extension,
  OrgMember,
  Organization,
  UserAlert,
  UserExtension,
  eqi,
} from "@amibeingpwned/db";

import { createTRPCRouter, managerProcedure, protectedProcedure } from "../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

export const fleetRouter = createTRPCRouter({
  /**
   * High-level stats for the manager's organisation.
   * Returns null (HTTP 200) when the user is not a manager — avoids a 401
   * console error for regular users on every dashboard load.
   */
  overview: protectedProcedure.query(async ({ ctx }) => {
    const userId = ctx.session.user.id;

    // Check org membership — must be owner or admin
    const [membership] = await ctx.db
      .select({
        orgId: OrgMember.orgId,
        orgRole: OrgMember.role,
        orgName: Organization.name,
        orgPlan: Organization.plan,
        orgSuspendedAt: Organization.suspendedAt,
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
          .innerJoin(
            Extension,
            eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId),
          )
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
      },
      deviceCount: deviceCountResult[0]?.total ?? 0,
      extensionCount: extensionCountResult[0]?.total ?? 0,
      flaggedCount: flaggedCountResult[0]?.total ?? 0,
      unreadAlertCount: unreadAlertResult[0]?.total ?? 0,
    };
  }),

  /**
   * Paginated list of devices belonging to the manager's org.
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
            flaggedExtensionCount: countDistinct(
              // count distinct flagged extension IDs
              UserExtension.chromeExtensionId,
            ),
          })
          .from(Device)
          .leftJoin(
            UserExtension,
            and(
              eqi(UserExtension.deviceId, Device.id),
              isNull(UserExtension.removedAt),
            ),
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
          .leftJoin(
            Extension,
            eq(UserExtension.chromeExtensionId, Extension.chromeExtensionId),
          )
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
