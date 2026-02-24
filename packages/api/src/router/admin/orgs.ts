import { TRPCError } from "@trpc/server";
import { and, count, desc, eq, ilike, isNotNull, isNull, or } from "drizzle-orm";
import { z } from "zod/v4";

import {
  Device,
  OrgApiKey,
  OrgMember,
  Organization,
  eqi,
  user,
} from "@amibeingpwned/db";

import { generateOrgApiKey } from "../../lib/tokens";
import { adminProcedure, createTRPCRouter } from "../../trpc";

const PaginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

export const adminOrgsRouter = createTRPCRouter({
  list: adminProcedure
    .input(
      PaginationSchema.extend({
        search: z.string().optional(),
        plan: z.enum(["free", "pro"]).optional(),
        isSuspended: z.boolean().optional(),
      }),
    )
    .query(async ({ ctx, input }) => {
      const offset = (input.page - 1) * input.limit;

      const where = and(
        input.search
          ? or(
              ilike(Organization.name, `%${input.search}%`),
              ilike(Organization.slug, `%${input.search}%`),
            )
          : undefined,
        input.plan !== undefined ? eq(Organization.plan, input.plan) : undefined,
        input.isSuspended !== undefined
          ? input.isSuspended
            ? isNotNull(Organization.suspendedAt)
            : isNull(Organization.suspendedAt)
          : undefined,
      );

      const [rows, totalResult] = await Promise.all([
        ctx.db
          .select()
          .from(Organization)
          .where(where)
          .orderBy(desc(Organization.createdAt))
          .limit(input.limit)
          .offset(offset),
        ctx.db.select({ total: count() }).from(Organization).where(where),
      ]);

      return {
        rows,
        total: totalResult[0]?.total ?? 0,
        page: input.page,
        limit: input.limit,
      };
    }),

  get: adminProcedure
    .input(z.object({ orgId: z.string() }))
    .query(async ({ ctx, input }) => {
      const [org] = await ctx.db
        .select()
        .from(Organization)
        .where(eqi(Organization.id, input.orgId))
        .limit(1);

      if (!org) throw new TRPCError({ code: "NOT_FOUND" });

      const [apiKeys, members, deviceCountResult] = await Promise.all([
        ctx.db
          .select({
            id: OrgApiKey.id,
            name: OrgApiKey.name,
            // Expose only a short prefix — never expose the full hash
            keyHashPrefix: OrgApiKey.keyHash,
            createdAt: OrgApiKey.createdAt,
            lastUsedAt: OrgApiKey.lastUsedAt,
            expiresAt: OrgApiKey.expiresAt,
            revokedAt: OrgApiKey.revokedAt,
          })
          .from(OrgApiKey)
          .where(eqi(OrgApiKey.orgId, org.id))
          .orderBy(desc(OrgApiKey.createdAt)),
        ctx.db
          .select({
            id: OrgMember.id,
            userId: OrgMember.userId,
            role: OrgMember.role,
            email: user.email,
            name: user.name,
          })
          .from(OrgMember)
          // OrgMember.userId is a plain text FK to the auth user table — use eq
          .innerJoin(user, eq(OrgMember.userId, user.id))
          .where(eqi(OrgMember.orgId, org.id)),
        ctx.db
          .select({ total: count() })
          .from(Device)
          .where(and(eqi(Device.orgId, org.id), isNull(Device.revokedAt))),
      ]);

      return {
        org,
        apiKeys: apiKeys.map((k) => ({
          ...k,
          // Truncate the stored hash to a short prefix for display only
          keyHashPrefix: k.keyHashPrefix.slice(0, 8) + "…",
        })),
        members,
        activeDeviceCount: deviceCountResult[0]?.total ?? 0,
      };
    }),

  setPlan: adminProcedure
    .input(
      z.object({
        orgId: z.string(),
        plan: z.enum(["free", "pro"]),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Organization)
        .set({ plan: input.plan })
        .where(eqi(Organization.id, input.orgId));
    }),

  setQuarantinePolicy: adminProcedure
    .input(
      z.object({
        orgId: z.string(),
        enabled: z.boolean(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Organization)
        .set({ quarantineUnscannedUpdates: input.enabled })
        .where(eqi(Organization.id, input.orgId));
    }),

  suspend: adminProcedure
    .input(
      z.object({
        orgId: z.string(),
        reason: z.string().min(1),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Organization)
        .set({ suspendedAt: new Date(), suspendedReason: input.reason })
        .where(eqi(Organization.id, input.orgId));
    }),

  unsuspend: adminProcedure
    .input(z.object({ orgId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .update(Organization)
        .set({ suspendedAt: null, suspendedReason: null })
        .where(eqi(Organization.id, input.orgId));
    }),

  revokeAllDevices: adminProcedure
    .input(z.object({ orgId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const revoked = await ctx.db
        .update(Device)
        .set({ revokedAt: new Date() })
        .where(and(eqi(Device.orgId, input.orgId), isNull(Device.revokedAt)))
        .returning({ id: Device.id });

      return { revokedCount: revoked.length };
    }),

  /**
   * Revokes the current API key and issues a replacement.
   * The raw key is returned exactly once — it must be stored by the caller.
   */
  rotateApiKey: adminProcedure
    .input(
      z.object({
        apiKeyId: z.string(),
        newName: z.string().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const [existing] = await ctx.db
        .select({ id: OrgApiKey.id, orgId: OrgApiKey.orgId, name: OrgApiKey.name })
        .from(OrgApiKey)
        .where(eqi(OrgApiKey.id, input.apiKeyId))
        .limit(1);

      if (!existing) throw new TRPCError({ code: "NOT_FOUND" });

      await ctx.db
        .update(OrgApiKey)
        .set({ revokedAt: new Date() })
        .where(eqi(OrgApiKey.id, existing.id));

      const { raw, hash } = await generateOrgApiKey();

      await ctx.db.insert(OrgApiKey).values({
        orgId: existing.orgId,
        name: input.newName ?? existing.name,
        keyHash: hash,
        createdBy: ctx.session.user.id,
      });

      // Return raw once — it is never persisted and cannot be retrieved again
      return { rawKey: raw };
    }),
});
