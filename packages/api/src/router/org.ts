/**
 * Org management router.
 *
 * Invite link flow:
 *   - Admin generates a shareable link via `rotateInviteLink`
 *   - Raw token returned once, never stored on the server
 *   - Employees open /join/:token, extension reads it and calls
 *     `devices.registerWithInvite`, no IT involvement required
 */

import { TRPCError } from "@trpc/server";
import { and, asc, eq, isNull } from "drizzle-orm";

import {
  OrgExtensionPolicy,
  OrgExtensionQueue,
  OrgInvite,
  Organization,
} from "@amibeingpwned/db";

import { generateInviteToken, hashToken } from "../lib/tokens";
import {
  createTRPCRouter,
  managerProcedure,
  publicProcedure,
} from "../trpc";
import { z } from "zod/v4";

export const orgRouter = createTRPCRouter({
  /**
   * Returns whether this org has an active (non-revoked) invite link.
   * Used by the dashboard to decide whether to show "Generate" or "Rotate".
   */
  hasInviteLink: managerProcedure.query(async ({ ctx }) => {
    const [row] = await ctx.db
      .select({ id: OrgInvite.id })
      .from(OrgInvite)
      .where(and(eq(OrgInvite.orgId, ctx.org.id), isNull(OrgInvite.revokedAt)))
      .limit(1);

    return { hasActiveLink: !!row };
  }),

  /**
   * Revokes all existing invite links for the org and creates a new one.
   * Returns the raw token, shown once - store securely in component state.
   */
  rotateInviteLink: managerProcedure.mutation(async ({ ctx }) => {
    const now = new Date();

    // Revoke all existing active links
    await ctx.db
      .update(OrgInvite)
      .set({ revokedAt: now })
      .where(
        and(eq(OrgInvite.orgId, ctx.org.id), isNull(OrgInvite.revokedAt)),
      );

    const { raw, hash } = await generateInviteToken();

    await ctx.db.insert(OrgInvite).values({
      orgId: ctx.org.id,
      tokenHash: hash,
      createdBy: ctx.session.user.id,
    });

    return { token: raw };
  }),

  /**
   * Validates an invite token from the join page.
   * Returns the org name so the page can greet the employee.
   * Throws NOT_FOUND if the token is invalid, revoked, or belongs to a
   * suspended org.
   */
  validateInviteToken: publicProcedure
    .input(z.object({ token: z.string() }))
    .query(async ({ ctx, input }) => {
      const tokenHash = await hashToken(input.token);

      const [row] = await ctx.db
        .select({ orgName: Organization.name, suspendedAt: Organization.suspendedAt })
        .from(OrgInvite)
        .innerJoin(Organization, eq(OrgInvite.orgId, Organization.id))
        .where(
          and(eq(OrgInvite.tokenHash, tokenHash), isNull(OrgInvite.revokedAt)),
        )
        .limit(1);

      if (!row) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Invite link is invalid or has been revoked",
        });
      }

      if (row.suspendedAt) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "This organization's account is suspended",
        });
      }

      return { orgName: row.orgName };
    }),

  /**
   * Returns the org's extension policy settings.
   * Returns defaults (empty blocklist, no threshold, blockUnknown off) if no
   * policy row has been saved yet.
   */
  getPolicy: managerProcedure.query(async ({ ctx }) => {
    const [row] = await ctx.db
      .select()
      .from(OrgExtensionPolicy)
      .where(eq(OrgExtensionPolicy.orgId, ctx.org.id))
      .limit(1);

    return row ?? {
      blockedExtensionIds: [] as string[],
      maxRiskLevel: null as string | null,
      blockUnknown: false,
    };
  }),

  /**
   * Saves the org's extension policy. Upserts the row - safe to call on first
   * save (no existing policy row required).
   */
  updatePolicy: managerProcedure
    .input(
      z.object({
        blockedExtensionIds: z.array(z.string().regex(/^[a-p]{32}$/, {
          message: "Each entry must be a valid 32-character Chrome extension ID",
        })).optional(),
        maxRiskLevel: z.enum(["unknown", "clean", "low", "medium", "high", "critical"]).nullable().optional(),
        blockUnknown: z.boolean().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const existing = await ctx.db
        .select({ id: OrgExtensionPolicy.id })
        .from(OrgExtensionPolicy)
        .where(eq(OrgExtensionPolicy.orgId, ctx.org.id))
        .limit(1);

      if (existing.length > 0) {
        await ctx.db
          .update(OrgExtensionPolicy)
          .set({
            ...(input.blockedExtensionIds !== undefined && {
              blockedExtensionIds: input.blockedExtensionIds,
            }),
            ...(input.maxRiskLevel !== undefined && {
              maxRiskLevel: input.maxRiskLevel,
            }),
            ...(input.blockUnknown !== undefined && {
              blockUnknown: input.blockUnknown,
            }),
            updatedBy: ctx.session.user.id,
          })
          .where(eq(OrgExtensionPolicy.orgId, ctx.org.id));
      } else {
        await ctx.db.insert(OrgExtensionPolicy).values({
          orgId: ctx.org.id,
          blockedExtensionIds: input.blockedExtensionIds ?? [],
          maxRiskLevel: input.maxRiskLevel ?? null,
          blockUnknown: input.blockUnknown ?? false,
          updatedBy: ctx.session.user.id,
        });
      }

      return { ok: true };
    }),

  /**
   * Returns the org's extension review queue, paginated.
   * Ordered oldest first so managers work through the backlog in order.
   */
  getQueue: managerProcedure
    .input(
      z.object({
        status: z
          .enum(["pending", "approved", "blocked"])
          .optional()
          .default("pending"),
        limit: z.number().int().min(1).max(100).default(50),
        offset: z.number().int().min(0).default(0),
      }),
    )
    .query(async ({ ctx, input }) => {
      const rows = await ctx.db
        .select()
        .from(OrgExtensionQueue)
        .where(
          and(
            eq(OrgExtensionQueue.orgId, ctx.org.id),
            eq(OrgExtensionQueue.status, input.status),
          ),
        )
        .orderBy(asc(OrgExtensionQueue.createdAt))
        .limit(input.limit)
        .offset(input.offset);

      return rows;
    }),

  /**
   * Approve or reject a queued extension.
   * Approved extensions are removed from the blocklist (if present) so they
   * re-enable on the next device sync.
   * Rejected extensions stay on the blocklist and remain disabled.
   */
  reviewQueueItem: managerProcedure
    .input(
      z.object({
        queueId: z.string(),
        // "override" = approve + add to allowedExtensionIds so auto-rules can't re-block it
        action: z.enum(["approve", "block", "override"]),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const [item] = await ctx.db
        .select()
        .from(OrgExtensionQueue)
        .where(
          and(
            eq(OrgExtensionQueue.id, input.queueId),
            eq(OrgExtensionQueue.orgId, ctx.org.id),
          ),
        )
        .limit(1);

      if (!item) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Queue item not found" });
      }

      const now = new Date();

      await ctx.db
        .update(OrgExtensionQueue)
        .set({
          status: input.action === "block" ? "blocked" : "approved",
          reviewedAt: now,
          reviewedBy: ctx.session.user.id,
        })
        .where(eq(OrgExtensionQueue.id, input.queueId));

      // Approve or override: remove from blocklist so it re-enables next sync
      if (input.action === "approve" || input.action === "override") {
        const [policy] = await ctx.db
          .select({
            blockedExtensionIds: OrgExtensionPolicy.blockedExtensionIds,
            allowedExtensionIds: OrgExtensionPolicy.allowedExtensionIds,
          })
          .from(OrgExtensionPolicy)
          .where(eq(OrgExtensionPolicy.orgId, ctx.org.id))
          .limit(1);

        if (policy) {
          const updatedBlocked = policy.blockedExtensionIds.filter(
            (id) => id !== item.chromeExtensionId,
          );
          const updatedAllowed = input.action === "override"
            ? Array.from(new Set([...policy.allowedExtensionIds, item.chromeExtensionId]))
            : policy.allowedExtensionIds;

          await ctx.db
            .update(OrgExtensionPolicy)
            .set({ blockedExtensionIds: updatedBlocked, allowedExtensionIds: updatedAllowed })
            .where(eq(OrgExtensionPolicy.orgId, ctx.org.id));
        } else if (input.action === "override") {
          await ctx.db.insert(OrgExtensionPolicy).values({
            orgId: ctx.org.id,
            allowedExtensionIds: [item.chromeExtensionId],
          });
        }
      }

      return { ok: true };
    }),

  /**
   * Manually block a specific extension by ID.
   * Adds it to the org's blockedExtensionIds policy and upserts a queue entry
   * with status "blocked" so it's immediately visible in the review queue.
   */
  blockExtension: managerProcedure
    .input(
      z.object({
        chromeExtensionId: z.string().regex(/^[a-p]{32}$/, {
          message: "Must be a valid 32-character Chrome extension ID",
        }),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const now = new Date();

      // Upsert policy row, appending to the blocklist
      const [existing] = await ctx.db
        .select({
          id: OrgExtensionPolicy.id,
          blockedExtensionIds: OrgExtensionPolicy.blockedExtensionIds,
        })
        .from(OrgExtensionPolicy)
        .where(eq(OrgExtensionPolicy.orgId, ctx.org.id))
        .limit(1);

      if (existing) {
        const updated = Array.from(
          new Set([...existing.blockedExtensionIds, input.chromeExtensionId]),
        );
        await ctx.db
          .update(OrgExtensionPolicy)
          .set({ blockedExtensionIds: updated, updatedBy: ctx.session.user.id })
          .where(eq(OrgExtensionPolicy.orgId, ctx.org.id));
      } else {
        await ctx.db.insert(OrgExtensionPolicy).values({
          orgId: ctx.org.id,
          blockedExtensionIds: [input.chromeExtensionId],
          updatedBy: ctx.session.user.id,
        });
      }

      // Upsert queue entry - if it already exists update it to blocked
      await ctx.db
        .insert(OrgExtensionQueue)
        .values({
          orgId: ctx.org.id,
          chromeExtensionId: input.chromeExtensionId,
          reason: "blocklisted",
          status: "blocked",
          reviewedAt: now,
          reviewedBy: ctx.session.user.id,
        })
        .onConflictDoUpdate({
          target: [OrgExtensionQueue.orgId, OrgExtensionQueue.chromeExtensionId],
          set: {
            reason: "blocklisted",
            status: "blocked",
            reviewedAt: now,
            reviewedBy: ctx.session.user.id,
          },
        });

      return { ok: true };
    }),
});
