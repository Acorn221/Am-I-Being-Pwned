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
import { and, eq, isNull } from "drizzle-orm";

import { OrgInvite, Organization } from "@amibeingpwned/db";

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
});
