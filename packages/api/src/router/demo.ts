/**
 * Demo router - sales/demo tool for prospect outreach.
 *
 * Flow:
 *   1. Admin creates a demo link with a label - slug derived from label, e.g. "techcorp-may"
 *   2. Prospect visits /demo/techcorp-may - click recorded
 *   3. Prospect pastes chrome://system extension text
 *   4. Client extracts IDs, calls demo.scan - scan recorded + results returned
 *   5. Prospect sees threat report and can book a call
 */

import { TRPCError } from "@trpc/server";
import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { z } from "zod/v4";

import { DemoLink, DemoScan, Extension } from "@amibeingpwned/db";

import { type Db } from "./devices-helpers";
import { adminProcedure, createTRPCRouter, publicProcedure } from "../trpc";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSlug(label: string): string {
  return label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

async function findActiveLink(db: Db, slug: string) {
  const [row] = await db
    .select()
    .from(DemoLink)
    .where(and(eq(DemoLink.slug, slug), isNull(DemoLink.revokedAt)))
    .limit(1);
  return row ?? null;
}

function scoreToRisk(score: number): string {
  if (score === 0) return "clean";
  if (score < 25) return "low";
  if (score < 50) return "medium";
  if (score < 75) return "high";
  return "critical";
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export const demoRouter = createTRPCRouter({
  /**
   * Called on /demo/:slug page load.
   * Records a click and returns whether the link is valid.
   */
  validateToken: publicProcedure
    .input(z.object({ token: z.string().min(1) }))
    .mutation(async ({ ctx, input }) => {
      const [row] = await ctx.db
        .select({ id: DemoLink.id, label: DemoLink.label, revokedAt: DemoLink.revokedAt })
        .from(DemoLink)
        .where(eq(DemoLink.slug, input.token))
        .limit(1);

      if (!row || row.revokedAt) {
        return { valid: false as const };
      }

      await ctx.db
        .update(DemoLink)
        .set({ clickCount: sql`${DemoLink.clickCount} + 1` })
        .where(eq(DemoLink.id, row.id));

      return { valid: true as const, label: row.label };
    }),

  /**
   * Called when the prospect submits their pasted extension IDs.
   */
  scan: publicProcedure
    .input(
      z.object({
        token: z.string().min(1),
        extensionIds: z
          .array(z.string().regex(/^[a-p]{32}$/))
          .min(1)
          .max(500),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const link = await findActiveLink(ctx.db, input.token);

      if (!link) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Demo link not found or revoked" });
      }

      const known = await ctx.db
        .select({
          chromeExtensionId: Extension.chromeExtensionId,
          name: Extension.name,
          riskScore: Extension.riskScore,
          isFlagged: Extension.isFlagged,
        })
        .from(Extension)
        .where(
          sql`${Extension.chromeExtensionId} = ANY(ARRAY[${sql.join(
            input.extensionIds.map((id) => sql`${id}`),
            sql`, `,
          )}]::text[])`,
        );

      const knownMap = new Map(known.map((e) => [e.chromeExtensionId, e]));

      const extensions = input.extensionIds.map((id) => {
        const ext = knownMap.get(id);
        if (!ext) {
          return {
            id,
            name: null as string | null,
            riskScore: null as number | null,
            risk: "unscanned" as string,
            isFlagged: false,
          };
        }
        return {
          id,
          name: ext.name,
          riskScore: ext.riskScore,
          risk: scoreToRisk(ext.riskScore),
          isFlagged: ext.isFlagged,
        };
      });

      const riskCounts: Record<string, number> = {
        clean: 0,
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
        unscanned: 0,
      };
      for (const ext of extensions) {
        riskCounts[ext.risk] = (riskCounts[ext.risk] ?? 0) + 1;
      }

      await ctx.db.transaction(async (tx) => {
        await tx.insert(DemoScan).values({
          demoLinkId: link.id,
          extensionCount: extensions.length,
          riskCounts,
        });
        await tx
          .update(DemoLink)
          .set({ scanCount: sql`${DemoLink.scanCount} + 1` })
          .where(eq(DemoLink.id, link.id));
      });

      return { extensions, riskCounts };
    }),

  // ---------------------------------------------------------------------------
  // Admin procedures
  // ---------------------------------------------------------------------------

  /**
   * Create a new demo link. Slug is derived from the label.
   * If the slug is already taken, a numeric suffix is appended.
   */
  create: adminProcedure
    .input(z.object({ label: z.string().min(1).max(100) }))
    .mutation(async ({ ctx, input }) => {
      const base = makeSlug(input.label);
      let slug = base;
      let attempt = 2;

      // Find a unique slug
      while (true) {
        const [existing] = await ctx.db
          .select({ id: DemoLink.id })
          .from(DemoLink)
          .where(eq(DemoLink.slug, slug))
          .limit(1);
        if (!existing) break;
        slug = `${base}-${attempt++}`;
      }

      await ctx.db.insert(DemoLink).values({
        slug,
        label: input.label,
        createdBy: ctx.session.user.id,
      });

      return { slug };
    }),

  list: adminProcedure.query(async ({ ctx }) => {
    const rows = await ctx.db
      .select({
        id: DemoLink.id,
        slug: DemoLink.slug,
        label: DemoLink.label,
        clickCount: DemoLink.clickCount,
        scanCount: DemoLink.scanCount,
        createdAt: DemoLink.createdAt,
        revokedAt: DemoLink.revokedAt,
      })
      .from(DemoLink)
      .orderBy(desc(DemoLink.createdAt));
    return rows;
  }),

  revoke: adminProcedure
    .input(z.object({ id: z.string().min(1) }))
    .mutation(async ({ ctx, input }) => {
      const [row] = await ctx.db
        .update(DemoLink)
        .set({ revokedAt: new Date() })
        .where(and(eq(DemoLink.id, input.id), isNull(DemoLink.revokedAt)))
        .returning({ id: DemoLink.id });
      if (!row) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Demo link not found or already revoked" });
      }
      return { ok: true };
    }),
});
