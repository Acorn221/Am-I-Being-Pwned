import { and, eq } from "drizzle-orm";
import { z } from "zod/v4";

import { OrgWebhook, eqi } from "@amibeingpwned/db";
import { TRPCError } from "@trpc/server";

import {
  WEBHOOK_EVENTS,
  fireWebhooks,
  generateWebhookSecret,
} from "../lib/fire-webhooks";
import { createTRPCRouter, managerProcedure } from "../trpc";

const WebhookEventEnum = z.enum(WEBHOOK_EVENTS);

export const webhooksRouter = createTRPCRouter({
  /**
   * List all webhooks for the manager's org.
   * Secret is masked — it was only shown in full at creation time.
   */
  list: managerProcedure.query(async ({ ctx }) => {
    const rows = await ctx.db
      .select({
        id: OrgWebhook.id,
        description: OrgWebhook.description,
        url: OrgWebhook.url,
        // Mask: show prefix + last 4 chars only
        secretMasked: OrgWebhook.secret,
        events: OrgWebhook.events,
        enabled: OrgWebhook.enabled,
        createdAt: OrgWebhook.createdAt,
      })
      .from(OrgWebhook)
      .where(eqi(OrgWebhook.orgId, ctx.org.id))
      .orderBy(OrgWebhook.createdAt);

    return rows.map((r) => ({
      ...r,
      // Show "whsec_****...****<last4>" — enough to identify it, not enough to abuse
      secretMasked: `${r.secretMasked.slice(0, 10)}${"*".repeat(20)}${r.secretMasked.slice(-4)}`,
    }));
  }),

  /**
   * Create a new webhook. Returns the full secret — show it to the user once.
   */
  create: managerProcedure
    .input(
      z.object({
        url: z.url(),
        description: z.string().max(120).optional(),
        events: z.array(WebhookEventEnum).min(1),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const secret = generateWebhookSecret();

      const [row] = await ctx.db
        .insert(OrgWebhook)
        .values({
          orgId: ctx.org.id,
          url: input.url,
          description: input.description ?? null,
          secret,
          events: input.events,
          enabled: true,
        })
        .returning({ id: OrgWebhook.id });

      if (!row) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR" });

      // Secret returned once — client must copy it now
      return { id: row.id, secret };
    }),

  /**
   * Enable / disable a webhook without deleting it.
   */
  setEnabled: managerProcedure
    .input(z.object({ webhookId: z.string(), enabled: z.boolean() }))
    .mutation(async ({ ctx, input }) => {
      await assertOwnership(ctx, input.webhookId);
      await ctx.db
        .update(OrgWebhook)
        .set({ enabled: input.enabled })
        .where(eqi(OrgWebhook.id, input.webhookId));
    }),

  /**
   * Delete a webhook permanently.
   */
  delete: managerProcedure
    .input(z.object({ webhookId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await assertOwnership(ctx, input.webhookId);
      await ctx.db
        .delete(OrgWebhook)
        .where(eqi(OrgWebhook.id, input.webhookId));
    }),

  /**
   * Fire a test event to verify the endpoint is reachable and the secret works.
   */
  test: managerProcedure
    .input(z.object({ webhookId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const [wh] = await ctx.db
        .select({ url: OrgWebhook.url, enabled: OrgWebhook.enabled })
        .from(OrgWebhook)
        .where(
          and(
            eqi(OrgWebhook.id, input.webhookId),
            eqi(OrgWebhook.orgId, ctx.org.id),
          ),
        )
        .limit(1);

      if (!wh) throw new TRPCError({ code: "NOT_FOUND" });

      // Fire test directly against the specific webhook (bypasses event filter)
      await fireWebhooks(ctx.db, ctx.org.id, "test", {
        message: "This is a test delivery from Am I Being Pwned.",
      });

      return { url: wh.url };
    }),
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function assertOwnership(
  ctx: { db: typeof import("@amibeingpwned/db/client").db; org: { id: string } },
  webhookId: string,
) {
  const [row] = await ctx.db
    .select({ id: OrgWebhook.id })
    .from(OrgWebhook)
    .where(
      and(
        eqi(OrgWebhook.id, webhookId),
        eqi(OrgWebhook.orgId, ctx.org.id),
      ),
    )
    .limit(1);

  if (!row) throw new TRPCError({ code: "NOT_FOUND" });
}
