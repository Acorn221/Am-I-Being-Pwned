/**
 * Outbound webhook delivery.
 *
 * Payload signature (Stripe-compatible pattern):
 *   Header: X-AIBP-Signature: t=<unix_ts>,v1=<hmac_sha256_hex>
 *   Signed string: "<timestamp>.<json_body>"
 *
 * Receivers verify with:
 *   const mac = createHmac("sha256", secret)
 *     .update(`${timestamp}.${rawBody}`)
 *     .digest("hex");
 *   const expected = `t=${timestamp},v1=${mac}`;
 *   assert(timingSafeEqual(expected, header));
 */

import { and, eq, sql } from "drizzle-orm";
import { OrgWebhook, eqi } from "@amibeingpwned/db";
import type { db as DbType } from "@amibeingpwned/db/client";

// ─── Event catalogue ─────────────────────────────────────────────────────────

export const WEBHOOK_EVENTS = [
  "threat.detected",
  "alert.created",
  "device.enrolled",
  "test",
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENTS)[number];

export interface WebhookPayloadMap {
  "threat.detected": {
    deviceId: string;
    platform: string;
    threats: {
      extensionName: string | null;
      chromeExtensionId: string;
      riskScore: number;
      flaggedReason: string | null;
    }[];
  };
  "alert.created": {
    alertId: string;
    alertType: string;
    severity: string;
    title: string;
    body: string;
    extensionName?: string | null;
    chromeExtensionId?: string | null;
  };
  "device.enrolled": {
    deviceId: string;
    platform: string;
  };
  test: {
    message: string;
  };
}

// ─── Signing ──────────────────────────────────────────────────────────────────

async function signPayload(
  secret: string,
  timestamp: number,
  body: string,
): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(`${timestamp}.${body}`),
  );
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── Secret generation ────────────────────────────────────────────────────────

export function generateWebhookSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `whsec_${hex}`;
}

// ─── Fire ─────────────────────────────────────────────────────────────────────

/**
 * Fire all enabled webhooks for an org that subscribe to the given event type.
 * Failures are swallowed — fire-and-forget. Does not throw.
 */
export async function fireWebhooks<E extends WebhookEventType>(
  db: typeof DbType,
  orgId: string,
  eventType: E,
  payload: WebhookPayloadMap[E],
): Promise<void> {
  // Fetch enabled webhooks subscribed to this event type.
  // We use a raw SQL fragment for the array-contains check (@>).
  const webhooks = await db
    .select({ id: OrgWebhook.id, url: OrgWebhook.url, secret: OrgWebhook.secret })
    .from(OrgWebhook)
    .where(
      and(
        eqi(OrgWebhook.orgId, orgId),
        eq(OrgWebhook.enabled, true),
        sql`${OrgWebhook.events} @> ARRAY[${eventType}]::text[]`,
      ),
    );

  if (webhooks.length === 0) return;

  const timestamp = Math.floor(Date.now() / 1000);
  const body = JSON.stringify({ event: eventType, timestamp, data: payload });

  await Promise.allSettled(
    webhooks.map(async (wh) => {
      const sig = await signPayload(wh.secret, timestamp, body);
      const deliveryId = crypto.randomUUID();
      try {
        await fetch(wh.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-AIBP-Event": eventType,
            "X-AIBP-Delivery": deliveryId,
            "X-AIBP-Signature": `t=${timestamp},v1=${sig}`,
            "User-Agent": "AmIBeingPwned-Webhooks/1.0",
          },
          body,
          signal: AbortSignal.timeout(10_000),
        });
      } catch {
        console.error(`[webhooks] delivery to ${wh.url} failed (event: ${eventType})`);
      }
    }),
  );
}
