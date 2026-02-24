/**
 * Device registration and sync router.
 *
 * Registration flows:
 *   B2C  — user is logged in (protectedProcedure), device binds to userId
 *   B2B  — enterprise extension sends org API key in `x-org-api-key` header,
 *           device binds to orgId
 *
 * After registration the extension receives a short-lived device token
 * ("aibp_dev_…") which it uses for all subsequent sync calls.
 *
 * Sync flow (deviceProcedure):
 *   1. Upsert the full extension inventory for this device
 *   2. Queue scan jobs for any extension versions not yet analyzed
 *   3. Return the current disable-list (extensions flagged malicious/suspicious)
 *   4. Rotate the device token — old hash kept valid for TOKEN_GRACE_MS so the
 *      extension is never permanently locked out by a mid-rotation crash
 */

import { TRPCError } from "@trpc/server";
import { and, count, eq, gt, inArray, isNull, notInArray, or } from "drizzle-orm";
import { z } from "zod/v4";

import type { db as dbInstance } from "@amibeingpwned/db/client";
import {
  Device,
  Extension,
  ExtensionScan,
  ExtensionVersion,
  OrgApiKey,
  UserExtension,
  UserExtensionEvent,
} from "@amibeingpwned/db";

import { generateDeviceToken, hashToken } from "../lib/tokens";
import { deviceProcedure } from "../middleware/device-auth";
import { createTRPCRouter, protectedProcedure, publicProcedure } from "../trpc";

type Db = typeof dbInstance;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Grace period after token rotation — old hash stays valid for this long. */
const TOKEN_GRACE_MS = 5 * 60 * 1000; // 5 minutes

/** Hard cap on extensions per sync payload. A real device won't have more. */
const MAX_EXTENSIONS_PER_SYNC = 500;

/**
 * Per-user device limit (free tier).
 * Prevents DB exhaustion if a session token is leaked or abused.
 */
const MAX_DEVICES_PER_USER = 10;

/**
 * Per-org device limit.
 * Enterprise clients on a paid plan will need this raised — tie to plan later.
 */
const MAX_DEVICES_PER_ORG = 1000;

// ---------------------------------------------------------------------------
// Shared input schemas
// ---------------------------------------------------------------------------

const ExtensionEntrySchema = z.object({
  chromeExtensionId: z
    .string()
    .regex(/^[a-z]{32}$/, "Must be a valid Chrome extension ID"),
  version: z.string(),
  enabled: z.boolean(),
  name: z.string().optional(),
});

const RegisterInputSchema = z.object({
  deviceFingerprint: z.string().min(1),
  extensionVersion: z.string(),
  platform: z.enum(["chrome", "edge"]).default("chrome"),
});

// ---------------------------------------------------------------------------
// Helper: validate an org API key from the request header and return the orgId
// ---------------------------------------------------------------------------

async function resolveOrgApiKey(db: Db, headers: Headers): Promise<string> {
  const raw = headers.get("x-org-api-key");
  if (!raw?.startsWith("aibp_org_")) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "Missing or invalid org API key",
    });
  }

  const keyHash = await hashToken(raw);
  const now = new Date();

  const [apiKey] = await db
    .select({ id: OrgApiKey.id, orgId: OrgApiKey.orgId })
    .from(OrgApiKey)
    .where(
      and(
        eq(OrgApiKey.keyHash, keyHash),
        isNull(OrgApiKey.revokedAt),
        // Treat null expiresAt as "never expires"; reject explicitly expired keys
        or(isNull(OrgApiKey.expiresAt), gt(OrgApiKey.expiresAt, now)),
      ),
    )
    .limit(1);

  if (!apiKey) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "Org API key is invalid, expired, or revoked",
    });
  }

  // Audit: record when this key was last used
  await db
    .update(OrgApiKey)
    .set({ lastUsedAt: now })
    .where(eq(OrgApiKey.id, apiKey.id));

  return apiKey.orgId;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export const devicesRouter = createTRPCRouter({
  /**
   * B2C registration — requires an active user session.
   * Creates (or re-uses) a Device row tied to the authenticated user and
   * returns a fresh device token.
   */
  registerB2C: protectedProcedure
    .input(RegisterInputSchema)
    .mutation(async ({ ctx, input }) => {
      const userId = ctx.session.user.id;
      const { raw, hash, expiresAt } = await generateDeviceToken();

      // Re-use existing device for this user+fingerprint to avoid duplicates
      const [existing] = await ctx.db
        .select({ id: Device.id })
        .from(Device)
        .where(
          and(
            eq(Device.userId, userId),
            eq(Device.deviceFingerprint, input.deviceFingerprint),
            isNull(Device.revokedAt),
          ),
        )
        .limit(1);

      if (existing) {
        await ctx.db
          .update(Device)
          .set({
            tokenHash: hash,
            tokenExpiresAt: expiresAt,
            extensionVersion: input.extensionVersion,
            platform: input.platform,
            lastSeenAt: new Date(),
          })
          .where(eq(Device.id, existing.id));

        return { deviceToken: raw };
      }

      // Enforce device cap before inserting a new row
      const countResult = await ctx.db
        .select({ deviceCount: count() })
        .from(Device)
        .where(and(eq(Device.userId, userId), isNull(Device.revokedAt)));

      if ((countResult[0]?.deviceCount ?? 0) >= MAX_DEVICES_PER_USER) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: `Device limit reached (max ${MAX_DEVICES_PER_USER}). Revoke an existing device first.`,
        });
      }

      await ctx.db.insert(Device).values({
        userId,
        tokenHash: hash,
        tokenExpiresAt: expiresAt,
        deviceFingerprint: input.deviceFingerprint,
        extensionVersion: input.extensionVersion,
        platform: input.platform,
      });

      return { deviceToken: raw };
    }),

  /**
   * B2B registration — enterprise extension sends its org API key.
   * No user session required; device binds to the org.
   */
  registerB2B: publicProcedure
    .input(RegisterInputSchema)
    .mutation(async ({ ctx, input }) => {
      const orgId = await resolveOrgApiKey(ctx.db, ctx.headers);
      const { raw, hash, expiresAt } = await generateDeviceToken();

      const [existing] = await ctx.db
        .select({ id: Device.id })
        .from(Device)
        .where(
          and(
            eq(Device.orgId, orgId),
            eq(Device.deviceFingerprint, input.deviceFingerprint),
            isNull(Device.revokedAt),
          ),
        )
        .limit(1);

      if (existing) {
        await ctx.db
          .update(Device)
          .set({
            tokenHash: hash,
            tokenExpiresAt: expiresAt,
            extensionVersion: input.extensionVersion,
            platform: input.platform,
            lastSeenAt: new Date(),
          })
          .where(eq(Device.id, existing.id));

        return { deviceToken: raw };
      }

      // Enforce device cap before inserting a new row
      const orgCountResult = await ctx.db
        .select({ deviceCount: count() })
        .from(Device)
        .where(and(eq(Device.orgId, orgId), isNull(Device.revokedAt)));

      if ((orgCountResult[0]?.deviceCount ?? 0) >= MAX_DEVICES_PER_ORG) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: `Org device limit reached (max ${MAX_DEVICES_PER_ORG}). Contact support to raise the limit.`,
        });
      }

      await ctx.db.insert(Device).values({
        orgId,
        tokenHash: hash,
        tokenExpiresAt: expiresAt,
        deviceFingerprint: input.deviceFingerprint,
        extensionVersion: input.extensionVersion,
        platform: input.platform,
      });

      return { deviceToken: raw };
    }),

  /**
   * Extension inventory sync.
   *
   * The extension calls this periodically (and on every update event).
   * Returns:
   *   - disableList: extension IDs that should be disabled
   *   - newToken:    rotated device token (replace the stored one immediately)
   */
  sync: deviceProcedure
    .input(
      z.object({
        extensions: z.array(ExtensionEntrySchema).max(MAX_EXTENSIONS_PER_SYNC),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const { device } = ctx;
      const now = new Date();

      // -----------------------------------------------------------------------
      // 1. Upsert extensions into the global registry
      // -----------------------------------------------------------------------

      for (const ext of input.extensions) {
        // Upsert the Extension row (global registry)
        await ctx.db
          .insert(Extension)
          .values({
            chromeExtensionId: ext.chromeExtensionId,
            name: ext.name ?? null,
            lastUpdatedAt: now,
          })
          .onConflictDoUpdate({
            target: Extension.chromeExtensionId,
            set: {
              name: ext.name ?? undefined,
              lastUpdatedAt: now,
            },
          });

        // Fetch the extension row to get its UUID id
        const [extensionRow] = await ctx.db
          .select({ id: Extension.id })
          .from(Extension)
          .where(eq(Extension.chromeExtensionId, ext.chromeExtensionId))
          .limit(1);

        if (!extensionRow) continue;

        // Upsert version snapshot
        const [versionRow] = await ctx.db
          .insert(ExtensionVersion)
          .values({
            extensionId: extensionRow.id,
            version: ext.version,
          })
          .onConflictDoNothing()
          .returning({ id: ExtensionVersion.id, analyzedAt: ExtensionVersion.analyzedAt });

        // Queue a scan job for this version if not yet analyzed
        if (versionRow && !versionRow.analyzedAt) {
          await ctx.db
            .insert(ExtensionScan)
            .values({ extensionVersionId: versionRow.id })
            .onConflictDoNothing();
        }

        // Upsert per-device inventory row
        const [existingUE] = await ctx.db
          .select({
            id: UserExtension.id,
            versionAtLastSync: UserExtension.versionAtLastSync,
            disabledByAibp: UserExtension.disabledByAibp,
          })
          .from(UserExtension)
          .where(
            and(
              eq(UserExtension.deviceId, device.id),
              eq(UserExtension.chromeExtensionId, ext.chromeExtensionId),
            ),
          )
          .limit(1);

        if (existingUE) {
          const versionChanged = existingUE.versionAtLastSync !== ext.version;

          await ctx.db
            .update(UserExtension)
            .set({
              versionAtLastSync: ext.version,
              // If we've forcibly disabled this extension, don't let the
              // extension re-enable it by reporting enabled: true in a sync.
              enabled: existingUE.disabledByAibp ? false : ext.enabled,
              lastSeenAt: now,
              removedAt: null,
            })
            .where(eq(UserExtension.id, existingUE.id));

          if (versionChanged) {
            await ctx.db.insert(UserExtensionEvent).values({
              userExtensionId: existingUE.id,
              eventType: "updated",
              previousVersion: existingUE.versionAtLastSync ?? undefined,
              newVersion: ext.version,
            });
          }
        } else {
          const [newUE] = await ctx.db
            .insert(UserExtension)
            .values({
              deviceId: device.id,
              userId: device.userId ?? undefined,
              chromeExtensionId: ext.chromeExtensionId,
              versionAtLastSync: ext.version,
              enabled: ext.enabled,
              lastSeenAt: now,
            })
            .returning({ id: UserExtension.id });

          if (newUE) {
            await ctx.db.insert(UserExtensionEvent).values({
              userExtensionId: newUE.id,
              eventType: "installed",
              newVersion: ext.version,
            });
          }
        }
      }

      // -----------------------------------------------------------------------
      // 2. Mark extensions no longer present as removed
      // -----------------------------------------------------------------------

      const reportedIds = input.extensions.map((e) => e.chromeExtensionId);

      if (reportedIds.length > 0) {
        const removed = await ctx.db
          .update(UserExtension)
          .set({ removedAt: now })
          .where(
            and(
              eq(UserExtension.deviceId, device.id),
              notInArray(UserExtension.chromeExtensionId, reportedIds),
              isNull(UserExtension.removedAt),
            ),
          )
          .returning({ id: UserExtension.id });

        for (const ue of removed) {
          await ctx.db.insert(UserExtensionEvent).values({
            userExtensionId: ue.id,
            eventType: "removed",
          });
        }
      }

      // -----------------------------------------------------------------------
      // 3. Build the disable list and persist enforcement state
      // -----------------------------------------------------------------------

      const disableList: string[] = [];

      if (reportedIds.length > 0) {
        const flagged = await ctx.db
          .select({ chromeExtensionId: Extension.chromeExtensionId })
          .from(Extension)
          .where(
            and(
              inArray(Extension.chromeExtensionId, reportedIds),
              eq(Extension.isFlagged, true),
            ),
          );

        disableList.push(...flagged.map((f) => f.chromeExtensionId));
      }

      // Persist the disabledByAibp flag so future syncs keep enforcement even
      // if the global isFlagged state changes (e.g. a false-positive is cleared
      // after the extension was already disabled on this device).
      if (disableList.length > 0) {
        await ctx.db
          .update(UserExtension)
          .set({
            disabledByAibp: true,
            disabledReason: "Extension flagged as malicious or suspicious",
            enabled: false,
          })
          .where(
            and(
              eq(UserExtension.deviceId, device.id),
              inArray(UserExtension.chromeExtensionId, disableList),
            ),
          );
      }

      // -----------------------------------------------------------------------
      // 4. Rotate the device token with a grace period on the old one
      //
      //    The previous token stays valid for TOKEN_GRACE_MS so the extension
      //    isn't permanently locked out if it receives the new token but crashes
      //    (or loses the response) before storing it.
      // -----------------------------------------------------------------------

      const { raw: newRaw, hash: newHash, expiresAt: newExpiry } = await generateDeviceToken();
      const gracePeriodExpiry = new Date(now.getTime() + TOKEN_GRACE_MS);

      await ctx.db
        .update(Device)
        .set({
          previousTokenHash: device.tokenHash,
          previousTokenExpiresAt: gracePeriodExpiry,
          tokenHash: newHash,
          tokenExpiresAt: newExpiry,
          lastSeenAt: now,
          lastSyncAt: now,
        })
        .where(eq(Device.id, device.id));

      return {
        disableList,
        newToken: newRaw,
      };
    }),
});
