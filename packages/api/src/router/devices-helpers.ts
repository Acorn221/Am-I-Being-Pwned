import { TRPCError } from "@trpc/server";
import { and, eq, gt, isNull, or } from "drizzle-orm";
import { z } from "zod/v4";

import type { db as dbInstance } from "@amibeingpwned/db/client";
import {
  OrgApiKey,
  OrgEndUser,
  eqi,
} from "@amibeingpwned/db";

import { hashToken } from "../lib/tokens";

export type Db = typeof dbInstance;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Grace period after token rotation — old hash stays valid for this long. */
export const TOKEN_GRACE_MS = 5 * 60 * 1000; // 5 minutes

/** Hard cap on extensions per sync payload. A real device won't have more. */
export const MAX_EXTENSIONS_PER_SYNC = 500;

/**
 * Per-org device limit.
 * Enterprise clients on a paid plan will need this raised — tie to plan later.
 * TODO: move this to DB
 */
export const MAX_DEVICES_PER_ORG = 1000;

// ---------------------------------------------------------------------------
// Shared input schemas
// ---------------------------------------------------------------------------

export const ExtensionEntrySchema = z.object({
  chromeExtensionId: z
    .string()
    .regex(/^[a-z]{32}$/, "Must be a valid Chrome extension ID"),
  version: z.string(),
  enabled: z.boolean(),
  name: z.string().optional(),
});

export const RegisterInputSchema = z.object({
  deviceFingerprint: z.string().min(1),
  extensionVersion: z.string(),
  platform: z.enum(["chrome", "edge"]).default("chrome"),
  os: z.string().max(32).optional(),
  arch: z.string().max(32).optional(),
  identityEmail: z.string().email().max(320).optional(),
});

// ---------------------------------------------------------------------------
// Helper: validate an org API key from the request header and return the orgId
// ---------------------------------------------------------------------------

export async function resolveOrgApiKey(db: Db, headers: Headers): Promise<string> {
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
// Helper: upsert an OrgEndUser from identityEmail and return its id.
// Called from both B2B registration flows after the device row is resolved.
// ---------------------------------------------------------------------------

export async function upsertEndUser(
  db: Db,
  orgId: string,
  email: string,
): Promise<string | null> {
  await db
    .insert(OrgEndUser)
    .values({ orgId, email })
    .onConflictDoNothing();
  const [row] = await db
    .select({ id: OrgEndUser.id })
    .from(OrgEndUser)
    .where(and(eqi(OrgEndUser.orgId, orgId), eq(OrgEndUser.email, email)))
    .limit(1);
  return row?.id ?? null;
}
