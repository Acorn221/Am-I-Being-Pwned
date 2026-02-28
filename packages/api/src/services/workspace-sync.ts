import { sql } from "drizzle-orm";

import { Extension, Organization, WorkspaceApp, eqi } from "@amibeingpwned/db";
import type { db as DbType } from "@amibeingpwned/db/client";

import { fetchWorkspaceApps } from "../lib/chrome-management";
import { getGoogleAccessToken } from "../lib/google-token";

interface SyncCtx {
  db: typeof DbType;
  userId: string;
  orgId: string;
}

/**
 * Fetches all Chrome extensions from the Google Workspace org associated with
 * the user's Google account, then upserts them into:
 *   1. The global Extension registry (name only — never overwrites risk data)
 *   2. The per-org WorkspaceApp table
 *
 * Designed as a plain async function so it can be called from both the tRPC
 * router and a future Cloudflare cron trigger.
 */
export async function syncWorkspaceApps(
  ctx: SyncCtx,
): Promise<{ count: number; lastSyncedAt: Date }> {
  const accessToken = await getGoogleAccessToken(ctx.db, ctx.userId);

  // Collect all pages from the generator before writing to DB
  const apps: {
    appId: string;
    displayName: string;
    permissions: string[];
    siteAccess: string[];
    installType: string;
    browserDeviceCount: number;
    osUserCount: number;
    description: string;
    homepageUri: string;
    iconUri: string;
  }[] = [];

  for await (const app of fetchWorkspaceApps(accessToken)) {
    apps.push(app);
  }

  if (apps.length > 0) {
    // 1. Upsert global extension registry — set name only if not already set
    await ctx.db
      .insert(Extension)
      .values(
        apps.map((app) => ({
          chromeExtensionId: app.appId,
          name: app.displayName || null,
        })),
      )
      .onConflictDoUpdate({
        target: Extension.chromeExtensionId,
        set: {
          name: sql`COALESCE(${Extension.name}, EXCLUDED.name)`,
          lastUpdatedAt: new Date(),
        },
      });

    // 2. Upsert per-org workspace app inventory
    await ctx.db
      .insert(WorkspaceApp)
      .values(
        apps.map((app) => ({
          orgId: ctx.orgId,
          chromeExtensionId: app.appId,
          displayName: app.displayName || null,
          description: app.description || null,
          homepageUrl: app.homepageUri || null,
          iconUrl: app.iconUri || null,
          permissions: app.permissions,
          siteAccess: app.siteAccess,
          installType: app.installType,
          browserDeviceCount: app.browserDeviceCount,
          osUserCount: app.osUserCount,
          lastSyncedAt: new Date(),
        })),
      )
      .onConflictDoUpdate({
        target: [WorkspaceApp.orgId, WorkspaceApp.chromeExtensionId],
        set: {
          displayName: sql`EXCLUDED.display_name`,
          description: sql`EXCLUDED.description`,
          homepageUrl: sql`EXCLUDED.homepage_url`,
          iconUrl: sql`EXCLUDED.icon_url`,
          permissions: sql`EXCLUDED.permissions`,
          siteAccess: sql`EXCLUDED.site_access`,
          installType: sql`EXCLUDED.install_type`,
          browserDeviceCount: sql`EXCLUDED.browser_device_count`,
          osUserCount: sql`EXCLUDED.os_user_count`,
          lastSyncedAt: new Date(),
          updatedAt: new Date(),
        },
      });
  }

  const lastSyncedAt = new Date();

  await ctx.db
    .update(Organization)
    .set({ lastWorkspaceSyncAt: lastSyncedAt })
    .where(eqi(Organization.id, ctx.orgId));

  return { count: apps.length, lastSyncedAt };
}
