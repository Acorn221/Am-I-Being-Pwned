import { sql } from "drizzle-orm";

import {
  Extension,
  Organization,
  WorkspaceApp,
  WorkspaceDevice,
  eqi,
} from "@amibeingpwned/db";
import type { db as DbType } from "@amibeingpwned/db/client";

import { fetchDevicesForApp, fetchWorkspaceApps } from "../lib/chrome-management";
import { getGoogleAccessToken } from "../lib/google-token";

interface SyncCtx {
  db: typeof DbType;
  userId: string;
  orgId: string;
}

/**
 * Fetches all Chrome extensions and enrolled devices from the Google Workspace
 * org associated with the user's account, then upserts them into:
 *   1. The global Extension registry (name only — never overwrites risk data)
 *   2. The per-org WorkspaceApp table (source='oauth')
 *   3. The per-org WorkspaceDevice table (one row per unique enrolled browser)
 *
 * Designed as a plain async function so it can be called from both the tRPC
 * router and a future Cloudflare cron trigger.
 */
export async function syncWorkspaceApps(
  ctx: SyncCtx,
): Promise<{ appCount: number; deviceCount: number; lastSyncedAt: Date }> {
  const accessToken = await getGoogleAccessToken(ctx.db, ctx.userId);

  // ── 1. Collect all extensions ─────────────────────────────────────────────

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

  // ── 2. Collect unique devices across all extensions ───────────────────────
  // deviceId → { machine, extensionCount }
  const deviceMap = new Map<string, { machine: string; extensionCount: number }>();

  for (const app of apps) {
    try {
      for await (const device of fetchDevicesForApp(accessToken, app.appId)) {
        const existing = deviceMap.get(device.deviceId);
        if (existing) {
          existing.extensionCount++;
        } else {
          deviceMap.set(device.deviceId, {
            machine: device.machine,
            extensionCount: 1,
          });
        }
      }
    } catch {
      // If a single app's device lookup fails, keep going — don't abort the whole sync
    }
  }

  // ── 3. Write to DB ────────────────────────────────────────────────────────

  const syncedAt = new Date();

  if (apps.length > 0) {
    // Upsert global extension registry — set name only if not already set
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
          lastUpdatedAt: syncedAt,
        },
      });

    // Upsert per-org workspace app inventory
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
          source: "oauth" as const,
          lastSyncedAt: syncedAt,
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
          source: "oauth" as const,
          lastSyncedAt: syncedAt,
          updatedAt: syncedAt,
        },
      });
  }

  if (deviceMap.size > 0) {
    const deviceValues = Array.from(deviceMap.entries()).map(
      ([deviceId, { machine, extensionCount }]) => ({
        orgId: ctx.orgId,
        googleDeviceId: deviceId,
        machineName: machine || null,
        extensionCount,
        lastSyncedAt: syncedAt,
      }),
    );

    await ctx.db
      .insert(WorkspaceDevice)
      .values(deviceValues)
      .onConflictDoUpdate({
        target: [WorkspaceDevice.orgId, WorkspaceDevice.googleDeviceId],
        set: {
          machineName: sql`EXCLUDED.machine_name`,
          extensionCount: sql`EXCLUDED.extension_count`,
          lastSyncedAt: syncedAt,
          updatedAt: syncedAt,
        },
      });
  }

  await ctx.db
    .update(Organization)
    .set({ lastWorkspaceSyncAt: syncedAt })
    .where(eqi(Organization.id, ctx.orgId));

  return {
    appCount: apps.length,
    deviceCount: deviceMap.size,
    lastSyncedAt: syncedAt,
  };
}
