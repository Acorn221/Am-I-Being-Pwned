import { relations, sql } from "drizzle-orm";
import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  unique,
  varchar,
} from "drizzle-orm/pg-core";

import { user } from "./auth-schema";
import { createTable, fk } from "./utils/utils";

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const scanStatusEnum = pgEnum("scan_status", [
  "pending",
  "running",
  "completed",
  "failed",
]);

export const verdictEnum = pgEnum("verdict", [
  "safe",
  "suspicious",
  "malicious",
  "unknown",
]);

export const extensionEventTypeEnum = pgEnum("extension_event_type", [
  "installed",
  "updated",
  "disabled_by_aibp",
  "re_enabled",
  "removed",
  "flagged",
]);

export const alertTypeEnum = pgEnum("alert_type", [
  "update_disabled",
  "threat_detected",
  "scan_complete",
  "new_permissions",
]);

export const severityEnum = pgEnum("severity", ["info", "warning", "critical"]);

export const planEnum = pgEnum("plan", ["free", "pro"]);

export const orgRoleEnum = pgEnum("org_role", ["owner", "admin", "member"]);

export const devicePlatformEnum = pgEnum("device_platform", ["chrome", "edge"]);

// ---------------------------------------------------------------------------
// Multi-tenancy: Organization
// Every enterprise client gets one. B2C personal users don't need one.
// ---------------------------------------------------------------------------

export const Organization = createTable("organization", {
  name: text().notNull(),
  // URL-safe slug used in dashboard routes, e.g. "acme-corp"
  slug: text().notNull().unique(),
  plan: planEnum().notNull().default("free"),
  // Soft-suspend — set to kill all B2B device auth for this org instantly
  suspendedAt: timestamp({ withTimezone: true }),
  suspendedReason: text(),
});

export type Organization = typeof Organization.$inferSelect;

// ---------------------------------------------------------------------------
// Org API Key
// Provisioning credential — IT admin creates one, bakes it into CDM policy.
// NEVER store the raw key. Only the SHA-256 hex hash lives here.
// ---------------------------------------------------------------------------

export const OrgApiKey = createTable(
  "org_api_key",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    name: text().notNull(), // human label, e.g. "Production fleet key"
    // SHA-256 hex of the raw "aibp_org_..." token — plaintext never persisted
    keyHash: text().notNull().unique(),
    createdBy: text("created_by").references(() => user.id, {
      onDelete: "set null",
    }),
    lastUsedAt: timestamp({ withTimezone: true }),
    expiresAt: timestamp({ withTimezone: true }),
    revokedAt: timestamp({ withTimezone: true }),
  },
  (t) => [index("org_api_key_org_id_idx").on(t.orgId)],
);

export type OrgApiKey = typeof OrgApiKey.$inferSelect;

// ---------------------------------------------------------------------------
// Device
// One row per installed extension instance (machine + browser profile).
// B2B: orgId set, userId nullable (employee may not have an AIBP account).
// B2C: orgId null, userId set.
// ---------------------------------------------------------------------------

export const Device = createTable(
  "device",
  {
    // B2B managed device — belongs to an org
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }),
    // B2C personal device — belongs to a user directly
    userId: text("user_id").references(() => user.id, { onDelete: "cascade" }),
    // SHA-256 hex of the raw rotating device token ("aibp_dev_...")
    tokenHash: text().notNull().unique(),
    tokenExpiresAt: timestamp({ withTimezone: true }).notNull(),
    // Previous token kept valid for a short grace period (5 min) after rotation
    // so the extension doesn't get locked out if it receives the new token but
    // crashes before persisting it.
    previousTokenHash: text().unique(),
    previousTokenExpiresAt: timestamp({ withTimezone: true }),
    // Hash of stable machine identifiers — used to detect re-registration
    // so we reuse the existing Device row rather than creating duplicates
    deviceFingerprint: text().notNull(),
    extensionVersion: text().notNull(),
    platform: devicePlatformEnum().notNull().default("chrome"),
    lastSeenAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
    lastSyncAt: timestamp({ withTimezone: true }),
    // Soft revoke — set this to kill a device's access instantly
    revokedAt: timestamp({ withTimezone: true }),
  },
  (t) => [
    index("device_org_id_idx").on(t.orgId),
    index("device_user_id_idx").on(t.userId),
    // Re-registration lookup: find existing device for this org+fingerprint
    index("device_fingerprint_org_idx").on(t.orgId, t.deviceFingerprint),
    // B2C re-registration lookup
    index("device_fingerprint_user_idx").on(t.userId, t.deviceFingerprint),
  ],
);

export type Device = typeof Device.$inferSelect;

// ---------------------------------------------------------------------------
// Org Member
// Links AIBP user accounts to organizations with a role.
// ---------------------------------------------------------------------------

export const OrgMember = createTable(
  "org_member",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: orgRoleEnum().notNull().default("member"),
  },
  (t) => [
    unique().on(t.orgId, t.userId),
    index("org_member_user_id_idx").on(t.userId),
  ],
);

export type OrgMember = typeof OrgMember.$inferSelect;

// ---------------------------------------------------------------------------
// Global extension registry
// One row per Chrome extension (not per version).
// ---------------------------------------------------------------------------

export const Extension = createTable("extension", {
  // Chrome Web Store IDs are always 32-char lowercase alphanumeric
  chromeExtensionId: varchar({ length: 32 }).notNull().unique(),
  name: text(),
  publisher: text(),
  // 0-100 aggregate risk score derived from latest analyzed version
  riskScore: integer().notNull().default(0),
  isFlagged: boolean().notNull().default(false),
  flaggedReason: text(),
  lastUpdatedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
});

export type Extension = typeof Extension.$inferSelect;

// ---------------------------------------------------------------------------
// Extension version snapshot
// ---------------------------------------------------------------------------

export const ExtensionVersion = createTable(
  "extension_version",
  {
    extensionId: fk("extension_id", () => Extension, {
      onDelete: "cascade",
    }).notNull(),
    version: text().notNull(),
    manifestHash: text(),
    permissions: jsonb().$type<string[]>(),
    hostPermissions: jsonb().$type<string[]>(),
    contentScripts: jsonb().$type<Record<string, unknown>[]>(),
    permissionsDiff: jsonb().$type<{ added: string[]; removed: string[] }>(),
    riskScore: integer().notNull().default(0),
    verdict: verdictEnum().notNull().default("unknown"),
    analyzedAt: timestamp({ withTimezone: true }),
    detectedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    unique().on(t.extensionId, t.version),
    index("ext_version_extension_id_idx").on(t.extensionId),
  ],
);

export type ExtensionVersion = typeof ExtensionVersion.$inferSelect;

// ---------------------------------------------------------------------------
// Scan job / result — shared across all users
// ---------------------------------------------------------------------------

export const ExtensionScan = createTable("extension_scan", {
  extensionVersionId: fk("extension_version_id", () => ExtensionVersion, {
    onDelete: "cascade",
  }).notNull(),
  status: scanStatusEnum().notNull().default("pending"),
  findings: jsonb().$type<Record<string, unknown>>(),
  scanner: text(),
  startedAt: timestamp({ withTimezone: true }),
  completedAt: timestamp({ withTimezone: true }),
});

export type ExtensionScan = typeof ExtensionScan.$inferSelect;

// ---------------------------------------------------------------------------
// Per-device extension inventory
// Updated on every sync. deviceId is the primary identity anchor.
// userId is denormalized from device.userId for efficient user-centric queries.
// ---------------------------------------------------------------------------

export const UserExtension = createTable(
  "user_extension",
  {
    deviceId: fk("device_id", () => Device, { onDelete: "cascade" }).notNull(),
    // Denormalized from device.userId — null for B2B without AIBP accounts
    userId: text("user_id").references(() => user.id, {
      onDelete: "set null",
    }),
    chromeExtensionId: varchar({ length: 32 }).notNull(),
    versionAtLastSync: text(),
    enabled: boolean().notNull().default(true),
    disabledByAibp: boolean().notNull().default(false),
    disabledReason: text(),
    lastSeenAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
    removedAt: timestamp({ withTimezone: true }),
  },
  (t) => [
    // Primary uniqueness: one row per (device, extension)
    unique().on(t.deviceId, t.chromeExtensionId),
    index("user_ext_device_id_idx").on(t.deviceId),
    index("user_ext_user_id_idx").on(t.userId),
  ],
);

export type UserExtension = typeof UserExtension.$inferSelect;

// ---------------------------------------------------------------------------
// Extension event audit log (append-only)
// ---------------------------------------------------------------------------

export const UserExtensionEvent = createTable(
  "user_extension_event",
  {
    userExtensionId: fk("user_extension_id", () => UserExtension, {
      onDelete: "cascade",
    }).notNull(),
    eventType: extensionEventTypeEnum().notNull(),
    previousVersion: text(),
    newVersion: text(),
    metadata: jsonb().$type<Record<string, unknown>>(),
  },
  (t) => [
    index("ext_event_user_ext_id_idx").on(t.userExtensionId),
    index("ext_event_created_at_idx").on(t.createdAt),
  ],
);

export type UserExtensionEvent = typeof UserExtensionEvent.$inferSelect;

// ---------------------------------------------------------------------------
// User alerts
// ---------------------------------------------------------------------------

export const UserAlert = createTable(
  "user_alert",
  {
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    extensionId: fk("extension_id", () => Extension, { onDelete: "set null" }),
    alertType: alertTypeEnum().notNull(),
    severity: severityEnum().notNull().default("info"),
    title: text().notNull(),
    body: text().notNull(),
    read: boolean().notNull().default(false),
    dismissed: boolean().notNull().default(false),
  },
  (t) => [index("alert_user_read_idx").on(t.userId, t.read)],
);

export type UserAlert = typeof UserAlert.$inferSelect;

// ---------------------------------------------------------------------------
// User subscription
// ---------------------------------------------------------------------------

export const UserSubscription = createTable("user_subscription", {
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" })
    .unique(),
  plan: planEnum().notNull().default("free"),
  stripeCustomerId: text(),
  stripeSubscriptionId: text(),
  currentPeriodEnd: timestamp({ withTimezone: true }),
  cancelAtPeriodEnd: boolean().notNull().default(false),
});

export type UserSubscription = typeof UserSubscription.$inferSelect;

// ---------------------------------------------------------------------------
// Relations
// ---------------------------------------------------------------------------

export const OrganizationRelations = relations(Organization, ({ many }) => ({
  apiKeys: many(OrgApiKey),
  devices: many(Device),
  members: many(OrgMember),
}));

export const OrgApiKeyRelations = relations(OrgApiKey, ({ one }) => ({
  organization: one(Organization, {
    fields: [OrgApiKey.orgId],
    references: [Organization.id],
  }),
}));

export const DeviceRelations = relations(Device, ({ one, many }) => ({
  organization: one(Organization, {
    fields: [Device.orgId],
    references: [Organization.id],
  }),
  userExtensions: many(UserExtension),
}));

export const OrgMemberRelations = relations(OrgMember, ({ one }) => ({
  organization: one(Organization, {
    fields: [OrgMember.orgId],
    references: [Organization.id],
  }),
}));

export const ExtensionRelations = relations(Extension, ({ many }) => ({
  versions: many(ExtensionVersion),
  alerts: many(UserAlert),
  userExtensions: many(UserExtension),
}));

export const ExtensionVersionRelations = relations(
  ExtensionVersion,
  ({ one, many }) => ({
    extension: one(Extension, {
      fields: [ExtensionVersion.extensionId],
      references: [Extension.id],
    }),
    scans: many(ExtensionScan),
  }),
);

export const ExtensionScanRelations = relations(ExtensionScan, ({ one }) => ({
  extensionVersion: one(ExtensionVersion, {
    fields: [ExtensionScan.extensionVersionId],
    references: [ExtensionVersion.id],
  }),
}));

export const UserExtensionRelations = relations(
  UserExtension,
  ({ one, many }) => ({
    device: one(Device, {
      fields: [UserExtension.deviceId],
      references: [Device.id],
    }),
    events: many(UserExtensionEvent),
  }),
);

export const UserExtensionEventRelations = relations(
  UserExtensionEvent,
  ({ one }) => ({
    userExtension: one(UserExtension, {
      fields: [UserExtensionEvent.userExtensionId],
      references: [UserExtension.id],
    }),
  }),
);

export const UserAlertRelations = relations(UserAlert, ({ one }) => ({
  extension: one(Extension, {
    fields: [UserAlert.extensionId],
    references: [Extension.id],
  }),
}));

// ---------------------------------------------------------------------------
// Zod insert schemas
// ---------------------------------------------------------------------------

import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const CreateExtensionSchema = createInsertSchema(Extension, {
  chromeExtensionId: z.string().regex(/^[a-z]{32}$/, {
    message: "Must be a valid 32-character Chrome extension ID",
  }),
}).omit({ id: true, createdAt: true, updatedAt: true, lastUpdatedAt: true });

export const CreateUserExtensionSchema = createInsertSchema(UserExtension).omit(
  {
    id: true,
    createdAt: true,
    updatedAt: true,
    lastSeenAt: true,
    removedAt: true,
  },
);

// ---------------------------------------------------------------------------
// Re-export auth schema
// ---------------------------------------------------------------------------

export * from "./auth-schema";

// ---------------------------------------------------------------------------
// Placeholder — remove once extension routers replace the post router
// ---------------------------------------------------------------------------

export const Post = pgTable("post", (t) => ({
  id: t.uuid().notNull().primaryKey().defaultRandom(),
  title: t.varchar({ length: 256 }).notNull(),
  content: t.text().notNull(),
  createdAt: t.timestamp().defaultNow().notNull(),
  updatedAt: t
    .timestamp({ mode: "date", withTimezone: true })
    .$onUpdateFn(() => sql`now()`),
}));

export const CreatePostSchema = createInsertSchema(Post, {
  title: z.string().max(256),
  content: z.string().max(256),
}).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
