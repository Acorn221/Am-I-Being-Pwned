import { relations } from "drizzle-orm";
import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
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
  // Override updatedAt semantics: this tracks Chrome Store updates specifically
  lastUpdatedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
});

export type Extension = typeof Extension.$inferSelect;

// ---------------------------------------------------------------------------
// Extension version snapshot
// Captured whenever the extension syncs a new version. The permissionsDiff
// is the KEY threat signal — new host_permissions on update = red flag.
// ---------------------------------------------------------------------------

export const ExtensionVersion = createTable(
  "extension_version",
  {
    extensionId: fk("extension_id", () => Extension, {
      onDelete: "cascade",
    }).notNull(),
    version: text().notNull(),
    // SHA-256 of raw manifest.json — any change means something structural changed
    manifestHash: text(),
    permissions: jsonb().$type<string[]>(),
    hostPermissions: jsonb().$type<string[]>(),
    contentScripts: jsonb().$type<Record<string, unknown>[]>(),
    // Delta from the PREVIOUS version — populated during analysis
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
// Scan job / result
// Shared across all users — one scan per extension version. Your engine
// populates findings and flips status to completed.
// ---------------------------------------------------------------------------

export const ExtensionScan = createTable("extension_scan", {
  extensionVersionId: fk("extension_version_id", () => ExtensionVersion, {
    onDelete: "cascade",
  }).notNull(),
  status: scanStatusEnum().notNull().default("pending"),
  // Arbitrary findings blob — structured by your engine
  findings: jsonb().$type<Record<string, unknown>>(),
  // Engine identifier + version so you can re-scan with newer engines
  scanner: text(),
  startedAt: timestamp({ withTimezone: true }),
  completedAt: timestamp({ withTimezone: true }),
});

export type ExtensionScan = typeof ExtensionScan.$inferSelect;

// ---------------------------------------------------------------------------
// Per-user extension inventory
// Updated on every sync from the extension.
// ---------------------------------------------------------------------------

export const UserExtension = createTable(
  "user_extension",
  {
    // FK to better-auth user (text ID) — cannot use fk() helper here
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    chromeExtensionId: varchar({ length: 32 }).notNull(),
    versionAtLastSync: text(),
    enabled: boolean().notNull().default(true),
    // Did AIBP instruct the browser to disable this extension pending a scan?
    disabledByAibp: boolean().notNull().default(false),
    disabledReason: text(),
    lastSeenAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
    // Soft delete — set when user uninstalls the extension
    removedAt: timestamp({ withTimezone: true }),
  },
  (t) => [
    unique().on(t.userId, t.chromeExtensionId),
    index("user_ext_user_id_idx").on(t.userId),
  ],
);

export type UserExtension = typeof UserExtension.$inferSelect;

// ---------------------------------------------------------------------------
// Extension event audit log (append-only)
// Forensic record — never update or delete rows here.
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
    // Any extra context: scan ID, reason string, source, etc.
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
    // Nullable — some alerts aren't tied to a specific extension
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
// One row per user. Free plan is default, pro unlocks continuous monitoring.
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
  ({ many }) => ({
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
// Zod insert schemas (derived from Drizzle tables via drizzle-zod)
// ---------------------------------------------------------------------------

import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const CreateExtensionSchema = createInsertSchema(Extension, {
  chromeExtensionId: z.string().regex(/^[a-z]{32}$/, {
    message: "Must be a valid 32-character Chrome extension ID",
  }),
}).omit({ id: true, createdAt: true, updatedAt: true, lastUpdatedAt: true });

export const CreateUserExtensionSchema = createInsertSchema(UserExtension).omit(
  { id: true, createdAt: true, updatedAt: true, lastSeenAt: true, removedAt: true },
);

// ---------------------------------------------------------------------------
// Re-export auth schema so packages/db exposes everything from one place
// ---------------------------------------------------------------------------

export * from "./auth-schema";

// ---------------------------------------------------------------------------
// Placeholder — remove once extension routers replace the post router
// ---------------------------------------------------------------------------

import { sql } from "drizzle-orm";
import { pgTable } from "drizzle-orm/pg-core";

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
