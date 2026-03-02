import { relations } from "drizzle-orm";
import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  real,
  smallint,
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

export const riskLevelEnum = pgEnum("risk_level", [
  "unknown",
  "clean",
  "low",
  "medium",
  "high",
  "critical",
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

export const devicePlatformEnum = pgEnum("device_platform", ["chrome", "edge"]);

// ---------------------------------------------------------------------------
// Multi-tenancy: Organization
// ---------------------------------------------------------------------------

export const Organization = createTable("organization", {
  name: text().notNull(),
  slug: text().notNull().unique(),
  plan: planEnum().notNull().default("free"),
  suspendedAt: timestamp({ withTimezone: true }),
  suspendedReason: text(),
  quarantineUnscannedUpdates: boolean().notNull().default(false),
  lastWorkspaceSyncAt: timestamp({ withTimezone: true }),
});

export type Organization = typeof Organization.$inferSelect;

// ---------------------------------------------------------------------------
// Org API Key
// ---------------------------------------------------------------------------

export const OrgApiKey = createTable(
  "org_api_key",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    name: text().notNull(),
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
// ---------------------------------------------------------------------------

export const Device = createTable(
  "device",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }),
    endUserId: fk("end_user_id", () => OrgEndUser, { onDelete: "set null" }),
    tokenHash: text().notNull().unique(),
    tokenExpiresAt: timestamp({ withTimezone: true }).notNull(),
    previousTokenHash: text().unique(),
    previousTokenExpiresAt: timestamp({ withTimezone: true }),
    deviceFingerprint: text().notNull(),
    extensionVersion: text().notNull(),
    platform: devicePlatformEnum("platform").notNull().default("chrome"),
    os: text("os"),
    arch: text("arch"),
    identityEmail: text("identity_email"),
    lastSeenAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
    lastSyncAt: timestamp({ withTimezone: true }),
    revokedAt: timestamp({ withTimezone: true }),
  },
  (t) => [
    index("device_org_id_idx").on(t.orgId),
    index("device_end_user_id_idx").on(t.endUserId),
    index("device_fingerprint_org_idx").on(t.orgId, t.deviceFingerprint),
  ],
);

export type Device = typeof Device.$inferSelect;

// ---------------------------------------------------------------------------
// Device Web Session
// ---------------------------------------------------------------------------

export const DeviceWebSession = createTable(
  "device_web_session",
  {
    deviceId: fk("device_id", () => Device, { onDelete: "cascade" }).notNull(),
    tokenHash: text().notNull().unique(),
    expiresAt: timestamp({ withTimezone: true }).notNull(),
    revokedAt: timestamp({ withTimezone: true }),
  },
  (t) => [index("device_web_session_device_id_idx").on(t.deviceId)],
);

export type DeviceWebSession = typeof DeviceWebSession.$inferSelect;

// ---------------------------------------------------------------------------
// Org Member
// ---------------------------------------------------------------------------

export const OrgMember = createTable(
  "org_member",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: text("role", { enum: ["owner", "admin", "member"] as const })
      .notNull()
      .default("member"),
  },
  (t) => [
    unique().on(t.orgId, t.userId),
    index("org_member_user_id_idx").on(t.userId),
  ],
);

export type OrgMember = typeof OrgMember.$inferSelect;

// ---------------------------------------------------------------------------
// Org End User
// ---------------------------------------------------------------------------

export const OrgEndUser = createTable(
  "org_end_user",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    email: text().notNull(),
  },
  (t) => [
    unique().on(t.orgId, t.email),
    index("org_end_user_org_id_idx").on(t.orgId),
  ],
);

export type OrgEndUser = typeof OrgEndUser.$inferSelect;

// ---------------------------------------------------------------------------
// Global extension registry
// One row per Chrome extension (not per version).
// riskLevel is the aggregate verdict derived from the latest analyzed version.
// ---------------------------------------------------------------------------

export const Extension = createTable("extension", {
  chromeExtensionId: varchar({ length: 32 }).notNull().unique(),
  name: text(),
  publisher: text(),
  riskLevel: riskLevelEnum().notNull().default("unknown"),
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
    riskLevel: riskLevelEnum().notNull().default("unknown"),
    // Short verdict summary populated after LLM analysis
    summary: text(),
    // e.g. ["data_exfiltration", "remote_config", "keylogging"]
    flagCategories: text("flag_categories").array().notNull().default([]),
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
// Scan job - tracks async scan pipeline state per version
// ---------------------------------------------------------------------------

export const ExtensionScan = createTable("extension_scan", {
  extensionVersionId: fk("extension_version_id", () => ExtensionVersion, {
    onDelete: "cascade",
  }).notNull(),
  status: scanStatusEnum().notNull().default("pending"),
  scanner: text(),
  startedAt: timestamp({ withTimezone: true }),
  completedAt: timestamp({ withTimezone: true }),
});

export type ExtensionScan = typeof ExtensionScan.$inferSelect;

// ---------------------------------------------------------------------------
// LLM analysis report
// One row per (extensionVersion, reportType). Primary type is "llm_analysis".
// ---------------------------------------------------------------------------

export const ExtensionAnalysisReport = createTable(
  "extension_analysis_report",
  {
    extensionVersionId: fk("extension_version_id", () => ExtensionVersion, {
      onDelete: "cascade",
    }).notNull(),
    reportType: text("report_type", {
      enum: ["llm_analysis", "vuln_report"] as const,
    })
      .notNull()
      .default("llm_analysis"),
    // Full markdown report content
    content: text().notNull(),
    // 1-2 sentence verdict
    summary: text(),
    riskLevel: riskLevelEnum().notNull().default("unknown"),
    flagCategories: text("flag_categories").array().notNull().default([]),
    vulnCountLow: smallint("vuln_count_low").notNull().default(0),
    vulnCountMedium: smallint("vuln_count_medium").notNull().default(0),
    vulnCountHigh: smallint("vuln_count_high").notNull().default(0),
    vulnCountCritical: smallint("vuln_count_critical").notNull().default(0),
    // External domains the extension contacts
    endpoints: text("endpoints").array().notNull().default([]),
    // Whether this report can be shown publicly on the website
    canPublish: boolean("can_publish").notNull().default(true),
    analyzedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    unique().on(t.extensionVersionId, t.reportType),
    index("analysis_report_version_id_idx").on(t.extensionVersionId),
  ],
);

export type ExtensionAnalysisReport =
  typeof ExtensionAnalysisReport.$inferSelect;

// ---------------------------------------------------------------------------
// Static/AST analysis result (Babel analyzer output)
// One row per (extensionVersion, analyzerVersion).
// ---------------------------------------------------------------------------

export const ExtensionStaticAnalysis = createTable(
  "extension_static_analysis",
  {
    extensionVersionId: fk("extension_version_id", () => ExtensionVersion, {
      onDelete: "cascade",
    }).notNull(),
    analyzerVersion: text("analyzer_version").notNull(),
    // 0-100 raw score from the analyzer (distinct from the normalized riskLevel enum)
    riskScore: integer("risk_score").notNull(),
    criticalCount: integer("critical_count").notNull().default(0),
    highCount: integer("high_count").notNull().default(0),
    mediumCount: integer("medium_count").notNull().default(0),
    lowCount: integer("low_count").notNull().default(0),
    // Data flows from sensitive source to network sink
    exfilFlows: integer("exfil_flows").notNull().default(0),
    // Flows reaching eval / Function / executeScript
    codeExecFlows: integer("code_exec_flows").notNull().default(0),
    totalFlowPaths: integer("total_flow_paths").notNull().default(0),
    openMessageHandlers: integer("open_message_handlers").notNull().default(0),
    hasWasm: boolean("has_wasm").notNull().default(false),
    hasObfuscation: boolean("has_obfuscation").notNull().default(false),
    filesAnalyzed: integer("files_analyzed").notNull().default(0),
    analysisTimeMs: integer("analysis_time_ms"),
    // Full structured output from the analyzer
    rawReport: jsonb("raw_report").$type<Record<string, unknown>>(),
    analyzedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    unique().on(t.extensionVersionId, t.analyzerVersion),
    index("static_analysis_version_id_idx").on(t.extensionVersionId),
  ],
);

export type ExtensionStaticAnalysis =
  typeof ExtensionStaticAnalysis.$inferSelect;

// ---------------------------------------------------------------------------
// VirusTotal scan result
// One row per (extensionVersion, sha256) - a version's zip may be re-submitted.
// ---------------------------------------------------------------------------

export const ExtensionVtResult = createTable(
  "extension_vt_result",
  {
    extensionVersionId: fk("extension_version_id", () => ExtensionVersion, {
      onDelete: "cascade",
    }).notNull(),
    sha256: varchar({ length: 64 }).notNull(),
    malicious: integer().notNull().default(0),
    suspicious: integer().notNull().default(0),
    undetected: integer().notNull().default(0),
    harmless: integer().notNull().default(0),
    totalEngines: integer("total_engines").notNull().default(0),
    // malicious / totalEngines
    detectionRatio: real("detection_ratio").notNull().default(0),
    status: text({ enum: ["found", "not_found", "unknown"] as const })
      .notNull()
      .default("unknown"),
    rawResponse: jsonb("raw_response").$type<Record<string, unknown>>(),
    scannedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    unique().on(t.extensionVersionId, t.sha256),
    index("vt_result_version_id_idx").on(t.extensionVersionId),
  ],
);

export type ExtensionVtResult = typeof ExtensionVtResult.$inferSelect;

// ---------------------------------------------------------------------------
// Per-device extension inventory
// ---------------------------------------------------------------------------

export const UserExtension = createTable(
  "user_extension",
  {
    deviceId: fk("device_id", () => Device, { onDelete: "cascade" }).notNull(),
    chromeExtensionId: varchar({ length: 32 }).notNull(),
    versionAtLastSync: text(),
    enabled: boolean().notNull().default(true),
    disabledByAibp: boolean().notNull().default(false),
    disabledReason: text(),
    lastSeenAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
    removedAt: timestamp({ withTimezone: true }),
  },
  (t) => [
    unique().on(t.deviceId, t.chromeExtensionId),
    index("user_ext_device_id_idx").on(t.deviceId),
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
// Org Invite
// ---------------------------------------------------------------------------

export const OrgInvite = createTable(
  "org_invite",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    tokenHash: text().notNull().unique(),
    createdBy: text("created_by").references(() => user.id, {
      onDelete: "set null",
    }),
    usedCount: integer().notNull().default(0),
    revokedAt: timestamp({ withTimezone: true }),
  },
  (t) => [index("org_invite_org_id_idx").on(t.orgId)],
);

export type OrgInvite = typeof OrgInvite.$inferSelect;

// ---------------------------------------------------------------------------
// Org Extension Policy
// ---------------------------------------------------------------------------

export const OrgExtensionPolicy = createTable(
  "org_extension_policy",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" })
      .notNull()
      .unique(),
    blockedExtensionIds: jsonb("blocked_extension_ids")
      .$type<string[]>()
      .notNull()
      .default([]),
    allowedExtensionIds: jsonb("allowed_extension_ids")
      .$type<string[]>()
      .notNull()
      .default([]),
    // Auto-disable any extension at or above this risk level (null = disabled)
    maxRiskLevel: riskLevelEnum("max_risk_level"),
    blockUnknown: boolean("block_unknown").notNull().default(false),
    updatedBy: text("updated_by").references(() => user.id, {
      onDelete: "set null",
    }),
  },
  (t) => [index("org_ext_policy_org_id_idx").on(t.orgId)],
);

export type OrgExtensionPolicy = typeof OrgExtensionPolicy.$inferSelect;

// ---------------------------------------------------------------------------
// Org Extension Queue
// ---------------------------------------------------------------------------

export const OrgExtensionQueue = createTable(
  "org_extension_queue",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    chromeExtensionId: varchar("chrome_extension_id", { length: 32 }).notNull(),
    reason: text("reason", {
      enum: ["unknown", "risk_threshold", "blocklisted"] as const,
    }).notNull(),
    status: text("status", {
      enum: ["pending", "approved", "blocked"] as const,
    })
      .notNull()
      .default("pending"),
    extensionName: text("extension_name"),
    // Risk level snapshot at time of queueing
    riskLevel: riskLevelEnum("risk_level"),
    reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
    reviewedBy: text("reviewed_by").references(() => user.id, {
      onDelete: "set null",
    }),
  },
  (t) => [
    unique().on(t.orgId, t.chromeExtensionId),
    index("org_ext_queue_org_id_idx").on(t.orgId),
  ],
);

export type OrgExtensionQueue = typeof OrgExtensionQueue.$inferSelect;

// ---------------------------------------------------------------------------
// Org Webhook
// ---------------------------------------------------------------------------

export const OrgWebhook = createTable(
  "org_webhook",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    description: text(),
    url: text().notNull(),
    secret: text().notNull(),
    events: text("events").array().notNull().default([]),
    enabled: boolean().notNull().default(true),
  },
  (t) => [index("org_webhook_org_id_idx").on(t.orgId)],
);

export type OrgWebhook = typeof OrgWebhook.$inferSelect;

// ---------------------------------------------------------------------------
// Workspace extension inventory (Google Chrome Management API)
// ---------------------------------------------------------------------------

export const WorkspaceApp = createTable(
  "workspace_app",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    chromeExtensionId: varchar({ length: 32 }).notNull(),
    displayName: text(),
    description: text(),
    homepageUrl: text(),
    iconUrl: text(),
    permissions: jsonb().$type<string[]>(),
    siteAccess: jsonb().$type<string[]>(),
    installType: text(),
    browserDeviceCount: integer().notNull().default(0),
    osUserCount: integer().notNull().default(0),
    source: text({ enum: ["oauth", "ext"] as const }).notNull().default("oauth"),
    lastSyncedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    unique().on(t.orgId, t.chromeExtensionId),
    index("workspace_app_org_id_idx").on(t.orgId),
  ],
);

export type WorkspaceApp = typeof WorkspaceApp.$inferSelect;

// ---------------------------------------------------------------------------
// Workspace device inventory (Google Chrome Management API)
// ---------------------------------------------------------------------------

export const WorkspaceDevice = createTable(
  "workspace_device",
  {
    orgId: fk("org_id", () => Organization, { onDelete: "cascade" }).notNull(),
    googleDeviceId: text().notNull(),
    machineName: text(),
    extensionCount: integer().notNull().default(0),
    lastSyncedAt: timestamp({ withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    unique().on(t.orgId, t.googleDeviceId),
    index("workspace_device_org_id_idx").on(t.orgId),
  ],
);

export type WorkspaceDevice = typeof WorkspaceDevice.$inferSelect;

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
// Demo Links
// ---------------------------------------------------------------------------

export const DemoLink = createTable(
  "demo_link",
  {
    slug: text().notNull().unique(),
    label: text().notNull(),
    createdBy: text("created_by").references(() => user.id, {
      onDelete: "set null",
    }),
    revokedAt: timestamp({ withTimezone: true }),
    clickCount: integer().notNull().default(0),
    scanCount: integer().notNull().default(0),
  },
  (t) => [index("demo_link_slug_idx").on(t.slug)],
);

export type DemoLink = typeof DemoLink.$inferSelect;

// ---------------------------------------------------------------------------
// Demo Scan
// ---------------------------------------------------------------------------

export const DemoScan = createTable(
  "demo_scan",
  {
    demoLinkId: fk("demo_link_id", () => DemoLink, {
      onDelete: "cascade",
    }).notNull(),
    extensionCount: integer().notNull(),
    riskCounts: jsonb()
      .$type<Record<string, number>>()
      .notNull()
      .default({}),
  },
  (t) => [index("demo_scan_demo_link_id_idx").on(t.demoLinkId)],
);

export type DemoScan = typeof DemoScan.$inferSelect;

// ---------------------------------------------------------------------------
// Relations
// ---------------------------------------------------------------------------

export const OrganizationRelations = relations(Organization, ({ one, many }) => ({
  apiKeys: many(OrgApiKey),
  devices: many(Device),
  invites: many(OrgInvite),
  members: many(OrgMember),
  webhooks: many(OrgWebhook),
  workspaceApps: many(WorkspaceApp),
  workspaceDevices: many(WorkspaceDevice),
  extensionPolicy: one(OrgExtensionPolicy, {
    fields: [Organization.id],
    references: [OrgExtensionPolicy.orgId],
  }),
  extensionQueue: many(OrgExtensionQueue),
}));

export const WorkspaceAppRelations = relations(WorkspaceApp, ({ one }) => ({
  organization: one(Organization, {
    fields: [WorkspaceApp.orgId],
    references: [Organization.id],
  }),
}));

export const WorkspaceDeviceRelations = relations(WorkspaceDevice, ({ one }) => ({
  organization: one(Organization, {
    fields: [WorkspaceDevice.orgId],
    references: [Organization.id],
  }),
}));

export const OrgWebhookRelations = relations(OrgWebhook, ({ one }) => ({
  organization: one(Organization, {
    fields: [OrgWebhook.orgId],
    references: [Organization.id],
  }),
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
    analysisReports: many(ExtensionAnalysisReport),
    staticAnalyses: many(ExtensionStaticAnalysis),
    vtResults: many(ExtensionVtResult),
  }),
);

export const ExtensionScanRelations = relations(ExtensionScan, ({ one }) => ({
  extensionVersion: one(ExtensionVersion, {
    fields: [ExtensionScan.extensionVersionId],
    references: [ExtensionVersion.id],
  }),
}));

export const ExtensionAnalysisReportRelations = relations(
  ExtensionAnalysisReport,
  ({ one }) => ({
    extensionVersion: one(ExtensionVersion, {
      fields: [ExtensionAnalysisReport.extensionVersionId],
      references: [ExtensionVersion.id],
    }),
  }),
);

export const ExtensionStaticAnalysisRelations = relations(
  ExtensionStaticAnalysis,
  ({ one }) => ({
    extensionVersion: one(ExtensionVersion, {
      fields: [ExtensionStaticAnalysis.extensionVersionId],
      references: [ExtensionVersion.id],
    }),
  }),
);

export const ExtensionVtResultRelations = relations(
  ExtensionVtResult,
  ({ one }) => ({
    extensionVersion: one(ExtensionVersion, {
      fields: [ExtensionVtResult.extensionVersionId],
      references: [ExtensionVersion.id],
    }),
  }),
);

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

export const OrgExtensionPolicyRelations = relations(
  OrgExtensionPolicy,
  ({ one }) => ({
    organization: one(Organization, {
      fields: [OrgExtensionPolicy.orgId],
      references: [Organization.id],
    }),
  }),
);

export const OrgExtensionQueueRelations = relations(
  OrgExtensionQueue,
  ({ one }) => ({
    organization: one(Organization, {
      fields: [OrgExtensionQueue.orgId],
      references: [Organization.id],
    }),
  }),
);

export const UserAlertRelations = relations(UserAlert, ({ one }) => ({
  extension: one(Extension, {
    fields: [UserAlert.extensionId],
    references: [Extension.id],
  }),
}));

export const DemoLinkRelations = relations(DemoLink, ({ many }) => ({
  scans: many(DemoScan),
}));

export const DemoScanRelations = relations(DemoScan, ({ one }) => ({
  demoLink: one(DemoLink, {
    fields: [DemoScan.demoLinkId],
    references: [DemoLink.id],
  }),
}));

// ---------------------------------------------------------------------------
// Zod insert schemas
// ---------------------------------------------------------------------------

import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const CreateExtensionSchema = createInsertSchema(Extension, {
  chromeExtensionId: z.string().regex(/^[a-p]{32}$/, {
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
