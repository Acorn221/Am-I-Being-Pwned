CREATE TYPE "public"."alert_type" AS ENUM('update_disabled', 'threat_detected', 'scan_complete', 'new_permissions');--> statement-breakpoint
CREATE TYPE "public"."device_platform" AS ENUM('chrome', 'edge');--> statement-breakpoint
CREATE TYPE "public"."extension_event_type" AS ENUM('installed', 'updated', 'disabled_by_aibp', 're_enabled', 'removed', 'flagged');--> statement-breakpoint
CREATE TYPE "public"."plan" AS ENUM('free', 'pro');--> statement-breakpoint
CREATE TYPE "public"."risk_level" AS ENUM('unknown', 'clean', 'low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."scan_status" AS ENUM('pending', 'running', 'completed', 'failed');--> statement-breakpoint
CREATE TYPE "public"."severity" AS ENUM('info', 'warning', 'critical');--> statement-breakpoint
CREATE TABLE "demo_link" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"slug" text NOT NULL,
	"label" text NOT NULL,
	"created_by" text,
	"revoked_at" timestamp with time zone,
	"click_count" integer DEFAULT 0 NOT NULL,
	"scan_count" integer DEFAULT 0 NOT NULL,
	CONSTRAINT "demo_link_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "demo_scan" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"demo_link_id" uuid NOT NULL,
	"extension_count" integer NOT NULL,
	"risk_counts" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "device" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid,
	"end_user_id" uuid,
	"token_hash" text NOT NULL,
	"token_expires_at" timestamp with time zone NOT NULL,
	"previous_token_hash" text,
	"previous_token_expires_at" timestamp with time zone,
	"device_fingerprint" text NOT NULL,
	"extension_version" text NOT NULL,
	"platform" "device_platform" DEFAULT 'chrome' NOT NULL,
	"os" text,
	"arch" text,
	"identity_email" text,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_sync_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "device_tokenHash_unique" UNIQUE("token_hash"),
	CONSTRAINT "device_previousTokenHash_unique" UNIQUE("previous_token_hash")
);
--> statement-breakpoint
CREATE TABLE "device_web_session" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"device_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "device_web_session_tokenHash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "extension" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"chrome_extension_id" varchar(32) NOT NULL,
	"name" text,
	"publisher" text,
	"risk_level" "risk_level" DEFAULT 'unknown' NOT NULL,
	"is_flagged" boolean DEFAULT false NOT NULL,
	"flagged_reason" text,
	"last_updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "extension_chromeExtensionId_unique" UNIQUE("chrome_extension_id")
);
--> statement-breakpoint
CREATE TABLE "extension_analysis_report" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"extension_version_id" uuid NOT NULL,
	"report_type" text DEFAULT 'llm_analysis' NOT NULL,
	"content" text NOT NULL,
	"summary" text,
	"risk_level" "risk_level" DEFAULT 'unknown' NOT NULL,
	"flag_categories" text[] DEFAULT '{}' NOT NULL,
	"vuln_count_low" smallint DEFAULT 0 NOT NULL,
	"vuln_count_medium" smallint DEFAULT 0 NOT NULL,
	"vuln_count_high" smallint DEFAULT 0 NOT NULL,
	"vuln_count_critical" smallint DEFAULT 0 NOT NULL,
	"endpoints" text[] DEFAULT '{}' NOT NULL,
	"can_publish" boolean DEFAULT true NOT NULL,
	"analyzed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "extension_analysis_report_extension_version_id_report_type_unique" UNIQUE("extension_version_id","report_type")
);
--> statement-breakpoint
CREATE TABLE "extension_scan" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"extension_version_id" uuid NOT NULL,
	"status" "scan_status" DEFAULT 'pending' NOT NULL,
	"scanner" text,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "extension_static_analysis" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"extension_version_id" uuid NOT NULL,
	"analyzer_version" text NOT NULL,
	"risk_score" integer NOT NULL,
	"critical_count" integer DEFAULT 0 NOT NULL,
	"high_count" integer DEFAULT 0 NOT NULL,
	"medium_count" integer DEFAULT 0 NOT NULL,
	"low_count" integer DEFAULT 0 NOT NULL,
	"exfil_flows" integer DEFAULT 0 NOT NULL,
	"code_exec_flows" integer DEFAULT 0 NOT NULL,
	"total_flow_paths" integer DEFAULT 0 NOT NULL,
	"open_message_handlers" integer DEFAULT 0 NOT NULL,
	"has_wasm" boolean DEFAULT false NOT NULL,
	"has_obfuscation" boolean DEFAULT false NOT NULL,
	"files_analyzed" integer DEFAULT 0 NOT NULL,
	"analysis_time_ms" integer,
	"raw_report" jsonb,
	"analyzed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "extension_static_analysis_extension_version_id_analyzer_version_unique" UNIQUE("extension_version_id","analyzer_version")
);
--> statement-breakpoint
CREATE TABLE "extension_version" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"extension_id" uuid NOT NULL,
	"version" text NOT NULL,
	"manifest_hash" text,
	"permissions" jsonb,
	"host_permissions" jsonb,
	"content_scripts" jsonb,
	"permissions_diff" jsonb,
	"risk_level" "risk_level" DEFAULT 'unknown' NOT NULL,
	"summary" text,
	"flag_categories" text[] DEFAULT '{}' NOT NULL,
	"analyzed_at" timestamp with time zone,
	"detected_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "extension_version_extension_id_version_unique" UNIQUE("extension_id","version")
);
--> statement-breakpoint
CREATE TABLE "extension_vt_result" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"extension_version_id" uuid NOT NULL,
	"sha256" varchar(64) NOT NULL,
	"malicious" integer DEFAULT 0 NOT NULL,
	"suspicious" integer DEFAULT 0 NOT NULL,
	"undetected" integer DEFAULT 0 NOT NULL,
	"harmless" integer DEFAULT 0 NOT NULL,
	"total_engines" integer DEFAULT 0 NOT NULL,
	"detection_ratio" real DEFAULT 0 NOT NULL,
	"status" text DEFAULT 'unknown' NOT NULL,
	"raw_response" jsonb,
	"scanned_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "extension_vt_result_extension_version_id_sha256_unique" UNIQUE("extension_version_id","sha256")
);
--> statement-breakpoint
CREATE TABLE "org_api_key" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"name" text NOT NULL,
	"key_hash" text NOT NULL,
	"created_by" text,
	"last_used_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "org_api_key_keyHash_unique" UNIQUE("key_hash")
);
--> statement-breakpoint
CREATE TABLE "org_end_user" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"email" text NOT NULL,
	CONSTRAINT "org_end_user_org_id_email_unique" UNIQUE("org_id","email")
);
--> statement-breakpoint
CREATE TABLE "org_extension_policy" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"blocked_extension_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_extension_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"max_risk_level" "risk_level",
	"block_unknown" boolean DEFAULT false NOT NULL,
	"updated_by" text,
	CONSTRAINT "org_extension_policy_org_id_unique" UNIQUE("org_id")
);
--> statement-breakpoint
CREATE TABLE "org_extension_queue" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"chrome_extension_id" varchar(32) NOT NULL,
	"reason" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"extension_name" text,
	"risk_level" "risk_level",
	"reviewed_at" timestamp with time zone,
	"reviewed_by" text,
	CONSTRAINT "org_extension_queue_org_id_chrome_extension_id_unique" UNIQUE("org_id","chrome_extension_id")
);
--> statement-breakpoint
CREATE TABLE "org_invite" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"created_by" text,
	"used_count" integer DEFAULT 0 NOT NULL,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "org_invite_tokenHash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "org_member" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"user_id" text NOT NULL,
	"role" text DEFAULT 'member' NOT NULL,
	CONSTRAINT "org_member_org_id_user_id_unique" UNIQUE("org_id","user_id")
);
--> statement-breakpoint
CREATE TABLE "org_webhook" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"description" text,
	"url" text NOT NULL,
	"secret" text NOT NULL,
	"events" text[] DEFAULT '{}' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organization" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"name" text NOT NULL,
	"slug" text NOT NULL,
	"plan" "plan" DEFAULT 'free' NOT NULL,
	"suspended_at" timestamp with time zone,
	"suspended_reason" text,
	"quarantine_unscanned_updates" boolean DEFAULT false NOT NULL,
	"last_workspace_sync_at" timestamp with time zone,
	CONSTRAINT "organization_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "user_alert" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"user_id" text NOT NULL,
	"extension_id" uuid,
	"alert_type" "alert_type" NOT NULL,
	"severity" "severity" DEFAULT 'info' NOT NULL,
	"title" text NOT NULL,
	"body" text NOT NULL,
	"read" boolean DEFAULT false NOT NULL,
	"dismissed" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_extension" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"device_id" uuid NOT NULL,
	"chrome_extension_id" varchar(32) NOT NULL,
	"version_at_last_sync" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"disabled_by_aibp" boolean DEFAULT false NOT NULL,
	"disabled_reason" text,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"removed_at" timestamp with time zone,
	CONSTRAINT "user_extension_device_id_chromeExtensionId_unique" UNIQUE("device_id","chrome_extension_id")
);
--> statement-breakpoint
CREATE TABLE "user_extension_event" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"user_extension_id" uuid NOT NULL,
	"event_type" "extension_event_type" NOT NULL,
	"previous_version" text,
	"new_version" text,
	"metadata" jsonb
);
--> statement-breakpoint
CREATE TABLE "user_subscription" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"user_id" text NOT NULL,
	"plan" "plan" DEFAULT 'free' NOT NULL,
	"stripe_customer_id" text,
	"stripe_subscription_id" text,
	"current_period_end" timestamp with time zone,
	"cancel_at_period_end" boolean DEFAULT false NOT NULL,
	CONSTRAINT "user_subscription_user_id_unique" UNIQUE("user_id")
);
--> statement-breakpoint
CREATE TABLE "workspace_app" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"chrome_extension_id" varchar(32) NOT NULL,
	"display_name" text,
	"description" text,
	"homepage_url" text,
	"icon_url" text,
	"permissions" jsonb,
	"site_access" jsonb,
	"install_type" text,
	"browser_device_count" integer DEFAULT 0 NOT NULL,
	"os_user_count" integer DEFAULT 0 NOT NULL,
	"source" text DEFAULT 'oauth' NOT NULL,
	"last_synced_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "workspace_app_org_id_chromeExtensionId_unique" UNIQUE("org_id","chrome_extension_id")
);
--> statement-breakpoint
CREATE TABLE "workspace_device" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"google_device_id" text NOT NULL,
	"machine_name" text,
	"extension_count" integer DEFAULT 0 NOT NULL,
	"last_synced_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "workspace_device_org_id_googleDeviceId_unique" UNIQUE("org_id","google_device_id")
);
--> statement-breakpoint
CREATE TABLE "account" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"provider_id" text NOT NULL,
	"user_id" text NOT NULL,
	"access_token" text,
	"refresh_token" text,
	"id_token" text,
	"access_token_expires_at" timestamp,
	"refresh_token_expires_at" timestamp,
	"scope" text,
	"password" text,
	"created_at" timestamp NOT NULL,
	"updated_at" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "session" (
	"id" text PRIMARY KEY NOT NULL,
	"expires_at" timestamp NOT NULL,
	"token" text NOT NULL,
	"created_at" timestamp NOT NULL,
	"updated_at" timestamp NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"user_id" text NOT NULL,
	CONSTRAINT "session_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE "user" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"email" text NOT NULL,
	"email_verified" boolean NOT NULL,
	"image" text,
	"role" text DEFAULT 'user' NOT NULL,
	"created_at" timestamp NOT NULL,
	"updated_at" timestamp NOT NULL,
	CONSTRAINT "user_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "verification" (
	"id" text PRIMARY KEY NOT NULL,
	"identifier" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp,
	"updated_at" timestamp
);
--> statement-breakpoint
ALTER TABLE "demo_link" ADD CONSTRAINT "demo_link_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "demo_scan" ADD CONSTRAINT "demo_scan_demo_link_id_demo_link_id_fk" FOREIGN KEY ("demo_link_id") REFERENCES "public"."demo_link"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device" ADD CONSTRAINT "device_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device" ADD CONSTRAINT "device_end_user_id_org_end_user_id_fk" FOREIGN KEY ("end_user_id") REFERENCES "public"."org_end_user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_web_session" ADD CONSTRAINT "device_web_session_device_id_device_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."device"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "extension_analysis_report" ADD CONSTRAINT "extension_analysis_report_extension_version_id_extension_version_id_fk" FOREIGN KEY ("extension_version_id") REFERENCES "public"."extension_version"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "extension_scan" ADD CONSTRAINT "extension_scan_extension_version_id_extension_version_id_fk" FOREIGN KEY ("extension_version_id") REFERENCES "public"."extension_version"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "extension_static_analysis" ADD CONSTRAINT "extension_static_analysis_extension_version_id_extension_version_id_fk" FOREIGN KEY ("extension_version_id") REFERENCES "public"."extension_version"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "extension_version" ADD CONSTRAINT "extension_version_extension_id_extension_id_fk" FOREIGN KEY ("extension_id") REFERENCES "public"."extension"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "extension_vt_result" ADD CONSTRAINT "extension_vt_result_extension_version_id_extension_version_id_fk" FOREIGN KEY ("extension_version_id") REFERENCES "public"."extension_version"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_api_key" ADD CONSTRAINT "org_api_key_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_api_key" ADD CONSTRAINT "org_api_key_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_end_user" ADD CONSTRAINT "org_end_user_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_extension_policy" ADD CONSTRAINT "org_extension_policy_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_extension_policy" ADD CONSTRAINT "org_extension_policy_updated_by_user_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_extension_queue" ADD CONSTRAINT "org_extension_queue_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_extension_queue" ADD CONSTRAINT "org_extension_queue_reviewed_by_user_id_fk" FOREIGN KEY ("reviewed_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_invite" ADD CONSTRAINT "org_invite_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_invite" ADD CONSTRAINT "org_invite_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_member" ADD CONSTRAINT "org_member_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_member" ADD CONSTRAINT "org_member_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_webhook" ADD CONSTRAINT "org_webhook_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_alert" ADD CONSTRAINT "user_alert_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_alert" ADD CONSTRAINT "user_alert_extension_id_extension_id_fk" FOREIGN KEY ("extension_id") REFERENCES "public"."extension"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_extension" ADD CONSTRAINT "user_extension_device_id_device_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."device"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_extension_event" ADD CONSTRAINT "user_extension_event_user_extension_id_user_extension_id_fk" FOREIGN KEY ("user_extension_id") REFERENCES "public"."user_extension"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_subscription" ADD CONSTRAINT "user_subscription_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_app" ADD CONSTRAINT "workspace_app_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workspace_device" ADD CONSTRAINT "workspace_device_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "account" ADD CONSTRAINT "account_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "demo_link_slug_idx" ON "demo_link" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "demo_scan_demo_link_id_idx" ON "demo_scan" USING btree ("demo_link_id");--> statement-breakpoint
CREATE INDEX "device_org_id_idx" ON "device" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "device_end_user_id_idx" ON "device" USING btree ("end_user_id");--> statement-breakpoint
CREATE INDEX "device_fingerprint_org_idx" ON "device" USING btree ("org_id","device_fingerprint");--> statement-breakpoint
CREATE INDEX "device_web_session_device_id_idx" ON "device_web_session" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "analysis_report_version_id_idx" ON "extension_analysis_report" USING btree ("extension_version_id");--> statement-breakpoint
CREATE INDEX "static_analysis_version_id_idx" ON "extension_static_analysis" USING btree ("extension_version_id");--> statement-breakpoint
CREATE INDEX "ext_version_extension_id_idx" ON "extension_version" USING btree ("extension_id");--> statement-breakpoint
CREATE INDEX "vt_result_version_id_idx" ON "extension_vt_result" USING btree ("extension_version_id");--> statement-breakpoint
CREATE INDEX "org_api_key_org_id_idx" ON "org_api_key" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "org_end_user_org_id_idx" ON "org_end_user" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "org_ext_policy_org_id_idx" ON "org_extension_policy" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "org_ext_queue_org_id_idx" ON "org_extension_queue" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "org_invite_org_id_idx" ON "org_invite" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "org_member_user_id_idx" ON "org_member" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "org_webhook_org_id_idx" ON "org_webhook" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "alert_user_read_idx" ON "user_alert" USING btree ("user_id","read");--> statement-breakpoint
CREATE INDEX "user_ext_device_id_idx" ON "user_extension" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "ext_event_user_ext_id_idx" ON "user_extension_event" USING btree ("user_extension_id");--> statement-breakpoint
CREATE INDEX "ext_event_created_at_idx" ON "user_extension_event" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "workspace_app_org_id_idx" ON "workspace_app" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "workspace_device_org_id_idx" ON "workspace_device" USING btree ("org_id");