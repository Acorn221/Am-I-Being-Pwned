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
	"last_synced_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "workspace_app_org_id_chromeExtensionId_unique" UNIQUE("org_id","chrome_extension_id")
);
--> statement-breakpoint
ALTER TABLE "organization" ADD COLUMN "last_workspace_sync_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "workspace_app" ADD CONSTRAINT "workspace_app_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "workspace_app_org_id_idx" ON "workspace_app" USING btree ("org_id");