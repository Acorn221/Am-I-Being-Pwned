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
ALTER TABLE "workspace_app" ADD COLUMN "source" text DEFAULT 'oauth' NOT NULL;--> statement-breakpoint
ALTER TABLE "workspace_device" ADD CONSTRAINT "workspace_device_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "workspace_device_org_id_idx" ON "workspace_device" USING btree ("org_id");