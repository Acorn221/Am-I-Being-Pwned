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
ALTER TABLE "demo_link" ADD CONSTRAINT "demo_link_created_by_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "demo_scan" ADD CONSTRAINT "demo_scan_demo_link_id_demo_link_id_fk" FOREIGN KEY ("demo_link_id") REFERENCES "public"."demo_link"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "demo_link_slug_idx" ON "demo_link" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "demo_scan_demo_link_id_idx" ON "demo_scan" USING btree ("demo_link_id");
