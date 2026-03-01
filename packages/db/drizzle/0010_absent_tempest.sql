CREATE TABLE "org_extension_policy" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"blocked_extension_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"max_risk_score" integer,
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
	"risk_score" integer,
	"reviewed_at" timestamp with time zone,
	"reviewed_by" text,
	CONSTRAINT "org_extension_queue_org_id_chrome_extension_id_unique" UNIQUE("org_id","chrome_extension_id")
);
--> statement-breakpoint
ALTER TABLE "org_extension_policy" ADD CONSTRAINT "org_extension_policy_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_extension_policy" ADD CONSTRAINT "org_extension_policy_updated_by_user_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_extension_queue" ADD CONSTRAINT "org_extension_queue_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_extension_queue" ADD CONSTRAINT "org_extension_queue_reviewed_by_user_id_fk" FOREIGN KEY ("reviewed_by") REFERENCES "public"."user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "org_ext_policy_org_id_idx" ON "org_extension_policy" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "org_ext_queue_org_id_idx" ON "org_extension_queue" USING btree ("org_id");