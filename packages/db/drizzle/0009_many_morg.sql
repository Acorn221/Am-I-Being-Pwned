CREATE TABLE "org_end_user" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	"org_id" uuid NOT NULL,
	"email" text NOT NULL,
	CONSTRAINT "org_end_user_org_id_email_unique" UNIQUE("org_id","email")
);
--> statement-breakpoint
ALTER TABLE "device" DROP CONSTRAINT "device_user_id_user_id_fk";
--> statement-breakpoint
ALTER TABLE "user_extension" DROP CONSTRAINT "user_extension_user_id_user_id_fk";
--> statement-breakpoint
DROP INDEX "device_user_id_idx";--> statement-breakpoint
DROP INDEX "device_fingerprint_user_idx";--> statement-breakpoint
DROP INDEX "user_ext_user_id_idx";--> statement-breakpoint
ALTER TABLE "device" ADD COLUMN "end_user_id" uuid;--> statement-breakpoint
ALTER TABLE "org_end_user" ADD CONSTRAINT "org_end_user_org_id_organization_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organization"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "org_end_user_org_id_idx" ON "org_end_user" USING btree ("org_id");--> statement-breakpoint
ALTER TABLE "device" ADD CONSTRAINT "device_end_user_id_org_end_user_id_fk" FOREIGN KEY ("end_user_id") REFERENCES "public"."org_end_user"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "device_end_user_id_idx" ON "device" USING btree ("end_user_id");--> statement-breakpoint
ALTER TABLE "device" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "user_extension" DROP COLUMN "user_id";