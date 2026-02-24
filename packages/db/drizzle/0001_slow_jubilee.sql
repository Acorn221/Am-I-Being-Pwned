ALTER TABLE "org_member" ALTER COLUMN "role" SET DATA TYPE text;--> statement-breakpoint
ALTER TABLE "org_member" ALTER COLUMN "role" SET DEFAULT 'member';--> statement-breakpoint
DROP TYPE "public"."org_role";