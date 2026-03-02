import { and, eq, or } from "drizzle-orm";

import { OrgMember, Organization, eqi } from "@amibeingpwned/db";
import type { db as DbType } from "@amibeingpwned/db/client";

/**
 * Look up the org membership for a user who must have the "owner" or "admin"
 * role. Returns null if the user is not a manager of any org.
 *
 * Used by both `managerProcedure` (throws on null) and endpoints that want
 * to return null instead of throwing (e.g. fleet.overview).
 */
export async function fetchManagerMembership(db: typeof DbType, userId: string) {
  const [membership] = await db
    .select({
      orgId: OrgMember.orgId,
      orgRole: OrgMember.role,
      orgName: Organization.name,
      orgPlan: Organization.plan,
      orgSuspendedAt: Organization.suspendedAt,
      orgLastWorkspaceSyncAt: Organization.lastWorkspaceSyncAt,
    })
    .from(OrgMember)
    .innerJoin(Organization, eqi(OrgMember.orgId, Organization.id))
    .where(
      and(
        eq(OrgMember.userId, userId),
        or(eq(OrgMember.role, "owner"), eq(OrgMember.role, "admin")),
      ),
    )
    .limit(1);
  return membership ?? null;
}

/**
 * Resolves the org context for a procedure call.
 *
 * For admin users: if the request includes an `x-impersonate-org` header with
 * a valid org ID, the org row is fetched directly (bypassing OrgMember) and
 * the caller is granted `orgRole: "admin"`. This is the "god mode" path.
 *
 * For everyone else: delegates to fetchManagerMembership as normal.
 */
export async function resolveOrgContext(
  db: typeof DbType,
  userId: string,
  userRole: string,
  headers: Headers,
) {
  if (userRole === "admin") {
    const impersonateOrgId = headers.get("x-impersonate-org");
    if (impersonateOrgId) {
      const [org] = await db
        .select({
          orgId: Organization.id,
          orgName: Organization.name,
          orgPlan: Organization.plan,
          orgSuspendedAt: Organization.suspendedAt,
          orgLastWorkspaceSyncAt: Organization.lastWorkspaceSyncAt,
        })
        .from(Organization)
        .where(eqi(Organization.id, impersonateOrgId))
        .limit(1);

      if (org) {
        return {
          orgId: org.orgId,
          orgRole: "admin" as const,
          orgName: org.orgName,
          orgPlan: org.orgPlan,
          orgSuspendedAt: org.orgSuspendedAt,
          orgLastWorkspaceSyncAt: org.orgLastWorkspaceSyncAt,
        };
      }
    }
  }
  return fetchManagerMembership(db, userId);
}
