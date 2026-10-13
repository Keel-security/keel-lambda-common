import { and, eq, or } from "drizzle-orm";
import { hostPolicies, hostPolicyAssignments, hosts } from "./db/schema";
import { getDb } from "./db";

export async function resolveOrgPolicy(orgId: string, hostname?: string | null) {
  const db = getDb();
  if (hostname) {
    const hostRows = await db
      .select()
      .from(hosts)
      .where(and(eq(hosts.orgId, orgId), eq(hosts.hostname, hostname)))
      .limit(1);
    const host = hostRows[0];
    if (host) {
      const assigned = await db
        .select({ policy: hostPolicies })
        .from(hostPolicyAssignments)
        .innerJoin(hostPolicies, eq(hostPolicyAssignments.policyId, hostPolicies.id))
        .where(
          and(
            eq(hostPolicies.orgId, orgId),
            or(eq(hostPolicyAssignments.hostId, host.id), eq(hostPolicyAssignments.orgWide, true)),
          ),
        )
        .limit(1);
      if (assigned[0]) return assigned[0].policy;
    }
  }

  const orgWide = await db
    .select({ policy: hostPolicies })
    .from(hostPolicyAssignments)
    .innerJoin(hostPolicies, eq(hostPolicyAssignments.policyId, hostPolicies.id))
    .where(and(eq(hostPolicies.orgId, orgId), eq(hostPolicyAssignments.orgWide, true)))
    .limit(1);

  if (orgWide[0]) return orgWide[0].policy;

  const any = await db.select().from(hostPolicies).where(eq(hostPolicies.orgId, orgId)).limit(1);
  return any[0] ?? null;
}
