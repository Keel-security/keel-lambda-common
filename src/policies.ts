import { and, eq, or } from "drizzle-orm";
import { hostPolicies, hostPolicyAssignments, hosts } from "./db/schema";
import { getDb } from "./db";
import { normalizeEmailDomains, normalizePatternList } from "./policyLists";

type PolicyRow = typeof hostPolicies.$inferSelect;

function uniqStrings(lists: Array<string[] | null | undefined>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const list of lists) {
    for (const item of list ?? []) {
      const t = String(item ?? "").trim();
      if (!t) continue;
      const key = t.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(t);
    }
  }
  return out;
}

/** Union Active assigned policies so a second org policy (login domains, MCP deny) is not dropped. */
export function mergeResolvedPolicies(rows: PolicyRow[]): PolicyRow | null {
  if (rows.length === 0) return null;
  const byId = new Map<string, PolicyRow>();
  for (const p of rows) byId.set(p.id, p);
  const unique = [...byId.values()];
  const active = unique.filter((p) => p.status === "active");
  const used = active.length ? active : unique;
  const base = used[0]!;
  const roots = used.find((p) => (p.agentRoots?.length ?? 0) > 0)?.agentRoots ?? base.agentRoots;
  const kindRules = used.find((p) => (p.kindRules?.length ?? 0) > 0)?.kindRules ?? base.kindRules;
  const nonemptyAllow = used.map((p) => p.mcpAllow).filter((l) => (l?.length ?? 0) > 0);
  return {
    ...base,
    status: active.length ? "active" : base.status,
    mode: used.some((p) => p.mode === "enforce") ? "enforce" : base.mode,
    denyExec: uniqStrings(used.map((p) => p.denyExec)),
    denyPathPrefixes: uniqStrings(used.map((p) => p.denyPathPrefixes)),
    denyDestinations: uniqStrings(used.map((p) => p.denyDestinations)),
    allowTeamIds: uniqStrings(used.map((p) => p.allowTeamIds)),
    mcpAuthDenied: uniqStrings(used.map((p) => p.mcpAuthDenied)),
    mcpDeny: normalizePatternList(uniqStrings(used.map((p) => p.mcpDeny))),
    mcpAllow: nonemptyAllow.length ? normalizePatternList(uniqStrings(nonemptyAllow)) : [],
    allowedEmailDomains: normalizeEmailDomains(uniqStrings(used.map((p) => p.allowedEmailDomains))),
    agentRoots: roots,
    kindRules,
  };
}

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
        );
      const merged = mergeResolvedPolicies(assigned.map((r) => r.policy));
      if (merged) return merged;
    }
  }

  const orgWide = await db
    .select({ policy: hostPolicies })
    .from(hostPolicyAssignments)
    .innerJoin(hostPolicies, eq(hostPolicyAssignments.policyId, hostPolicies.id))
    .where(and(eq(hostPolicies.orgId, orgId), eq(hostPolicyAssignments.orgWide, true)));

  const mergedOrg = mergeResolvedPolicies(orgWide.map((r) => r.policy));
  if (mergedOrg) return mergedOrg;

  const any = await db.select().from(hostPolicies).where(eq(hostPolicies.orgId, orgId));
  return mergeResolvedPolicies(any);
}
