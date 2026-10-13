import { and, desc, eq, sql } from "drizzle-orm";
import { hosts, sensorEvents } from "./db/schema";
import {
  compileSantaFromDenyLists,
  type SantaBinaryHint,
  type SantaCompiledPolicy,
} from "./santaCompilePure";
import { effectiveDenyLists } from "./effectivePolicy";
import { getDb } from "./db";
import { findHostByMachineId } from "./santaHosts";
import { resolveOrgPolicy } from "./policies";

export async function compileSantaForMachine(
  orgId: string,
  machineId: string,
): Promise<SantaCompiledPolicy & { hostname: string | null }> {
  const host = await findHostByMachineId(orgId, machineId);
  const hostname = host?.hostname ?? null;
  const policy = await resolveOrgPolicy(orgId, hostname);
  if (!policy) {
    return {
      hostname,
      ...compileSantaFromDenyLists(
        { denyExec: [], denyPathPrefixes: [], denyDestinations: [] },
        { allowTeamIds: [] },
      ),
    };
  }

  const deny = effectiveDenyLists({
    denyExec: policy.denyExec ?? [],
    denyPathPrefixes: policy.denyPathPrefixes ?? [],
    denyDestinations: policy.denyDestinations ?? [],
  });

  const hints = await loadBinaryHintsForDeny(orgId, deny.denyExec, host?.id);
  return {
    hostname,
    ...compileSantaFromDenyLists(deny, {
      allowTeamIds: policy.allowTeamIds ?? [],
      binaryHints: hints,
    }),
  };
}

async function loadBinaryHintsForDeny(
  orgId: string,
  denyExec: string[],
  hostId: string | undefined,
): Promise<SantaBinaryHint[]> {
  const names = denyExec.map((n) => n.trim().toLowerCase()).filter(Boolean);
  if (names.length === 0) return [];

  const nameSet = new Set(names);
  const filters = [
    eq(sensorEvents.orgId, orgId),
    eq(sensorEvents.syscall, "execve"),
    sql`${sensorEvents.rawJson}->>'source' = 'santa'`,
  ];
  if (hostId) filters.push(eq(sensorEvents.hostId, hostId));

  const rows = await getDb()
    .select({
      rawJson: sensorEvents.rawJson,
      subject: sensorEvents.subject,
    })
    .from(sensorEvents)
    .innerJoin(hosts, eq(sensorEvents.hostId, hosts.id))
    .where(and(...filters))
    .orderBy(desc(sensorEvents.createdAt))
    .limit(500);

  const hints: SantaBinaryHint[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const raw = row.rawJson as Record<string, unknown>;
    const sha = typeof raw.file_sha256 === "string" ? raw.file_sha256 : "";
    const fileName =
      typeof raw.file_name === "string" ? raw.file_name : (row.subject.split("/").pop() ?? "");
    const base = fileName.toLowerCase();
    if (!sha || !nameSet.has(base) || seen.has(sha)) continue;
    seen.add(sha);
    hints.push({ sha256: sha, name: fileName });
  }
  return hints;
}
