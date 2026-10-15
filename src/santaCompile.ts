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
        { allowTeamIds: [], allowBinaries: loadAllowBinariesFromEnv() },
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
      allowBinaries: loadAllowBinariesFromEnv(),
    }),
  };
}

/** JSON array in SANTA_ALLOW_BINARIES, e.g. [{"sha256":"…","name":"keel-mcp-gateway"}] */
export function loadAllowBinariesFromEnv(): SantaBinaryHint[] {
  const raw = process.env.SANTA_ALLOW_BINARIES?.trim();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    const out: SantaBinaryHint[] = [];
    for (const item of parsed) {
      if (!item || typeof item !== "object") continue;
      const sha = String((item as { sha256?: unknown }).sha256 ?? "").trim().toLowerCase();
      const name = String((item as { name?: unknown }).name ?? "allow").trim();
      if (/^[a-f0-9]{64}$/.test(sha)) out.push({ sha256: sha, name });
    }
    return out;
  } catch {
    return [];
  }
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
