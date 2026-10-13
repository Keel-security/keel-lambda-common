import type { agents, hostPolicies, hosts, sensorEvents } from "./db/schema";
import { DEFAULT_AGENT_ROOTS } from "./agentRoots";
import { compileSantaFromDenyLists } from "./santaCompilePure";
import { effectiveDenyLists } from "./effectivePolicy";
import { mergeKindRules } from "./kindRules";
import type { PolicyCategory, PolicyLifecycleStatus, PolicySeverity } from "./schemas/types";

type HostRow = typeof hosts.$inferSelect;
type PolicyRow = typeof hostPolicies.$inferSelect;
type AgentRow = typeof agents.$inferSelect;
type EventRow = typeof sensorEvents.$inferSelect;

const CATEGORIES = new Set(["exec", "path", "network", "credential", "custom"]);
const SEVERITIES = new Set(["high", "medium", "low"]);
const STATUSES = new Set(["active", "draft"]);

function asCategory(v: string | null | undefined): PolicyCategory {
  return CATEGORIES.has(v ?? "") ? (v as PolicyCategory) : "custom";
}
function asSeverity(v: string | null | undefined): PolicySeverity {
  return SEVERITIES.has(v ?? "") ? (v as PolicySeverity) : "medium";
}
function asStatus(v: string | null | undefined): PolicyLifecycleStatus {
  return STATUSES.has(v ?? "") ? (v as PolicyLifecycleStatus) : "draft";
}

export function serializeHost(h: HostRow) {
  return {
    id: h.id,
    hostname: h.hostname,
    os: h.os,
    osVersion: h.osVersion,
    userName: h.userName,
    sensorVersion: h.sensorVersion,
    lastSeenAt: h.lastSeenAt.toISOString(),
    status: h.status,
  };
}

export function serializePolicy(p: PolicyRow) {
  const roots = p.agentRoots?.length ? p.agentRoots : DEFAULT_AGENT_ROOTS;
  const kindRules = mergeKindRules(p.kindRules as Parameters<typeof mergeKindRules>[0]);
  const stored = {
    denyExec: p.denyExec ?? [],
    denyPathPrefixes: p.denyPathPrefixes ?? [],
    denyDestinations: p.denyDestinations ?? [],
  };
  const allowTeamIds = p.allowTeamIds ?? [];
  const effective = effectiveDenyLists(stored);
  const compiled = compileSantaFromDenyLists(effective, { allowTeamIds });
  return {
    id: p.id,
    name: p.name,
    description: p.description ?? "",
    version: p.version,
    mode: p.mode,
    category: asCategory(p.category),
    severity: asSeverity(p.severity),
    status: asStatus(p.status),
    source: "manual" as const,
    denyExec: stored.denyExec,
    denyPathPrefixes: stored.denyPathPrefixes,
    denyDestinations: stored.denyDestinations,
    allowTeamIds,
    effectiveDenyExec: effective.denyExec,
    effectiveDenyPathPrefixes: effective.denyPathPrefixes,
    effectiveDenyDestinations: effective.denyDestinations,
    agentRoots: roots,
    kindRules,
    santaPreview: {
      blockedPathRegex: compiled.blockedPathRegex,
      rules: compiled.rules.map((r) => ({
        identifier: r.identifier,
        policy: r.policy,
        rule_type: r.rule_type,
        custom_msg: r.custom_msg,
      })),
    },
    updatedAt: p.updatedAt.toISOString(),
  };
}

export function serializeAgent(a: AgentRow, hostname?: string) {
  return {
    id: a.id,
    hostId: a.hostId,
    hostname,
    kind: a.kind,
    name: a.name,
    version: a.version,
    detail: a.detailJson ?? {},
    lastSeenAt: a.lastSeenAt.toISOString(),
  };
}

export function serializeEvent(e: EventRow, hostname?: string) {
  return {
    id: e.id,
    hostId: e.hostId,
    hostname,
    agentId: e.agentId,
    pid: e.pid,
    syscall: e.syscall,
    subject: e.subject,
    decision: e.decision,
    createdAt: e.createdAt.toISOString(),
  };
}
