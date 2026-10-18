import type { agents, alerts, hostPolicies, hosts, sensorEvents } from "./db/schema";
import { DEFAULT_AGENT_ROOTS } from "./agentRoots";
import { compileSantaFromDenyLists } from "./santaCompilePure";
import { effectiveDenyLists } from "./effectivePolicy";
import { mergeKindRules } from "./kindRules";
import { normalizeMcpAuthDenied } from "./mcpAuth";
import { normalizeEmailDomains, normalizePatternList } from "./policyLists";
import type { PolicyCategory, PolicyLifecycleStatus, PolicySeverity } from "./schemas/types";

type HostRow = typeof hosts.$inferSelect;
type PolicyRow = typeof hostPolicies.$inferSelect;
type AgentRow = typeof agents.$inferSelect;
type EventRow = typeof sensorEvents.$inferSelect;
type AlertRow = typeof alerts.$inferSelect;

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
    mcpAuthDenied: normalizeMcpAuthDenied(p.mcpAuthDenied),
    mcpAllow: normalizePatternList(p.mcpAllow),
    mcpDeny: normalizePatternList(p.mcpDeny),
    allowedEmailDomains: normalizeEmailDomains(p.allowedEmailDomains),
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

export function serializeAlert(a: AlertRow, hostname?: string | null) {
  return {
    id: a.id,
    hostId: a.hostId,
    hostname: hostname ?? null,
    agentId: a.agentId,
    eventId: a.eventId,
    source: a.source,
    kind: a.kind,
    severity: a.severity,
    status: a.status,
    title: a.title,
    summary: a.summary,
    subject: a.subject,
    decision: a.decision,
    count: a.count,
    firstSeenAt: a.firstSeenAt.toISOString(),
    lastSeenAt: a.lastSeenAt.toISOString(),
    acknowledgedAt: a.acknowledgedAt?.toISOString() ?? null,
    acknowledgedBy: a.acknowledgedBy,
    resolvedAt: a.resolvedAt?.toISOString() ?? null,
    resolvedBy: a.resolvedBy,
  };
}
