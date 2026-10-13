import { z } from "zod";

export const HostStatusSchema = z.enum(["online", "stale", "offline"]);
export type HostStatus = z.infer<typeof HostStatusSchema>;

export const AgentKindSchema = z.enum(["claude", "codex", "cursor", "other"]);
export type AgentKind = z.infer<typeof AgentKindSchema>;

export const PolicyModeSchema = z.enum(["observe", "enforce"]);
export type PolicyMode = z.infer<typeof PolicyModeSchema>;

export const SyscallSchema = z.enum(["execve", "open", "connect"]);
export type Syscall = z.infer<typeof SyscallSchema>;

export const DecisionSchema = z.enum(["allow", "deny", "observe"]);
export type Decision = z.infer<typeof DecisionSchema>;

export const HeartbeatProcessSchema = z.object({
  pid: z.number().int().positive(),
  ppid: z.number().int().nonnegative().optional(),
  binaryPath: z.string().min(1),
  agentKind: AgentKindSchema.default("other"),
});

export const HeartbeatBodySchema = z.object({
  hostname: z.string().min(1),
  os: z.string().min(1),
  osVersion: z.string().optional().default(""),
  userName: z.string().optional().default(""),
  sensorVersion: z.string().optional().default("0.1.0"),
  processes: z.array(HeartbeatProcessSchema).optional().default([]),
});
export type HeartbeatBody = z.infer<typeof HeartbeatBodySchema>;

export const InventoryAgentSchema = z.object({
  externalId: z.string().min(1),
  kind: z.string().min(1),
  name: z.string().min(1),
  version: z.string().optional().nullable(),
  detail: z.record(z.unknown()).optional().default({}),
});

export const InventoryBodySchema = z.object({
  hostname: z.string().min(1),
  agents: z.array(InventoryAgentSchema),
});
export type InventoryBody = z.infer<typeof InventoryBodySchema>;

export const EventIngestItemSchema = z.object({
  hostname: z.string().min(1),
  pid: z.number().int().nonnegative().optional().nullable(),
  agentExternalId: z.string().optional().nullable(),
  syscall: SyscallSchema,
  subject: z.string().min(1),
  decision: DecisionSchema,
  raw: z.record(z.unknown()).optional().default({}),
  occurredAt: z.string().datetime().optional(),
});

export const EventsBodySchema = z.object({
  events: z.array(EventIngestItemSchema).min(1),
});
export type EventsBody = z.infer<typeof EventsBodySchema>;

export const AgentRootMatcherSchema = z.object({
  kind: z.string().min(1),
  basenames: z.array(z.string()).default([]),
  pathContains: z.array(z.string()).optional().default([]),
  excludeContains: z.array(z.string()).optional().default([]),
});
export type AgentRootMatcher = z.infer<typeof AgentRootMatcherSchema>;

export const PolicyKindSchema = z.enum(["mcp", "skill", "agent"]);
export type PolicyKind = z.infer<typeof PolicyKindSchema>;

export const PolicyRuleActionSchema = z.enum(["deny", "warn", "observe"]);
export type PolicyRuleAction = z.infer<typeof PolicyRuleActionSchema>;

export const PolicyRuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional().default(""),
  enabled: z.boolean(),
  action: PolicyRuleActionSchema.default("deny"),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const KindPolicySchema = z.object({
  kind: PolicyKindSchema,
  label: z.string().min(1),
  rules: z.array(PolicyRuleSchema).default([]),
});
export type KindPolicy = z.infer<typeof KindPolicySchema>;

export const SantaPreviewRuleSchema = z.object({
  identifier: z.string(),
  policy: z.string(),
  rule_type: z.string(),
  custom_msg: z.string().optional(),
});
export type SantaPreviewRule = z.infer<typeof SantaPreviewRuleSchema>;

export const SantaPreviewSchema = z.object({
  blockedPathRegex: z.string().nullable(),
  rules: z.array(SantaPreviewRuleSchema),
});
export type SantaPreview = z.infer<typeof SantaPreviewSchema>;

export const PolicyCategorySchema = z.enum([
  "exec",
  "path",
  "network",
  "credential",
  "custom",
]);
export type PolicyCategory = z.infer<typeof PolicyCategorySchema>;

export const PolicySeveritySchema = z.enum(["high", "medium", "low"]);
export type PolicySeverity = z.infer<typeof PolicySeveritySchema>;

export const PolicyStatusSchema = z.enum(["active", "draft"]);
export type PolicyLifecycleStatus = z.infer<typeof PolicyStatusSchema>;

export const HostPolicyPackSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().default(""),
  version: z.number(),
  mode: PolicyModeSchema,
  category: PolicyCategorySchema.default("custom"),
  severity: PolicySeveritySchema.default("medium"),
  status: PolicyStatusSchema.default("draft"),
  /** Always manual for customer-created policies. */
  source: z.literal("manual").default("manual"),
  /** Customer block-exec basenames or path fragments. */
  denyExec: z.array(z.string()),
  denyPathPrefixes: z.array(z.string()),
  denyDestinations: z.array(z.string()),
  /** Customer Santa TEAMID allowlist. */
  allowTeamIds: z.array(z.string()).default([]),
  /** Same as stored lists (no kind-rule expansion). */
  effectiveDenyExec: z.array(z.string()).default([]),
  effectiveDenyPathPrefixes: z.array(z.string()).default([]),
  effectiveDenyDestinations: z.array(z.string()).default([]),
  agentRoots: z.array(AgentRootMatcherSchema).default([]),
  kindRules: z.array(KindPolicySchema).default([]),
  /** What Santa will receive on next sync (compiled). */
  santaPreview: SantaPreviewSchema.optional(),
  updatedAt: z.string(),
});
export type HostPolicyPack = z.infer<typeof HostPolicyPackSchema>;

export const CreateHostPolicySchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  mode: PolicyModeSchema.optional(),
  category: PolicyCategorySchema.optional(),
  severity: PolicySeveritySchema.optional(),
  status: PolicyStatusSchema.optional(),
  denyExec: z.array(z.string()).optional(),
  denyPathPrefixes: z.array(z.string()).optional(),
  denyDestinations: z.array(z.string()).optional(),
  allowTeamIds: z.array(z.string()).optional(),
  orgWide: z.boolean().optional().default(true),
});
export type CreateHostPolicy = z.infer<typeof CreateHostPolicySchema>;

export const PatchHostPolicySchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  mode: PolicyModeSchema.optional(),
  category: PolicyCategorySchema.optional(),
  severity: PolicySeveritySchema.optional(),
  status: PolicyStatusSchema.optional(),
  denyExec: z.array(z.string()).optional(),
  denyPathPrefixes: z.array(z.string()).optional(),
  denyDestinations: z.array(z.string()).optional(),
  allowTeamIds: z.array(z.string()).optional(),
  agentRoots: z.array(AgentRootMatcherSchema).optional(),
  kindRules: z.array(KindPolicySchema).optional(),
});
export type PatchHostPolicy = z.infer<typeof PatchHostPolicySchema>;

export const OverviewSchema = z.object({
  hostsOnline: z.number(),
  hostsTotal: z.number(),
  agentsTotal: z.number(),
  denies24h: z.number(),
  policiesEnforce: z.number(),
  policiesObserve: z.number(),
});
export type Overview = z.infer<typeof OverviewSchema>;

export const HostSchema = z.object({
  id: z.string(),
  hostname: z.string(),
  os: z.string(),
  osVersion: z.string(),
  userName: z.string(),
  sensorVersion: z.string(),
  lastSeenAt: z.string(),
  status: HostStatusSchema,
});
export type Host = z.infer<typeof HostSchema>;

export const AgentSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  hostname: z.string().optional(),
  kind: z.string(),
  name: z.string(),
  version: z.string().nullable(),
  detail: z.record(z.unknown()),
  lastSeenAt: z.string(),
});
export type Agent = z.infer<typeof AgentSchema>;

export const SensorEventSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  hostname: z.string().optional(),
  agentId: z.string().nullable(),
  pid: z.number().nullable(),
  syscall: SyscallSchema,
  subject: z.string(),
  decision: DecisionSchema,
  createdAt: z.string(),
});
export type SensorEvent = z.infer<typeof SensorEventSchema>;
