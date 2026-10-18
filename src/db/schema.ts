import { sql } from "drizzle-orm";
import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

export const hostStatusEnum = pgEnum("host_status", ["online", "stale", "offline"]);
export const agentKindEnum = pgEnum("agent_kind", ["claude", "codex", "cursor", "other"]);
export const policyModeEnum = pgEnum("policy_mode", ["observe", "enforce"]);
export const syscallEnum = pgEnum("syscall", ["execve", "open", "connect", "identity"]);
export const decisionEnum = pgEnum("decision", ["allow", "deny", "observe"]);

export const orgs = pgTable("orgs", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: text("name").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const apiKeys = pgTable("api_keys", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: uuid("org_id")
    .notNull()
    .references(() => orgs.id, { onDelete: "cascade" }),
  keyHash: text("key_hash").notNull(),
  name: text("name").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const hosts = pgTable(
  "hosts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => orgs.id, { onDelete: "cascade" }),
    hostname: text("hostname").notNull(),
    os: text("os").notNull(),
    osVersion: text("os_version").notNull().default(""),
    userName: text("user_name").notNull().default(""),
    sensorVersion: text("sensor_version").notNull().default("0.1.0"),
    /** Santa hardware UUID / MachineID for sync URL lookup. */
    machineId: text("machine_id"),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).defaultNow().notNull(),
    status: hostStatusEnum("status").notNull().default("online"),
  },
  (t) => [
    uniqueIndex("hosts_org_hostname").on(t.orgId, t.hostname),
    uniqueIndex("hosts_org_machine").on(t.orgId, t.machineId),
  ],
);

export const hostProcesses = pgTable("host_processes", {
  id: uuid("id").defaultRandom().primaryKey(),
  hostId: uuid("host_id")
    .notNull()
    .references(() => hosts.id, { onDelete: "cascade" }),
  pid: integer("pid").notNull(),
  ppid: integer("ppid"),
  binaryPath: text("binary_path").notNull(),
  agentKind: agentKindEnum("agent_kind").notNull().default("other"),
  taggedAt: timestamp("tagged_at", { withTimezone: true }).defaultNow().notNull(),
});

export const agents = pgTable(
  "agents",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => orgs.id, { onDelete: "cascade" }),
    hostId: uuid("host_id")
      .notNull()
      .references(() => hosts.id, { onDelete: "cascade" }),
    externalId: text("external_id").notNull(),
    kind: text("kind").notNull(),
    name: text("name").notNull(),
    version: text("version"),
    detailJson: jsonb("detail_json").$type<Record<string, unknown>>().notNull().default({}),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [uniqueIndex("agents_host_external").on(t.hostId, t.externalId)],
);

export type AgentRootMatcherRow = {
  kind: string;
  basenames: string[];
  pathContains?: string[];
  excludeContains?: string[];
};

export type PolicyRuleRow = {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  action: "deny" | "warn" | "observe";
};

export type KindPolicyRow = {
  kind: "mcp" | "skill" | "agent";
  label: string;
  rules: PolicyRuleRow[];
};

export const hostPolicies = pgTable("host_policies", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: uuid("org_id")
    .notNull()
    .references(() => orgs.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  /** Short description shown in the policies table. */
  description: text("description").notNull().default(""),
  version: integer("version").notNull().default(1),
  mode: policyModeEnum("mode").notNull().default("observe"),
  /** UI: exec | path | network | credential | custom */
  category: text("category").notNull().default("custom"),
  /** UI: high | medium | low */
  severity: text("severity").notNull().default("medium"),
  /** UI: active | draft */
  status: text("status").notNull().default("draft"),
  denyExec: jsonb("deny_exec").$type<string[]>().notNull().default([]),
  denyPathPrefixes: jsonb("deny_path_prefixes").$type<string[]>().notNull().default([]),
  denyDestinations: jsonb("deny_destinations").$type<string[]>().notNull().default([]),
  /** Santa TEAMID allowlist entries (customer-authored). */
  allowTeamIds: jsonb("allow_team_ids").$type<string[]>().notNull().default([]),
  /** Process matchers for agent roots; empty means API fills shared defaults. */
  agentRoots: jsonb("agent_roots").$type<AgentRootMatcherRow[]>().notNull().default([]),
  /** Kind-scoped rules (legacy; not used by simple Santa policy UX). */
  kindRules: jsonb("kind_rules").$type<KindPolicyRow[]>().notNull().default([]),
  /** MCP auth methods the gateway must not use (bearer_static, oauth_client_credentials, …). */
  mcpAuthDenied: jsonb("mcp_auth_denied").$type<string[]>().notNull().default([]),
  /** Approved MCP servers (alias, host, URL, or command). Empty = no allow restriction. */
  mcpAllow: jsonb("mcp_allow").$type<string[]>().notNull().default([]),
  /** Blocked MCP servers. Deny wins over allow. */
  mcpDeny: jsonb("mcp_deny").$type<string[]>().notNull().default([]),
  /** Org email domains for agent logins. Empty = inventory only, no alert. */
  allowedEmailDomains: jsonb("allowed_email_domains").$type<string[]>().notNull().default([]),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const hostPolicyAssignments = pgTable("host_policy_assignments", {
  id: uuid("id").defaultRandom().primaryKey(),
  policyId: uuid("policy_id")
    .notNull()
    .references(() => hostPolicies.id, { onDelete: "cascade" }),
  hostId: uuid("host_id").references(() => hosts.id, { onDelete: "cascade" }),
  orgWide: boolean("org_wide").notNull().default(false),
});

export const sensorEvents = pgTable("sensor_events", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: uuid("org_id")
    .notNull()
    .references(() => orgs.id, { onDelete: "cascade" }),
  hostId: uuid("host_id")
    .notNull()
    .references(() => hosts.id, { onDelete: "cascade" }),
  agentId: uuid("agent_id").references(() => agents.id, { onDelete: "set null" }),
  pid: integer("pid"),
  syscall: syscallEnum("syscall").notNull(),
  subject: text("subject").notNull(),
  decision: decisionEnum("decision").notNull(),
  rawJson: jsonb("raw_json").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const sensorHeartbeats = pgTable("sensor_heartbeats", {
  id: uuid("id").defaultRandom().primaryKey(),
  hostId: uuid("host_id")
    .notNull()
    .references(() => hosts.id, { onDelete: "cascade" }),
  payloadJson: jsonb("payload_json").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const alertSeverityEnum = pgEnum("alert_severity", ["high", "medium", "low"]);
export const alertStatusEnum = pgEnum("alert_status", ["open", "acknowledged", "resolved"]);
export const alertKindEnum = pgEnum("alert_kind", [
  "policy_violation",
  "gateway_block",
  "santa_block",
]);

export const alerts = pgTable(
  "alerts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => orgs.id, { onDelete: "cascade" }),
    hostId: uuid("host_id").references(() => hosts.id, { onDelete: "set null" }),
    agentId: uuid("agent_id").references(() => agents.id, { onDelete: "set null" }),
    eventId: uuid("event_id").references(() => sensorEvents.id, { onDelete: "set null" }),
    source: text("source").notNull(),
    kind: alertKindEnum("kind").notNull(),
    severity: alertSeverityEnum("severity").notNull().default("medium"),
    status: alertStatusEnum("status").notNull().default("open"),
    title: text("title").notNull(),
    summary: text("summary").notNull().default(""),
    subject: text("subject").notNull(),
    decision: decisionEnum("decision").notNull(),
    fingerprint: text("fingerprint").notNull(),
    count: integer("count").notNull().default(1),
    rawJson: jsonb("raw_json").$type<Record<string, unknown>>().notNull().default({}),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).defaultNow().notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).defaultNow().notNull(),
    acknowledgedAt: timestamp("acknowledged_at", { withTimezone: true }),
    acknowledgedBy: text("acknowledged_by"),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    resolvedBy: text("resolved_by"),
  },
  (t) => [
    index("alerts_org_status_last").on(t.orgId, t.status, t.lastSeenAt),
    index("alerts_org_fingerprint").on(t.orgId, t.fingerprint),
    uniqueIndex("alerts_org_open_fingerprint")
      .on(t.orgId, t.fingerprint)
      .where(sql`${t.status} = 'open'`),
  ],
);
