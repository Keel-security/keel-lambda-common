import type { KindPolicy, PolicyKind, PolicyRule } from "./schemas/types";

/** Display labels for kind-scoped policy packs. */
export const POLICY_KIND_LABELS: Record<PolicyKind, string> = {
  mcp: "MCP Policy",
  skill: "Skills Policy",
  agent: "Agent Policy",
};

export const DEFAULT_KIND_RULES: KindPolicy[] = [
  {
    kind: "mcp",
    label: POLICY_KIND_LABELS.mcp,
    rules: [
      {
        id: "mcp-unknown-server",
        name: "Warn on unknown MCP servers",
        description: "Flag MCP servers that are not present in discovered local MCP configs.",
        enabled: true,
        action: "warn",
      },
      {
        id: "mcp-remote-http",
        name: "Deny remote HTTP MCP transports",
        description: "Block MCP servers that connect over remote HTTP/SSE instead of local stdio.",
        enabled: true,
        action: "deny",
      },
      {
        id: "mcp-secrets-path",
        name: "Deny MCP configs near credentials",
        description: "Block MCP entries whose command or args reference .ssh, .aws, .env, or similar paths.",
        enabled: true,
        action: "deny",
      },
      {
        id: "mcp-privilege",
        name: "Deny privilege-escalating MCP execs",
        description:
          "When an MCP server (under an agent tree) execs sudo/doas/pkexec/su, deny that exec — not the MCP config file.",
        enabled: true,
        action: "deny",
      },
    ],
  },
  {
    kind: "skill",
    label: POLICY_KIND_LABELS.skill,
    rules: [
      {
        id: "skill-privilege",
        name: "Deny privilege-escalation execs",
        description:
          "When Claude/Codex/Cursor (or a child) execs sudo, doas, pkexec, or su after using a skill, deny that call under the agent tree. Skills on disk are not blocked.",
        enabled: true,
        action: "deny",
      },
      {
        id: "skill-network",
        name: "Warn on network-capable skills",
        description:
          "Inventory/warn when a skill text implies outbound network. Runtime connect denial uses Agent Policy destinations.",
        enabled: true,
        action: "warn",
      },
      {
        id: "skill-secret-adjacent",
        name: "Deny secret-path opens",
        description:
          "When an agent tree opens paths under .ssh, .aws, .kube, .env, or .netrc, deny that open — regardless of which skill prompted it.",
        enabled: true,
        action: "deny",
      },
      {
        id: "skill-unofficial",
        name: "Warn on skills outside agent roots",
        description: "Inventory-only: warn when SKILL.md is found outside known agent skill directories.",
        enabled: false,
        action: "warn",
      },
    ],
  },
  {
    kind: "agent",
    label: POLICY_KIND_LABELS.agent,
    rules: [
      {
        id: "agent-deny-exec",
        name: "Enforce deny-exec list",
        description: "Apply the configured deny-exec basenames under scoped agent process trees.",
        enabled: true,
        action: "deny",
      },
      {
        id: "agent-deny-paths",
        name: "Enforce deny path prefixes",
        description: "Apply the configured deny path prefixes for open/read under agent trees.",
        enabled: true,
        action: "deny",
      },
      {
        id: "agent-deny-destinations",
        name: "Enforce deny destinations",
        description: "Apply the configured host:port deny list for connect under agent trees.",
        enabled: true,
        action: "deny",
      },
      {
        id: "agent-unknown-root",
        name: "Warn on unmatched agent roots",
        description: "Warn when a process looks agent-like but matches no configured agent root.",
        enabled: false,
        action: "warn",
      },
    ],
  },
];

/** Merge stored rules with defaults so new built-ins appear without wiping user toggles. */
export function mergeKindRules(stored: KindPolicy[] | null | undefined): KindPolicy[] {
  const byKind = new Map((stored ?? []).map((k) => [k.kind, k]));
  return DEFAULT_KIND_RULES.map((def) => {
    const existing = byKind.get(def.kind);
    if (!existing) return { ...def, rules: def.rules.map((r) => ({ ...r })) };
    const byId = new Map(existing.rules.map((r) => [r.id, r]));
    const rules: PolicyRule[] = def.rules.map((r) => {
      const edit = byId.get(r.id);
      if (!edit) return { ...r };
      return {
        ...r,
        enabled: edit.enabled,
        action: edit.action ?? r.action,
        name: edit.name || r.name,
        description: edit.description || r.description,
      };
    });
    for (const r of existing.rules) {
      if (!def.rules.some((d) => d.id === r.id)) rules.push({ ...r });
    }
    return {
      kind: def.kind,
      label: existing.label || def.label,
      rules,
    };
  });
}
