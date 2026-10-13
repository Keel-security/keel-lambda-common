import type { AgentRootMatcher } from "./schemas/types";

/** Control-plane defaults for which processes count as agent roots. Sensors consume these from policy — they do not hardcode names. */
export type { AgentRootMatcher };

export const DEFAULT_AGENT_ROOTS: AgentRootMatcher[] = [
  {
    kind: "claude",
    basenames: ["claude", "claude.exe"],
    pathContains: ["@anthropic-ai/claude-code"],
  },
  {
    kind: "cursor",
    basenames: ["cursor", "cursor-server"],
    pathContains: ["cursor.app/contents/macos/cursor"],
    excludeContains: ["helper"],
  },
  {
    kind: "codex",
    basenames: ["codex"],
  },
];
