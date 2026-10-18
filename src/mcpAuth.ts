/** MCP upstream auth methods the gateway (and later inventory) can classify. */

export const MCP_AUTH_METHOD_IDS = [
  "none",
  "bearer_static",
  "oauth_auth_code",
  "oauth_device_code",
  "oauth_client_credentials",
  "oauth_token_exchange",
  "stdio_env_secret",
] as const;

export type McpAuthMethod = (typeof MCP_AUTH_METHOD_IDS)[number];

export const MCP_AUTH_METHODS: {
  id: McpAuthMethod;
  label: string;
  hint: string;
  shipped: boolean;
}[] = [
  {
    id: "bearer_static",
    label: "API keys / static Bearer",
    hint: "Authorization header or PAT copied from mcp.json",
    shipped: true,
  },
  {
    id: "oauth_auth_code",
    label: "OAuth authorization code (browser)",
    hint: "PKCE; Notion DCR or a pre-registered app (GitHub)",
    shipped: true,
  },
  {
    id: "none",
    label: "No auth",
    hint: "Local stdio or an open HTTP MCP",
    shipped: true,
  },
  {
    id: "stdio_env_secret",
    label: "Stdio env secrets",
    hint: "API keys in stdio MCP env (mcp.json env). Inventory + Alert; HTTP gateway cannot see them",
    shipped: true,
  },
  {
    id: "oauth_device_code",
    label: "OAuth device code",
    hint: "Headless RFC 8628 — not implemented yet; deny so it cannot be used later without policy",
    shipped: false,
  },
  {
    id: "oauth_client_credentials",
    label: "OAuth client credentials",
    hint: "Machine grant with client id+secret — not implemented yet",
    shipped: false,
  },
  {
    id: "oauth_token_exchange",
    label: "OAuth token exchange / OBO",
    hint: "RFC 8693 — needs Hop A identity first",
    shipped: false,
  },
];

const known = new Set<string>(MCP_AUTH_METHOD_IDS);

export function normalizeMcpAuthDenied(raw: unknown): McpAuthMethod[] {
  if (!Array.isArray(raw)) return [];
  const out: McpAuthMethod[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    const id = String(item ?? "").trim();
    if (!known.has(id) || seen.has(id)) continue;
    seen.add(id);
    out.push(id as McpAuthMethod);
  }
  return out;
}
