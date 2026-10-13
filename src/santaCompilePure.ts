import type { DenyLists } from "./effectivePolicy";

/** Santa ruledownload rule (snake + camel for protobuf JSON). */
export type SantaCompiledRule = {
  identifier: string;
  policy: "ALLOWLIST" | "BLOCKLIST" | "SILENT_BLOCKLIST" | "ALLOWLIST_COMPILER" | "REMOVE";
  rule_type: "BINARY" | "CERTIFICATE" | "TEAMID" | "SIGNINGID" | "CDHASH";
  custom_msg?: string;
  ruleType?: string;
  customMsg?: string;
};

export type SantaCompiledPolicy = {
  blockedPathRegex: string | null;
  rules: SantaCompiledRule[];
};

export type SantaBinaryHint = {
  sha256: string;
  name: string;
};

const SANTA_VENDOR_TEAM_ID = "ZMCG7MLDV9";

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function withCamel(rule: SantaCompiledRule): SantaCompiledRule {
  return {
    ...rule,
    ruleType: rule.rule_type,
    customMsg: rule.custom_msg,
  };
}

/**
 * Build a path regex that blocks denyExec basenames / path fragments and
 * denyPathPrefixes substrings. Applied by Santa as blocked_path_regex.
 */
export function compileBlockedPathRegex(deny: DenyLists): string | null {
  const parts: string[] = [];

  const basenames = deny.denyExec
    .map((b) => b.trim())
    .filter((b) => b.length > 0 && !b.includes("/"));
  if (basenames.length > 0) {
    const alt = basenames.map(escapeRegex).join("|");
    parts.push(`(?:^|/)(?:${alt})$`);
  }

  for (const exec of deny.denyExec) {
    const t = exec.trim();
    if (t.includes("/")) {
      parts.push(escapeRegex(t));
    }
  }

  for (const prefix of deny.denyPathPrefixes) {
    const t = prefix.trim();
    if (!t) continue;
    parts.push(escapeRegex(t));
  }

  if (parts.length === 0) return null;
  return parts.join("|");
}

export type CompileSantaOptions = {
  allowTeamIds?: string[];
  binaryHints?: SantaBinaryHint[];
};

/**
 * Compile customer deny/allow lists into Santa sync material.
 * Always includes Santa vendor TeamID so clean syncs have ≥1 rule.
 */
export function compileSantaFromDenyLists(
  deny: DenyLists,
  binaryHintsOrOpts: SantaBinaryHint[] | CompileSantaOptions = [],
): SantaCompiledPolicy {
  const opts: CompileSantaOptions = Array.isArray(binaryHintsOrOpts)
    ? { binaryHints: binaryHintsOrOpts }
    : binaryHintsOrOpts;
  const binaryHints = opts.binaryHints ?? [];
  const allowTeamIds = opts.allowTeamIds ?? [];

  const blockedPathRegex = compileBlockedPathRegex(deny);
  const rules: SantaCompiledRule[] = [
    withCamel({
      identifier: SANTA_VENDOR_TEAM_ID,
      policy: "ALLOWLIST",
      rule_type: "TEAMID",
      custom_msg: "Keel — allow Santa vendor TeamID",
    }),
  ];

  const seenTeam = new Set<string>([SANTA_VENDOR_TEAM_ID]);
  for (const tid of allowTeamIds) {
    const id = tid.trim().toUpperCase();
    if (!id || seenTeam.has(id)) continue;
    // TeamIDs are typically 10 alphanumeric chars; accept broader customer input.
    if (!/^[A-Z0-9]{8,12}$/.test(id)) continue;
    seenTeam.add(id);
    rules.push(
      withCamel({
        identifier: id,
        policy: "ALLOWLIST",
        rule_type: "TEAMID",
        custom_msg: `Keel allow TeamID — ${id}`,
      }),
    );
  }

  const denyNames = new Set(
    deny.denyExec.map((b) => b.trim().toLowerCase()).filter(Boolean),
  );

  const seenHash = new Set<string>();
  for (const hint of binaryHints) {
    const sha = hint.sha256.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha) || seenHash.has(sha)) continue;
    const name = hint.name.trim().toLowerCase();
    if (denyNames.size > 0 && name && !denyNames.has(name)) continue;
    seenHash.add(sha);
    rules.push(
      withCamel({
        identifier: sha,
        policy: "BLOCKLIST",
        rule_type: "BINARY",
        custom_msg: `Keel block — ${hint.name || "binary"}`,
      }),
    );
  }

  return { blockedPathRegex, rules };
}
