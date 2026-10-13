/**
 * Deny lists for sensors / Santa.
 * Customer-authored lists only — no kind-rule expansions or presets.
 */

export const PRIVILEGE_DENY_EXEC = ["sudo", "doas", "pkexec", "su"] as const;

export const SECRET_DENY_PATH_PREFIXES = ["/.ssh/", "/.aws/", "/.kube/", "/.env", "/.netrc"] as const;

function uniq(list: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of list) {
    const t = item.trim();
    if (!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}

export type DenyLists = {
  denyExec: string[];
  denyPathPrefixes: string[];
  denyDestinations: string[];
};

/**
 * Effective deny lists = stored customer lists (deduped).
 * `kindRulesStored` is ignored (kept for call-site compatibility).
 */
export function effectiveDenyLists(
  stored: DenyLists,
  _kindRulesStored?: unknown,
): DenyLists {
  return {
    denyExec: uniq(stored.denyExec ?? []),
    denyPathPrefixes: uniq(stored.denyPathPrefixes ?? []),
    denyDestinations: uniq(stored.denyDestinations ?? []),
  };
}
