/** Trim, lowercase, dedupe string lists stored on host policy. */

export function normalizePatternList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    const t = String(item ?? "").trim().toLowerCase();
    if (!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}

/** Domains like `@Acme.COM` / `*.acme.com` → `acme.com`. */
export function normalizeEmailDomains(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    let t = String(item ?? "").trim().toLowerCase();
    t = t.replace(/^@+/, "").replace(/^\*\./, "").replace(/\.+$/, "");
    if (!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}
