import { createHash } from "node:crypto";
import { and, eq } from "drizzle-orm";
import type { Db } from "./db/client";
import { alerts } from "./db/schema";
import type { AlertKind, AlertSeverity, Decision } from "./schemas/types";

export type AlertEventInput = {
  orgId: string;
  hostId: string | null;
  hostname?: string | null;
  agentId?: string | null;
  eventId?: string | null;
  syscall?: string | null;
  subject: string;
  decision: Decision;
  raw?: Record<string, unknown> | null;
  occurredAt?: Date;
};

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function basename(subject: string): string {
  const parts = subject.split("/").filter(Boolean);
  return parts[parts.length - 1] || subject;
}

export function shouldCreateAlert(decision: Decision, raw?: Record<string, unknown> | null): boolean {
  if (decision === "deny") return true;
  if (decision === "observe" && raw?.policyHit === true) return true;
  return false;
}

export function classifyAlertKind(raw?: Record<string, unknown> | null): {
  source: string;
  kind: AlertKind;
} {
  const source = str(raw?.source) || "host-sensor";
  if (source === "mcp-gateway") return { source, kind: "gateway_block" };
  if (source === "santa") return { source, kind: "santa_block" };
  return { source, kind: "policy_violation" };
}

export function alertFingerprint(kind: AlertKind, hostId: string | null, source: string, subject: string) {
  return createHash("sha256")
    .update(`${kind}|${hostId ?? ""}|${source}|${subject}`)
    .digest("hex");
}

function actionsOf(raw?: Record<string, unknown> | null): string[] {
  const a = raw?.actions;
  return Array.isArray(a) ? a.filter((x): x is string => typeof x === "string") : [];
}

export function deriveAlertSeverity(
  kind: AlertKind,
  decision: Decision,
  syscall?: string | null,
  raw?: Record<string, unknown> | null,
): AlertSeverity {
  if (kind === "santa_block" || syscall === "execve") return "high";
  if (kind === "gateway_block") {
    const actions = actionsOf(raw);
    if (actions.some((a) => a === "drop" || a.startsWith("quarantine"))) return "high";
    return "medium";
  }
  if (decision === "observe") return "low";
  return "medium";
}

export function deriveAlertTitle(
  kind: AlertKind,
  decision: Decision,
  subject: string,
  syscall?: string | null,
  raw?: Record<string, unknown> | null,
): string {
  const alias = str(raw?.alias);
  const tool = str(raw?.tool);
  const method = str(raw?.mcpMethod);
  const name = basename(subject);

  if (kind === "gateway_block") {
    if (subject.includes("mcp:server") || str(raw?.reason) === "mcp-server") {
      const verb = decision === "deny" ? "blocked" : "flagged";
      return `Gateway ${verb} MCP server${alias ? ` (${alias})` : ""}`;
    }
    if (subject.includes("auth") || str(raw?.reason).includes("mcpAuth")) {
      return `Gateway blocked MCP auth${alias ? ` (${alias})` : ""}`;
    }
    if (method === "tools/list") {
      return `Gateway quarantined poisoned tools${alias ? ` (${alias})` : ""}`;
    }
    if (method === "tools/call") {
      const who = [alias, tool].filter(Boolean).join(" · ");
      return `Gateway blocked tool result${who ? ` (${who})` : ""}`;
    }
    return `Gateway blocked ${name}`;
  }
  if (kind === "santa_block") {
    return `Santa blocked ${name}`;
  }
  if (syscall === "identity" || subject.startsWith("login:")) {
    const harness = str(raw?.harness) || subject.split(":")[1] || "agent";
    const pretty = harness.charAt(0).toUpperCase() + harness.slice(1);
    return `Non-org ${pretty} login`;
  }
  const verb = decision === "deny" ? "blocked" : "matched";
  const sys = syscall ? `${syscall} ` : "";
  return `Policy ${verb} ${sys}${name}`.trim();
}

export function deriveAlertSummary(input: {
  kind: AlertKind;
  hostname?: string | null;
  subject: string;
  decision: Decision;
  source: string;
}): string {
  const host = input.hostname ? ` on ${input.hostname}` : "";
  if (input.subject.startsWith("login:")) {
    return `Non-org agent login${host}: ${input.subject}`;
  }
  const verb = input.decision === "deny" ? "blocked" : "matched policy";
  return `${input.kind.replace(/_/g, " ")} ${verb}${host}: ${input.subject} (${input.source})`;
}

/**
 * Insert or roll up an open alert for a policy hit / gateway or Santa block.
 * No-ops when the event is not a violation.
 */
export async function upsertAlertFromEvent(db: Db, input: AlertEventInput): Promise<void> {
  const raw = input.raw ?? {};
  if (!shouldCreateAlert(input.decision, raw)) return;

  const { source, kind } = classifyAlertKind(raw);
  const subject = input.subject.trim();
  if (!subject) return;

  const fingerprint = alertFingerprint(kind, input.hostId, source, subject);
  const now = input.occurredAt ?? new Date();
  const title = deriveAlertTitle(kind, input.decision, subject, input.syscall, raw);
  const summary = deriveAlertSummary({
    kind,
    hostname: input.hostname,
    subject,
    decision: input.decision,
    source,
  });
  const severity = deriveAlertSeverity(kind, input.decision, input.syscall, raw);

  const existing = await db
    .select()
    .from(alerts)
    .where(
      and(eq(alerts.orgId, input.orgId), eq(alerts.fingerprint, fingerprint), eq(alerts.status, "open")),
    )
    .limit(1);

  const row = existing[0];
  if (row) {
    await db
      .update(alerts)
      .set({
        count: row.count + 1,
        lastSeenAt: now,
        eventId: input.eventId ?? row.eventId,
        agentId: input.agentId ?? row.agentId,
        rawJson: raw,
        severity,
        title,
        summary,
        decision: input.decision,
      })
      .where(eq(alerts.id, row.id));
    return;
  }

  try {
    await db.insert(alerts).values({
      orgId: input.orgId,
      hostId: input.hostId,
      agentId: input.agentId ?? null,
      eventId: input.eventId ?? null,
      source,
      kind,
      severity,
      status: "open",
      title,
      summary,
      subject,
      decision: input.decision,
      fingerprint,
      count: 1,
      rawJson: raw,
      firstSeenAt: now,
      lastSeenAt: now,
    });
  } catch (err) {
    // Concurrent insert on the open-fingerprint unique index: roll up instead.
    const raced = await db
      .select()
      .from(alerts)
      .where(
        and(
          eq(alerts.orgId, input.orgId),
          eq(alerts.fingerprint, fingerprint),
          eq(alerts.status, "open"),
        ),
      )
      .limit(1);
    if (!raced[0]) throw err;
    await db
      .update(alerts)
      .set({
        count: raced[0].count + 1,
        lastSeenAt: now,
        eventId: input.eventId ?? raced[0].eventId,
        rawJson: raw,
      })
      .where(eq(alerts.id, raced[0].id));
  }
}
