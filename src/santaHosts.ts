import { gunzipSync, inflateRawSync, inflateSync } from "node:zlib";
import { and, eq } from "drizzle-orm";
import type { APIGatewayProxyEvent } from "aws-lambda";
import { hosts } from "./db/schema";
import { getDb } from "./db";
import { getHeader, rawBodyBuffer } from "./http";
import type { SantaPreflightRequest } from "./schemas/santa";

export async function upsertSantaHost(
  orgId: string,
  machineId: string,
  body: Pick<SantaPreflightRequest, "hostname" | "os_version" | "primary_user" | "santa_version">,
): Promise<{ id: string; hostname: string }> {
  const db = getDb();
  const now = new Date();
  const sensorVersion = body.santa_version ? `santa:${body.santa_version}` : "santa";

  const byMachine = await db
    .select()
    .from(hosts)
    .where(and(eq(hosts.orgId, orgId), eq(hosts.machineId, machineId)))
    .limit(1);

  if (byMachine[0]) {
    await db
      .update(hosts)
      .set({
        hostname: body.hostname,
        os: "macOS",
        osVersion: body.os_version ?? "",
        userName: body.primary_user ?? "",
        sensorVersion,
        lastSeenAt: now,
        status: "online",
      })
      .where(eq(hosts.id, byMachine[0].id));
    return { id: byMachine[0].id, hostname: body.hostname };
  }

  const byHostname = await db
    .select()
    .from(hosts)
    .where(and(eq(hosts.orgId, orgId), eq(hosts.hostname, body.hostname)))
    .limit(1);

  if (byHostname[0]) {
    await db
      .update(hosts)
      .set({
        machineId,
        os: "macOS",
        osVersion: body.os_version ?? "",
        userName: body.primary_user ?? "",
        sensorVersion,
        lastSeenAt: now,
        status: "online",
      })
      .where(eq(hosts.id, byHostname[0].id));
    return { id: byHostname[0].id, hostname: byHostname[0].hostname };
  }

  const [created] = await db
    .insert(hosts)
    .values({
      orgId,
      hostname: body.hostname,
      os: "macOS",
      osVersion: body.os_version ?? "",
      userName: body.primary_user ?? "",
      sensorVersion,
      machineId,
      lastSeenAt: now,
      status: "online",
    })
    .returning();

  if (!created) {
    throw new Error("failed to create host");
  }
  return { id: created.id, hostname: created.hostname };
}

export async function findHostByMachineId(
  orgId: string,
  machineId: string,
): Promise<{ id: string; hostname: string } | null> {
  const rows = await getDb()
    .select({ id: hosts.id, hostname: hosts.hostname })
    .from(hosts)
    .where(and(eq(hosts.orgId, orgId), eq(hosts.machineId, machineId)))
    .limit(1);
  return rows[0] ?? null;
}

function looksLikeJsonUtf8(buf: Buffer): boolean {
  let i = 0;
  while (i < buf.length && (buf[i] === 0x20 || buf[i] === 0x09 || buf[i] === 0x0a || buf[i] === 0x0d)) {
    i++;
  }
  if (i >= buf.length) return false;
  const c = buf[i];
  return c === 0x7b /* { */ || c === 0x5b /* [ */;
}

/**
 * Santa sends Content-Encoding: deflate|gzip. API Gateway (esp. HTTP API) may
 * already decompress the body while still forwarding Content-Encoding — inflating
 * again yields garbage and "invalid json" / santactl "bad request".
 */
function decodeSantaBody(buf: Buffer, contentEncoding: string | null): Buffer {
  if (buf.length === 0) return buf;
  // Already plaintext JSON (API GW pre-decompressed, or client sent identity).
  if (looksLikeJsonUtf8(buf)) return buf;

  const enc = (contentEncoding ?? "").toLowerCase().trim();
  if (!enc || enc === "identity" || enc === "none") return buf;
  if (enc === "gzip" || enc === "x-gzip") {
    try {
      return gunzipSync(buf);
    } catch {
      return buf;
    }
  }
  if (enc === "deflate") {
    try {
      return inflateSync(buf);
    } catch {
      try {
        return inflateRawSync(buf);
      } catch {
        return buf;
      }
    }
  }
  return buf;
}

export function normalizeSantaJson(raw: unknown): unknown {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return raw;
  const o = raw as Record<string, unknown>;
  const aliases: Record<string, string> = {
    serialNum: "serial_num",
    osVersion: "os_version",
    osBuild: "os_build",
    modelIdentifier: "model_identifier",
    santaVersion: "santa_version",
    primaryUser: "primary_user",
    clientMode: "client_mode",
    requestCleanSync: "request_clean_sync",
    binaryRuleCount: "binary_rule_count",
    certificateRuleCount: "certificate_rule_count",
    compilerRuleCount: "compiler_rule_count",
    transitiveRuleCount: "transitive_rule_count",
    teamidRuleCount: "teamid_rule_count",
    signingidRuleCount: "signingid_rule_count",
    cdhashRuleCount: "cdhash_rule_count",
    rulesReceived: "rules_received",
    rulesProcessed: "rules_processed",
  };
  const out: Record<string, unknown> = { ...o };
  for (const [camel, snake] of Object.entries(aliases)) {
    if (out[snake] === undefined && out[camel] !== undefined) {
      out[snake] = out[camel];
    }
  }
  return out;
}

export function parseSantaJsonBody(event: APIGatewayProxyEvent): unknown {
  const buf = rawBodyBuffer(event);
  if (buf.length === 0) return {};
  const decoded = decodeSantaBody(buf, getHeader(event, "content-encoding"));
  const text = decoded.toString("utf8").trim();
  if (!text) return {};
  return normalizeSantaJson(JSON.parse(text) as unknown);
}
