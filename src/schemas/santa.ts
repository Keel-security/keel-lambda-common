import { z } from "zod";

/** Santa sync protocol (JSON) — see https://santa.dev/development/sync-protocol.html */

/** Santa ClientMode: string enums from protobuf JSON, or legacy ints 1/2/3. */
export const SantaClientModeSchema = z.preprocess((v) => {
  if (v === 1 || v === "1") return "MONITOR";
  if (v === 2 || v === "2") return "LOCKDOWN";
  if (v === 3 || v === "3") return "STANDALONE";
  return v;
}, z.enum(["MONITOR", "LOCKDOWN", "STANDALONE", "UNKNOWN_CLIENT_MODE"]).optional());
export type SantaClientMode = "MONITOR" | "LOCKDOWN" | "STANDALONE";

export const SantaPreflightRequestSchema = z
  .object({
    serial_num: z.string().optional(),
    hostname: z.string().min(1),
    os_version: z.union([z.string(), z.number()]).optional().transform((v) => String(v ?? "")),
    os_build: z.union([z.string(), z.number()]).optional().transform((v) => String(v ?? "")),
    model_identifier: z.string().optional(),
    santa_version: z.union([z.string(), z.number()]).optional().transform((v) => String(v ?? "")),
    primary_user: z.string().optional().default(""),
    client_mode: SantaClientModeSchema,
    request_clean_sync: z.boolean().optional(),
    binary_rule_count: z.number().optional(),
    certificate_rule_count: z.number().optional(),
    teamid_rule_count: z.number().optional(),
    signingid_rule_count: z.number().optional(),
    cdhash_rule_count: z.number().optional(),
  })
  .passthrough();
export type SantaPreflightRequest = z.infer<typeof SantaPreflightRequestSchema>;

export const SantaDecisionSchema = z.string();

export const SantaEventSchema = z
  .object({
    file_sha256: z.string().min(1),
    file_path: z.string().min(1),
    file_name: z.string().min(1),
    decision: SantaDecisionSchema,
    executing_user: z.string().optional(),
    execution_time: z.number().optional(),
    pid: z.number().optional(),
    ppid: z.number().optional(),
    parent_name: z.string().optional(),
    signing_id: z.string().optional(),
    team_id: z.string().optional(),
    cdhash: z.string().optional(),
  })
  .passthrough();
export type SantaEvent = z.infer<typeof SantaEventSchema>;

export const SantaEventUploadRequestSchema = z.object({
  events: z.array(SantaEventSchema).default([]),
});
export type SantaEventUploadRequest = z.infer<typeof SantaEventUploadRequestSchema>;

export const SantaRuleDownloadRequestSchema = z
  .object({
    cursor: z.string().optional(),
  })
  .passthrough();

export const SantaPostflightRequestSchema = z
  .object({
    rules_received: z.number().int().nonnegative(),
    rules_processed: z.number().int().nonnegative(),
  })
  .passthrough();

/** Map Santa decision → Keel sensor_events.decision */
export function santaDecisionToKeel(decision: string): "allow" | "deny" | "observe" {
  const d = decision.toUpperCase();
  if (d.startsWith("BLOCK_") || d === "SILENT_BLOCKLIST") return "deny";
  if (d.startsWith("ALLOW_")) return "observe";
  if (d === "BUNDLE_BINARY") return "observe";
  return "observe";
}

export function santaSubject(ev: SantaEvent): string {
  if (ev.file_path.endsWith(ev.file_name) || ev.file_path.endsWith(`/${ev.file_name}`)) {
    return ev.file_path;
  }
  return `${ev.file_path.replace(/\/$/, "")}/${ev.file_name}`;
}
