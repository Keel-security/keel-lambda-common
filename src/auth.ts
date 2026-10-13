import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { apiKeys } from "./db/schema";
import { getDb } from "./db";
import { getHeader, json } from "./http";

export function hashApiKey(key: string) {
  return createHash("sha256").update(key).digest("hex");
}

export type AuthContext = {
  orgId: string;
  keyId: string;
};

export async function requireApiKey(
  event: APIGatewayProxyEvent,
): Promise<AuthContext | APIGatewayProxyResult> {
  const key = getHeader(event, "x-api-key");
  if (!key) {
    return json(401, { error: "missing x-api-key" });
  }
  const keyHash = hashApiKey(key);
  const rows = await getDb()
    .select()
    .from(apiKeys)
    .where(eq(apiKeys.keyHash, keyHash))
    .limit(1);
  const row = rows[0];
  if (!row) {
    return json(401, { error: "invalid api key" });
  }
  return { orgId: row.orgId, keyId: row.id };
}

export function isAuthError(
  v: AuthContext | APIGatewayProxyResult,
): v is APIGatewayProxyResult {
  return typeof v === "object" && v !== null && "statusCode" in v;
}
