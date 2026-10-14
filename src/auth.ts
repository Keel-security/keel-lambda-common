import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { apiKeys } from "./db/schema";
import { getDb } from "./db";
import { getHeader, json } from "./http";

export function hashApiKey(key: string) {
  return createHash("sha256").update(key).digest("hex");
}

export type AuthContext = {
  orgId: string;
  /** Present when authenticated via x-api-key (agents/sensors). */
  keyId?: string;
  /** Cognito `sub` when authenticated via JWT. */
  userId?: string;
  email?: string;
  via: "api_key" | "jwt";
};

let jwtVerifier: ReturnType<typeof CognitoJwtVerifier.create> | null = null;

function getJwtVerifier() {
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const clientId = process.env.COGNITO_CLIENT_ID;
  if (!userPoolId || !clientId) return null;
  if (!jwtVerifier) {
    // ID token carries email + custom:org_id for the browser UI.
    jwtVerifier = CognitoJwtVerifier.create({
      userPoolId,
      tokenUse: "id",
      clientId,
    });
  }
  return jwtVerifier;
}

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
  return { orgId: row.orgId, keyId: row.id, via: "api_key" };
}

async function requireJwt(
  event: APIGatewayProxyEvent,
): Promise<AuthContext | APIGatewayProxyResult> {
  const verifier = getJwtVerifier();
  if (!verifier) {
    return json(401, { error: "jwt auth not configured" });
  }
  const header = getHeader(event, "authorization");
  if (!header?.toLowerCase().startsWith("bearer ")) {
    return json(401, { error: "missing bearer token" });
  }
  const token = header.slice(7).trim();
  try {
    const payload = await verifier.verify(token);
    const orgId =
      (typeof payload["custom:org_id"] === "string" && payload["custom:org_id"]) ||
      (typeof payload["org_id"] === "string" && payload["org_id"]) ||
      "";
    if (!orgId) {
      return json(403, {
        error: "user not linked to an org",
        hint: "Set Cognito custom:org_id to a Keel org UUID",
      });
    }
    return {
      orgId,
      userId: String(payload.sub),
      email: typeof payload.email === "string" ? payload.email : undefined,
      via: "jwt",
    };
  } catch {
    return json(401, { error: "invalid or expired token" });
  }
}

/**
 * Browser: `Authorization: Bearer <Cognito ID token>`
 * Agents/sensors: `x-api-key: <key>`
 */
export async function requireAuth(
  event: APIGatewayProxyEvent,
): Promise<AuthContext | APIGatewayProxyResult> {
  const authz = getHeader(event, "authorization");
  if (authz?.toLowerCase().startsWith("bearer ")) {
    return requireJwt(event);
  }
  return requireApiKey(event);
}

export function isAuthError(
  v: AuthContext | APIGatewayProxyResult,
): v is APIGatewayProxyResult {
  return typeof v === "object" && v !== null && "statusCode" in v;
}
