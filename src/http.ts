import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

export const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, x-api-key, authorization",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Content-Type": "application/json",
};

export function json(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { ...CORS_HEADERS },
    body: JSON.stringify(body),
  };
}

export function noContent(): APIGatewayProxyResult {
  return {
    statusCode: 204,
    headers: { ...CORS_HEADERS },
    body: "",
  };
}

export function getHeader(event: APIGatewayProxyEvent, name: string): string | null {
  const headers = event.headers ?? {};
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === want) return v ?? null;
  }
  // Multi-value headers (some API GW configs)
  const mv = event.multiValueHeaders ?? {};
  for (const [k, v] of Object.entries(mv)) {
    if (k.toLowerCase() === want && v?.[0]) return v[0];
  }
  return null;
}

export function methodOf(event: APIGatewayProxyEvent): string {
  return (event.httpMethod || event.requestContext?.httpMethod || "GET").toUpperCase();
}

/** Normalize path: strip stage prefix (/dev, /Prod) when present. */
export function pathOf(event: APIGatewayProxyEvent): string {
  let p = event.path || event.requestContext?.resourcePath || "/";
  const stage = event.requestContext?.stage;
  if (stage && p.startsWith(`/${stage}/`)) {
    p = p.slice(stage.length + 1);
  } else if (stage && p === `/${stage}`) {
    p = "/";
  }
  // Ensure leading slash
  if (!p.startsWith("/")) p = `/${p}`;
  // Drop trailing slash except root
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

export function queryOf(event: APIGatewayProxyEvent): Record<string, string | undefined> {
  return (event.queryStringParameters ?? {}) as Record<string, string | undefined>;
}

export function parseJsonBody(event: APIGatewayProxyEvent): unknown {
  if (!event.body) return {};
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event.body;
  const text = raw.trim();
  if (!text) return {};
  return JSON.parse(text) as unknown;
}

export function rawBodyBuffer(event: APIGatewayProxyEvent): Buffer {
  if (!event.body) return Buffer.alloc(0);
  if (event.isBase64Encoded) return Buffer.from(event.body, "base64");
  return Buffer.from(event.body, "utf8");
}

export type RouteMatch = {
  params: Record<string, string>;
};

/** Match `/v1/hosts/{id}` style patterns against a path. */
export function matchPath(pattern: string, path: string): RouteMatch | null {
  const pp = pattern.split("/").filter(Boolean);
  const sp = path.split("/").filter(Boolean);
  if (pp.length !== sp.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < pp.length; i++) {
    const a = pp[i]!;
    const b = sp[i]!;
    if (a.startsWith("{") && a.endsWith("}")) {
      params[a.slice(1, -1)] = decodeURIComponent(b);
    } else if (a !== b) {
      return null;
    }
  }
  return { params };
}
