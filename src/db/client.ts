import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

export type Db = ReturnType<typeof createDb>;

export function createDb(connectionString: string) {
  // Small pool for Lambda; prefer RDS Proxy in AWS.
  const client = postgres(connectionString, { max: 1, idle_timeout: 20, connect_timeout: 10 });
  return drizzle(client, { schema });
}
