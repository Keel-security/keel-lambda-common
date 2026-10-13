import { createDb, type Db } from "./db/client";

let _db: Db | null = null;

/** Lazy singleton — safe for Lambda warm starts (RDS Proxy recommended). */
export function getDb(): Db {
  if (_db) return _db;
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new Error("DATABASE_URL is required");
  }
  _db = createDb(url);
  return _db;
}
