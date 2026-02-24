import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";

import * as schema from "./schema";

type Db = ReturnType<typeof drizzle<typeof schema>>;

let _db: Db | undefined;
let _url: string | undefined;

/**
 * Must be called once per isolate with the worker's env.POSTGRES_URL
 * before any DB query runs. CF Workers don't expose env bindings on
 * process.env with nodejs_compat (v1), so we accept it explicitly.
 */
export function initDb(url: string): void {
  if (_url !== url) {
    _url = url;
    _db = undefined; // recreate on URL change (supports wrangler hot reload)
  }
}

function getDb(): Db {
  if (!_db) {
    const url = _url ?? process.env.POSTGRES_URL;
    if (!url) {
      throw new Error(
        "No DB URL — call initDb(env.POSTGRES_URL) at the start of the fetch handler",
      );
    }
    _db = drizzle(neon(url), { schema, casing: "snake_case" });
  }
  return _db;
}

export const db = new Proxy({} as Db, {
  get(_, prop) {
    return Reflect.get(getDb(), prop);
  },
});
