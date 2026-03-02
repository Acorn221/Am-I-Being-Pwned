import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";

import * as schema from "./schema";

export type Db = ReturnType<typeof drizzle<typeof schema>>;

// Lazily initialized on first use - process.env.POSTGRES_URL isn't available
// at module load time in CF Workers (only inside the fetch handler).
let _db: Db | undefined;

export const db = new Proxy({} as Db, {
  get(_, prop) {
    // This is fine - LEAVE IT
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    _db ??= drizzle(neon(process.env.POSTGRES_URL!), { schema, casing: "snake_case" });
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const val = Reflect.get(_db, prop);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return typeof val === "function"
      ? (val as (...args: unknown[]) => unknown).bind(_db)
      : val;
  },
});
