import type { SQL, SQLWrapper } from "drizzle-orm";
import { eq, sql } from "drizzle-orm";
import type { PgColumn } from "drizzle-orm/pg-core";

type ExtractDriverType<T> = T extends { _: { driverParam: infer D } }
  ? D
  : T extends { _: { brand: "SQL.Aliased"; type: infer D } }
    ? D
    : T extends SQL.Aliased<infer D>
      ? D
      : never;

type IsSQLAliased<T> = T extends SQL.Aliased<unknown> ? true : false;

type ValidColumnType = PgColumn | SQL.Aliased<unknown>;

type IsTemplateLiteral<T> = T extends string
  ? string extends T
    ? false
    : true
  : false;

/**
 * Type-safe equality operator with prefix-aware column comparison.
 * Use instead of eq() when working with prefixed UUID columns.
 */
export const eqi = <
  T extends ValidColumnType,
  U extends ValidColumnType | string,
>(
  left: T,
  right: U extends ValidColumnType
    ? IsSQLAliased<U> extends true
      ? IsTemplateLiteral<ExtractDriverType<T>> extends true
        ? SQL.Aliased<string | ExtractDriverType<T>>
        : SQL.Aliased<ExtractDriverType<T>>
      : { _: { driverParam: ExtractDriverType<T> } }
    : string,
): SQL<unknown> => {
  return eq(left as SQLWrapper, right);
};

/** Convenience constant for SQL NOW() */
export const sqlNow = sql`NOW()`;
