import type {
  AnyPgColumn,
  AnyPgTable,
  PgColumnBuilderBase,
  PgTableExtraConfigValue,
  PgTableWithColumns,
  UpdateDeleteAction,
} from "drizzle-orm/pg-core";
import type { BuildColumns, BuildExtraConfigColumns } from "drizzle-orm";
import type { SQL } from "drizzle-orm/sql";
import { customType, pgTable, timestamp } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm/sql";

// ---------------------------------------------------------------------------
// Prefixed UUID
// Infrastructure is in place — uncomment the body of fromDriver/toDriver
// to enable IDs like "extension_550e8400-e29b-41d4-a716-...".
// ---------------------------------------------------------------------------

type PrefixedId<TableName extends string> = `${TableName}_${string}`;

export function createPrefixedUuid<TIdName extends string>(
  _nameFn: () => TIdName,
) {
  return customType<{
    data: string;
    driverData: PrefixedId<TIdName>;
  }>({
    dataType: () => "uuid",
    fromDriver: (val): PrefixedId<TIdName> => {
      return val;
      // Uncomment to enable prefixed IDs:
      // return `${_nameFn()}_${val}` as PrefixedId<TIdName>;
    },
    toDriver: (val) => {
      return val as PrefixedId<TIdName>;
      // Uncomment to enable prefixed IDs:
      // const lastUnderscore = val.lastIndexOf("_");
      // return (lastUnderscore !== -1 ? val.substring(lastUnderscore + 1) : val) as PrefixedId<TIdName>;
    },
  });
}

// ---------------------------------------------------------------------------
// Primary key helper
// ---------------------------------------------------------------------------

export function pk<TableName extends string>(tableNameFn: () => TableName) {
  type IdName = `${TableName}_id`;
  return createPrefixedUuid<IdName>(() => `${tableNameFn()}_id`)()
    .primaryKey()
    .notNull()
    .default(sql`gen_random_uuid()`);
}

// ---------------------------------------------------------------------------
// Foreign key helper
// Use this for FKs between your own tables (UUID IDs).
// For FKs to the better-auth user table (text ID), use plain `.references()`.
// ---------------------------------------------------------------------------

type ExtractTableName<T> = T extends { _: { name: infer N extends string } }
  ? N
  : never;

export function fk<
  T extends { id: AnyPgColumn; _: { name: string } } & AnyPgTable,
>(
  columnName: string,
  referencedTableFn: () => T,
  options?: {
    onDelete?: UpdateDeleteAction;
    onUpdate?: UpdateDeleteAction;
    column?: () => AnyPgColumn;
  },
) {
  type TIdName = `${ExtractTableName<T>}_id`;
  const getColumnName = () => columnName as TIdName;

  return createPrefixedUuid<TIdName>(getColumnName)(columnName).references(
    () => (options?.column ? options.column() : referencedTableFn().id),
    {
      onDelete: options?.onDelete,
      onUpdate: options?.onUpdate,
    },
  );
}

// ---------------------------------------------------------------------------
// Case-insensitive SQL wrapper (useful for indexes)
// ---------------------------------------------------------------------------

export function lower(column: AnyPgColumn): SQL {
  return sql`lower(${column})`;
}

// ---------------------------------------------------------------------------
// Base fields & createTable
// ---------------------------------------------------------------------------

type ColumnDefinitions = Record<string, PgColumnBuilderBase>;

export const createBaseFields = <TableName extends string>(
  tableName: TableName,
) => ({
  id: pk<TableName>(() => tableName),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at")
    .defaultNow()
    .$onUpdate(() => new Date())
    .notNull(),
});

export const BASE_FIELD_NAMES = {
  id: true,
  createdAt: true,
  updatedAt: true,
} as const satisfies Record<string, boolean>;

type BaseFields<TableName extends string> = ReturnType<
  typeof createBaseFields<TableName>
>;

type HasCustomId<T> = T extends { id: PgColumnBuilderBase } ? true : false;

type MergeWithBaseFields<
  CustomColumns extends ColumnDefinitions,
  TableName extends string,
> =
  HasCustomId<CustomColumns> extends true
    ? CustomColumns & Omit<BaseFields<TableName>, "id">
    : CustomColumns & BaseFields<TableName>;

type TableResult<
  TableName extends string,
  CustomColumns extends ColumnDefinitions,
> = PgTableWithColumns<{
  name: TableName;
  schema: undefined;
  columns: BuildColumns<
    TableName,
    MergeWithBaseFields<CustomColumns, TableName>,
    "pg"
  >;
  dialect: "pg";
}>;

/**
 * Drop-in replacement for pgTable that automatically adds id, createdAt,
 * updatedAt to every table. Supply your own `id` column to override just the
 * primary key while keeping the timestamps.
 */
export function createTable<
  TableName extends string,
  CustomColumns extends ColumnDefinitions,
>(
  tableName: TableName,
  columns: CustomColumns,
  extraConfig?: (
    tableColumns: BuildExtraConfigColumns<
      TableName,
      MergeWithBaseFields<CustomColumns, TableName>,
      "pg"
    >,
  ) => PgTableExtraConfigValue[],
): TableResult<TableName, CustomColumns> {
  const baseFields = createBaseFields<TableName>(tableName);
  const hasCustomId = "id" in columns;

  const allColumns = {
    ...(hasCustomId
      ? { createdAt: baseFields.createdAt, updatedAt: baseFields.updatedAt }
      : baseFields),
    ...columns,
  } as MergeWithBaseFields<CustomColumns, TableName>;

  return pgTable(tableName, allColumns, extraConfig);
}
