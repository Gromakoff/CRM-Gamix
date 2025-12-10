import type { D1Database } from '@cloudflare/workers-types';

export async function runQuery<T = unknown>(db: D1Database, sql: string, bindings: unknown[] = []): Promise<T[]> {
  const statement = db.prepare(sql).bind(...bindings);
  const result = await statement.all<T>();
  return result.results ?? [];
}

export async function getFirst<T = unknown>(db: D1Database, sql: string, bindings: unknown[] = []): Promise<T | null> {
  const rows = await runQuery<T>(db, sql, bindings);
  return rows.length ? rows[0] : null;
}

export async function execute(db: D1Database, sql: string, bindings: unknown[] = []): Promise<number> {
  const statement = db.prepare(sql).bind(...bindings);
  const result = await statement.run();
  return result.lastInsertRowId ?? 0;
}
