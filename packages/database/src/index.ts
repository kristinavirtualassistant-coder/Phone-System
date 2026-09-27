import pg from 'pg';
import type { PoolClient, QueryResult, QueryResultRow } from 'pg';
export type { PoolClient, QueryResult, QueryResultRow };

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
});

export interface TransactionContext {
  tenantId?: string | null;
  userId?: string | null;
  apiKeyHash?: string | null;
}

export async function withTransaction<T>(
  context: TransactionContext | string | null,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  const normalized: TransactionContext =
    typeof context === 'string' || context === null ? { tenantId: context } : context;

  try {
    await client.query('BEGIN');
    await client.query(
      `SELECT
        set_config('app.tenant_id', $1, true),
        set_config('app.user_id', $2, true),
        set_config('app.api_key_hash', $3, true)`,
      [
        normalized.tenantId ?? '',
        normalized.userId ?? '',
        normalized.apiKeyHash ?? '',
      ],
    );
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function query<T extends QueryResultRow>(
  text: string,
  values: unknown[] = [],
): Promise<QueryResult<T>> {
  return pool.query<T>(text, values);
}
