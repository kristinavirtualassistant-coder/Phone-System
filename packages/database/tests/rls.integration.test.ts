import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';

const { Client } = pg;

const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)('PostgreSQL tenant isolation', () => {
  let client: pg.Client;
  const tenantA = '0199f7b0-0000-7000-8000-000000000001';
  const tenantB = '0199f7b0-0000-7000-8000-000000000002';
  const userA = '0199f7b0-0000-7000-8000-000000000011';
  const userB = '0199f7b0-0000-7000-8000-000000000012';

  beforeAll(async () => {
    client = new Client({ connectionString: databaseUrl });
    await client.connect();

    await client.query('BEGIN');
    await client.query('SET LOCAL ROLE postgres');

    await client.query(
      `INSERT INTO tenants(id,name) VALUES ($1,'RLS Test A'),($2,'RLS Test B')
       ON CONFLICT (id) DO NOTHING`,
      [tenantA, tenantB],
    );

    await client.query(
      `INSERT INTO users(id,email,email_normalized,password_hash)
       VALUES ($1,'rls-a@example.invalid','rls-a@example.invalid','test'),
              ($2,'rls-b@example.invalid','rls-b@example.invalid','test')
       ON CONFLICT (id) DO NOTHING`,
      [userA, userB],
    );

    await client.query(
      `INSERT INTO tenant_memberships(id,tenant_id,user_id,role)
       VALUES ('0199f7b0-0000-7000-8000-000000000021',$1,$3,'OWNER'),
              ('0199f7b0-0000-7000-8000-000000000022',$2,$4,'OWNER')
       ON CONFLICT (id) DO NOTHING`,
      [tenantA, tenantB, userA, userB],
    );
    await client.query('COMMIT');
  });

  afterAll(async () => {
    await client.query('BEGIN');
    await client.query('SET LOCAL ROLE postgres');
    await client.query(
      'DELETE FROM tenant_memberships WHERE tenant_id IN ($1,$2)',
      [tenantA, tenantB],
    );
    await client.query('DELETE FROM users WHERE id IN ($1,$2)', [userA, userB]);
    await client.query('DELETE FROM tenants WHERE id IN ($1,$2)', [tenantA, tenantB]);
    await client.query('COMMIT');
    await client.end();
  });

  async function asTenant(tenantId: string, userId: string) {
    await client.query('BEGIN');
    await client.query('SET LOCAL ROLE platform_app');
    await client.query(
      `SELECT
        set_config('app.tenant_id',$1,true),
        set_config('app.user_id',$2,true),
        set_config('app.api_key_hash','',true)`,
      [tenantId, userId],
    );
  }

  it('allows the active tenant membership', async () => {
    await asTenant(tenantA, userA);
    const result = await client.query(
      'SELECT tenant_id,user_id FROM tenant_memberships ORDER BY id',
    );
    await client.query('ROLLBACK');

    expect(result.rows).toEqual([
      { tenant_id: tenantA, user_id: userA },
    ]);
  });

  it('blocks SELECT across tenants', async () => {
    await asTenant(tenantA, userA);
    const result = await client.query(
      'SELECT tenant_id,user_id FROM tenant_memberships WHERE tenant_id=$1',
      [tenantB],
    );
    await client.query('ROLLBACK');

    expect(result.rowCount).toBe(0);
  });

  it('blocks UPDATE across tenants', async () => {
    await asTenant(tenantA, userA);
    const result = await client.query(
      `UPDATE tenant_memberships SET role='ADMIN'
       WHERE tenant_id=$1 RETURNING id`,
      [tenantB],
    );
    await client.query('ROLLBACK');

    expect(result.rowCount).toBe(0);
  });

  it('blocks DELETE across tenants', async () => {
    await asTenant(tenantA, userA);
    const result = await client.query(
      'DELETE FROM tenant_memberships WHERE tenant_id=$1 RETURNING id',
      [tenantB],
    );
    await client.query('ROLLBACK');

    expect(result.rowCount).toBe(0);
  });

  it('rejects INSERT into another tenant', async () => {
    await asTenant(tenantA, userA);
    await expect(
      client.query(
        `INSERT INTO tenant_memberships(id,tenant_id,user_id,role)
         VALUES ('0199f7b0-0000-7000-8000-000000000099',$1,$2,'AGENT')`,
        [tenantB, userA],
      ),
    ).rejects.toThrow();
    await client.query('ROLLBACK');
  });
});