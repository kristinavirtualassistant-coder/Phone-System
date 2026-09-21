import pg from 'pg';
import { TelnyxClient, decryptProviderSecret } from '@platform/telephony';
import { uuidv7 } from '@platform/domain';

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 20 });
const adminPool = new Pool({ connectionString: process.env.DATABASE_ADMIN_URL ?? process.env.DATABASE_URL, max: 10 });
const concurrency = Math.max(1, Number(process.env.DIALER_CONCURRENCY ?? '5'));
const mode = process.env.DIALER_MODE === 'sequential' ? 'sequential' : 'parallel';
const pollMs = Math.max(250, Number(process.env.DIALER_POLL_MS ?? '1000'));
const publicApiOrigin = process.env.PUBLIC_API_ORIGIN;
const encryptionKey = process.env.TELEPHONY_ENCRYPTION_KEY ?? process.env.MFA_ENCRYPTION_KEY;
const running = new Set<string>();
let stopping = false;

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!process.env.DATABASE_ADMIN_URL) throw new Error('DATABASE_ADMIN_URL is required for cross-tenant queue claims');
if (!publicApiOrigin) throw new Error('PUBLIC_API_ORIGIN is required');
if (!encryptionKey) throw new Error('TELEPHONY_ENCRYPTION_KEY or MFA_ENCRYPTION_KEY is required');

async function claimBatch(limit: number) {
  const client = await adminPool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(`
      WITH candidates AS (
        SELECT id FROM calls
        WHERE state='QUEUED' AND next_attempt_at <= NOW() AND dial_attempts < max_attempts
        ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1
      )
      UPDATE calls c SET state='INITIATED', dial_attempts=c.dial_attempts+1
      FROM candidates x WHERE c.id=x.id
      RETURNING c.id,c.tenant_id,c.phone_number_id,c.to_number,c.dial_attempts,c.max_attempts`, [limit]);
    await client.query('COMMIT');
    return result.rows;
  } catch (error) {
    await client.query('ROLLBACK'); throw error;
  } finally { client.release(); }
}

async function processCall(call: any) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id',$1,true)`, [call.tenant_id]);
    const provider = await client.query(`
      SELECT p.api_key_encrypted,p.api_base_url,p.connection_id,p.id provider_id,n.e164
      FROM phone_numbers n JOIN telephony_providers p ON p.id=n.provider_id
      WHERE n.id=$1 AND n.tenant_id=$2 AND n.status='ACTIVE' AND p.status='ACTIVE'`, [call.phone_number_id, call.tenant_id]);
    const row = provider.rows[0];
    if (!row) throw new Error('Active telephony provider/number not found');
    const telnyx = new TelnyxClient({ apiKey: decryptProviderSecret(row.api_key_encrypted, encryptionKey!), baseUrl: row.api_base_url, connectionId: row.connection_id });
    const result = await telnyx.createCall({
      to: call.to_number,
      from: row.e164,
      connectionId: row.connection_id,
      webhookUrl: `${publicApiOrigin}/api/v1/webhooks/telnyx/${call.tenant_id}/${row.provider_id}`,
      commandId: call.id,
    });
    await client.query(`UPDATE calls SET provider_call_id=$2,started_at=COALESCE(started_at,NOW()),last_error=NULL WHERE id=$1`, [call.id, result.callControlId]);
    await client.query(`INSERT INTO call_legs(id,tenant_id,call_id,provider,provider_call_id,leg_index,state,from_number,to_number,started_at)
      VALUES($1,$2,$3,'telnyx',$4,0,'INITIATED',$5,$6,NOW())`, [uuidv7(),call.tenant_id,call.id,result.callControlId,row.e164,call.to_number]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    const message = error instanceof Error ? error.message : 'Dial attempt failed';
    const retry = call.dial_attempts < call.max_attempts;
    const recoveryClient = await adminPool.connect();
    try {
      await recoveryClient.query('BEGIN');
      await recoveryClient.query(`UPDATE calls SET state=$2,last_error=$3,next_attempt_at=NOW()+($4 || ' seconds')::interval,ended_at=CASE WHEN $2='FAILED' THEN NOW() ELSE ended_at END WHERE id=$1`, [call.id,retry?'QUEUED':'FAILED',message,retry ? Math.min(300, 2 ** call.dial_attempts * 5) : 0]);
      await recoveryClient.query('COMMIT');
    } catch (recoveryError) {
      await recoveryClient.query('ROLLBACK');
      console.error('dialer failure-state update failed', call.id, recoveryError);
    } finally {
      recoveryClient.release();
    }
  } finally { client.release(); }
}

async function purgeExpiredRecordings() {
  const client = await pool.connect();
  try {
    const result = await client.query(`
      SELECT r.id,r.tenant_id,r.provider_recording_id,p.api_key_encrypted,p.api_base_url
      FROM recordings r
      JOIN calls c ON c.id=r.call_id AND c.tenant_id=r.tenant_id
      JOIN phone_numbers n ON n.id=c.phone_number_id AND n.tenant_id=r.tenant_id
      JOIN telephony_providers p ON p.id=n.provider_id AND p.tenant_id=r.tenant_id
      WHERE r.status='AVAILABLE' AND r.expires_at IS NOT NULL AND r.expires_at <= NOW()
      ORDER BY r.expires_at
      LIMIT 50
    `);
    for (const recording of result.rows) {
      try {
        await client.query('SELECT set_config(\'app.tenant_id\',$1,true)', [recording.tenant_id]);
        const telnyx = new TelnyxClient({
          apiKey: decryptProviderSecret(recording.api_key_encrypted, encryptionKey!),
          baseUrl: recording.api_base_url,
        });
        await telnyx.deleteRecording(recording.provider_recording_id);
        await client.query(
          'UPDATE recordings SET status=\'DELETED\',storage_url=NULL WHERE id=$1 AND tenant_id=$2',
          [recording.id, recording.tenant_id],
        );
      } catch (error) {
        console.error('recording retention failed', recording.id, error);
        await client.query(
          'UPDATE recordings SET status=\'RETENTION_ERROR\' WHERE id=$1 AND tenant_id=$2',
          [recording.id, recording.tenant_id],
        );
      }
    }
  } finally {
    client.release();
  }
}

async function recoverStaleClaims() {
  const client = await adminPool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE calls SET state='QUEUED', next_attempt_at=NOW(), last_error='Recovered stale dialer claim'
      WHERE state='INITIATED' AND provider_call_id IS NULL AND started_at IS NULL
        AND created_at < NOW() - INTERVAL '2 minutes' AND dial_attempts < max_attempts`);
    await client.query(`UPDATE calls SET state='FAILED', ended_at=COALESCE(ended_at,NOW()), last_error='Dialer claim expired after max attempts'
      WHERE state='INITIATED' AND provider_call_id IS NULL AND started_at IS NULL
        AND created_at < NOW() - INTERVAL '2 minutes' AND dial_attempts >= max_attempts`);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

async function tick() {
  if (stopping) return;
  const slots = (mode === 'sequential' ? 1 : concurrency) - running.size;
  if (slots <= 0) return;
  const calls = await claimBatch(slots);
  for (const call of calls) {
    running.add(call.id);
    void processCall(call).finally(() => running.delete(call.id));
  }
}

const timer = setInterval(() => void tick().catch((error) => console.error('dialer tick failed', error)), pollMs);
const retentionTimer = setInterval(() => void purgeExpiredRecordings().catch((error) => console.error('recording retention failed', error)), 60_000);
const recoveryTimer = setInterval(() => void recoverStaleClaims().catch((error) => console.error('dialer recovery failed', error)), 30_000);
void tick();
void purgeExpiredRecordings();
void recoverStaleClaims();

async function shutdown() {
  if (stopping) return;
  stopping = true;
  clearInterval(timer);
  clearInterval(retentionTimer);
  clearInterval(recoveryTimer);
  while (running.size) await new Promise((resolve) => setTimeout(resolve, 100));
  await pool.end();
  await adminPool.end();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
console.log(`worker dialer ready mode=${mode} concurrency=${mode === 'sequential' ? 1 : concurrency}`);
