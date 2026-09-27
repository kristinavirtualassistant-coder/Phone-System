import type { PoolClient } from '@platform/database';

export async function revokeUserSessions(
  client: PoolClient,
  userId: string,
): Promise<void> {
  await client.query(
    `UPDATE sessions
     SET revoked_at=NOW()
     WHERE user_id=$1 AND revoked_at IS NULL`,
    [userId],
  );
}

export async function consumePasswordResetToken(
  client: PoolClient,
  tokenHash: string,
): Promise<string | null> {
  const result = await client.query<{ user_id: string }>(
    `UPDATE password_reset_tokens
     SET used_at=NOW()
     WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW()
     RETURNING user_id`,
    [tokenHash],
  );
  return result.rows[0]?.user_id ?? null;
}
