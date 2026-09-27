import { randomUUID } from 'node:crypto';
import { withTransaction } from '@platform/database';

export async function writeAuditEvent(input: {
  tenantId: string | null;
  actorUserId?: string | null;
  action: string;
  resourceType?: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  await withTransaction(
    { tenantId: input.tenantId, userId: input.actorUserId ?? null },
    async (client) => {
      await client.query(
        `INSERT INTO audit_events
          (id, tenant_id, actor_user_id, action, resource_type, resource_id, ip_address, user_agent, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          randomUUID(), input.tenantId ?? null, input.actorUserId ?? null, input.action,
          input.resourceType ?? null, input.resourceId ?? null, input.ipAddress ?? null,
          input.userAgent ?? null, input.metadata ?? null,
        ],
      );
    },
  );
}
