import { uuidv7 } from '@platform/domain';
import { withTransaction } from '@platform/database';

export async function writeAuditEvent(input: { tenantId: string | null; actorUserId?: string | null; action: string; resourceType?: string; resourceId?: string; ipAddress?: string; userAgent?: string; metadata?: Record<string, unknown>; }): Promise<void> {
  await withTransaction({tenantId: input.tenantId, userId: input.actorUserId ?? null}, async client => {
    await client.query(`INSERT INTO audit_events (id,tenant_id,actor_user_id,action,resource_type,resource_id,ip_address,user_agent,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [uuidv7(),input.tenantId??null,input.actorUserId??null,input.action,input.resourceType??null,input.resourceId??null,input.ipAddress??null,input.userAgent??null,input.metadata??null]);
  });
}

export interface OutboundCommunicationCheck {
  tenantId: string;
  destination: string;
  channel: 'SMS'|'MMS'|'EMAIL';
  requireConsent?: boolean;
  maxPerMinute?: number;
}
export async function assertOutboundCommunicationAllowed(input: OutboundCommunicationCheck): Promise<void> {
  const maxPerMinute = input.maxPerMinute ?? 30;
  const result = await withTransaction(input.tenantId, async tx => {
    const suppression = input.channel === 'EMAIL'
      ? await tx.query(`SELECT 1 FROM communication_contacts WHERE tenant_id=$1 AND lower(email)=lower($2) AND consent_status='OPTED_OUT'`, [input.tenantId, input.destination])
      : await tx.query(`SELECT 1 FROM contact_suppressions WHERE tenant_id=$1 AND phone_e164=$2 AND (expires_at IS NULL OR expires_at>NOW())`, [input.tenantId, input.destination]);
    if (suppression.rowCount) return 'suppressed';
    if (input.channel !== 'EMAIL' && input.requireConsent !== false) {
      const consent = await tx.query(`SELECT consent_status FROM communication_contacts WHERE tenant_id=$1 AND phone_e164=$2`, [input.tenantId, input.destination]);
      if (!consent.rows[0] || consent.rows[0].consent_status !== 'OPTED_IN') return 'consent_required';
    }
    const rate = await tx.query(`SELECT COUNT(*)::int AS count FROM messages WHERE tenant_id=$1 AND direction='OUTBOUND' AND channel=$2 AND created_at>NOW()-INTERVAL '1 minute'`, [input.tenantId,input.channel]);
    return Number(rate.rows[0]?.count ?? 0) >= maxPerMinute ? 'rate_limited' : 'ok';
  });
  if (result !== 'ok') {
    const messages: Record<string,string> = { suppressed:'Destination is suppressed or opted out', consent_required:'Documented consent is required before outbound messaging', rate_limited:'Outbound communication rate limit exceeded' };
    throw Object.assign(new Error(messages[result] ?? 'Communication blocked'), { statusCode: result === 'rate_limited' ? 429 : 409, code: `COMMUNICATION_${result.toUpperCase()}` });
  }
}

export async function recordOptOut(tenantId:string, phone:string, source='inbound') {
  return withTransaction(tenantId, async tx => {
    await tx.query(`INSERT INTO contact_suppressions(id,tenant_id,phone_e164,reason,source) VALUES($1,$2,$3,'OPT_OUT',$4) ON CONFLICT (tenant_id,phone_e164) DO UPDATE SET reason='OPT_OUT',source=EXCLUDED.source,expires_at=NULL`,[uuidv7(),tenantId,phone,source]);
    await tx.query(`UPDATE communication_contacts SET consent_status='OPTED_OUT',updated_at=NOW() WHERE tenant_id=$1 AND phone_e164=$2`,[tenantId,phone]);
  });
}
