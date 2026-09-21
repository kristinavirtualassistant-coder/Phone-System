export const MESSAGE_STATES = ['QUEUED','SENT','DELIVERED','FAILED','RECEIVED','OPTED_OUT'] as const;
export type MessageState = typeof MESSAGE_STATES[number];
export type MessageChannel = 'SMS'|'MMS'|'EMAIL';
export type MessageDirection = 'INBOUND'|'OUTBOUND';

const rank: Record<MessageState, number> = { QUEUED: 0, SENT: 1, DELIVERED: 2, FAILED: 3, RECEIVED: 3, OPTED_OUT: 4 };
export function canTransitionMessage(current: MessageState, next: MessageState): boolean {
  if (current === next) return true;
  if (current === 'QUEUED') return ['SENT','FAILED','OPTED_OUT'].includes(next);
  if (current === 'SENT') return ['DELIVERED','FAILED'].includes(next);
  if (current === 'DELIVERED' || current === 'FAILED' || current === 'RECEIVED' || current === 'OPTED_OUT') return false;
  return rank[next] >= rank[current];
}
export function assertMessageTransition(current: MessageState, next: MessageState): void {
  if (!canTransitionMessage(current, next)) throw new Error(`Invalid message transition ${current} -> ${next}`);
}
export function normalizePhone(phone: string): string {
  const value = phone.trim().replace(/[().\s-]/g, '');
  if (!/^\+[1-9]\d{7,14}$/.test(value)) throw new Error('Phone number must be E.164');
  return value;
}
export function normalizeEmailAddress(email: string): string {
  const value = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) throw new Error('Invalid email address');
  return value;
}
export function validateTemplateVariables(body: string, allowed: string[], values: Record<string, unknown>): void {
  const used = Array.from(body.matchAll(/\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}/g)).map(m => m[1]);
  for (const name of used) {
    if (!name || !allowed.includes(name)) throw new Error(`Template variable not allowed: ${name ?? ''}`);
    if (values[name] === undefined || values[name] === null) throw new Error(`Template variable missing: ${name}`);
  }
}
export interface SmsSendInput { from: string; to: string; text: string; mediaUrls?: string[]; idempotencyKey?: string; }
export interface MessagingProvider { send(input: SmsSendInput): Promise<{providerMessageId: string; status: MessageState; raw: unknown}>; }
export function normalizeProviderStatus(value: string): MessageState {
  const v = value.toLowerCase();
  if (['queued','accepted','pending'].includes(v)) return 'QUEUED';
  if (['sent','sending'].includes(v)) return 'SENT';
  if (['delivered','delivery_report'].includes(v)) return 'DELIVERED';
  if (['failed','undelivered','error'].includes(v)) return 'FAILED';
  if (['received','inbound'].includes(v)) return 'RECEIVED';
  if (['opted_out','opt-out','blocked'].includes(v)) return 'OPTED_OUT';
  return 'FAILED';
}