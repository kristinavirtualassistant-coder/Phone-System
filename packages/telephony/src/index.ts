import { createCipheriv, createDecipheriv, createPublicKey, verify as verifySignature } from 'node:crypto';
import { uuidv7 } from '@platform/domain';

export const CALL_STATES = [
  'QUEUED','INITIATED','RINGING','ANSWERED','BRIDGED','ON_HOLD','ENDED','FAILED','CANCELED'
] as const;
export type CallState = (typeof CALL_STATES)[number];

const TRANSITIONS: Record<CallState, readonly CallState[]> = {
  QUEUED: ['INITIATED','CANCELED'],
  INITIATED: ['RINGING','ANSWERED','FAILED','CANCELED','ENDED'],
  RINGING: ['ANSWERED','FAILED','CANCELED','ENDED'],
  ANSWERED: ['BRIDGED','ON_HOLD','ENDED','FAILED'],
  BRIDGED: ['ON_HOLD','ENDED','FAILED'],
  ON_HOLD: ['BRIDGED','ANSWERED','ENDED','FAILED'],
  ENDED: [],
  FAILED: [],
  CANCELED: [],
};

export function canTransition(from: CallState, to: CallState): boolean {
  return from === to || TRANSITIONS[from].includes(to);
}

export function assertTransition(from: CallState, to: CallState): void {
  if (!canTransition(from, to)) throw new Error(`Invalid call transition: ${from} -> ${to}`);
}

export function normalizeE164(value: string): string {
  const normalized = value.replace(/[\s().-]/g, '');
  if (!/^\+[1-9]\d{7,14}$/.test(normalized)) throw new Error('Phone number must be valid E.164');
  return normalized;
}

export interface TelnyxProviderConfig {
  apiKey: string;
  baseUrl?: string | undefined;
  connectionId?: string | undefined;
  publicKey?: string | undefined;
}

export interface CreateCallInput {
  to: string;
  from: string;
  connectionId?: string | undefined;
  webhookUrl?: string | undefined;
  commandId?: string | undefined;
  clientState?: string | undefined;
  answeringMachineDetection?: boolean;
}

export interface TelnyxCallResponse {
  id: string;
  callControlId: string;
  callSessionId?: string | undefined;
  callLegId?: string | undefined;
}

export class TelnyxClient {
  readonly baseUrl: string;
  constructor(private readonly config: TelnyxProviderConfig) {
    this.baseUrl = config.baseUrl ?? 'https://api.telnyx.com/v2';
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${this.config.apiKey}`,
        'content-type': 'application/json',
        ...(init.headers ?? {}),
      },
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`Telnyx ${response.status}: ${text.slice(0, 1000)}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  async createCall(input: CreateCallInput): Promise<TelnyxCallResponse> {
    const payload = {
      to: normalizeE164(input.to),
      from: normalizeE164(input.from),
      connection_id: input.connectionId ?? this.config.connectionId,
      webhook_url: input.webhookUrl,
      command_id: input.commandId ?? uuidv7(),
      client_state: input.clientState,
      answering_machine_detection: input.answeringMachineDetection ? 'premium' : undefined,
    };
    if (!payload.connection_id) throw new Error('Telnyx connection_id is required');
    const result = await this.request<{ data: { id: string; call_control_id: string; call_session_id?: string; call_leg_id?: string } }>('/calls', {
      method: 'POST', body: JSON.stringify(payload),
    });
    return {
      id: result.data.id,
      callControlId: result.data.call_control_id,
      callSessionId: result.data.call_session_id,
      callLegId: result.data.call_leg_id,
    };
  }

  async createTelephonyCredential(name: string, connectionId: string, expiresAt?: string): Promise<{ id: string }> {
    const result = await this.request<{ data: { id: string } }>('/telephony_credentials', {
      method: 'POST', body: JSON.stringify({ name, connection_id: connectionId, expires_at: expiresAt }),
    });
    return { id: result.data.id };
  }

  async createCredentialToken(credentialId: string): Promise<string> {
    const response = await fetch(`${this.baseUrl}/telephony_credentials/${encodeURIComponent(credentialId)}/token`, {
      method: 'POST', headers: { accept: 'text/plain', authorization: `Bearer ${this.config.apiKey}` },
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`Telnyx ${response.status}: ${text.slice(0, 1000)}`);
    return text.trim();
  }

  async deleteRecording(recordingId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/recordings/${encodeURIComponent(recordingId)}`, {
      method: 'DELETE',
      headers: { accept: 'application/json', authorization: `Bearer ${this.config.apiKey}` },
    });
    if (!response.ok && response.status !== 404) {
      const text = await response.text();
      throw new Error(`Telnyx ${response.status}: ${text.slice(0, 1000)}`);
    }
  }

  verifyWebhook(rawBody: Buffer | string, signature: string, timestamp: string, maxAgeSeconds = 300): boolean {
    if (!this.config.publicKey || !signature || !timestamp) return false;
    const ts = Number(timestamp);
    if (!Number.isSafeInteger(ts) || Math.abs(Date.now() / 1000 - ts) > maxAgeSeconds) return false;
    const message = Buffer.from(`${timestamp}|${Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody}`, 'utf8');
    const sig = Buffer.from(signature, 'base64');
    try {
      const key = createPublicKey({ key: Buffer.from(this.config.publicKey, 'base64'), format: 'der', type: 'spki' });
      return verifySignature(null, message, key, sig);
    } catch {
      return false;
    }
  }
}

export function webhookEventId(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const data = (body as { data?: { id?: unknown } }).data;
  return typeof data?.id === 'string' ? data.id : undefined;
}

export function webhookEventType(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const data = (body as { data?: { event_type?: unknown } }).data;
  return typeof data?.event_type === 'string' ? data.event_type : undefined;
}

export function decryptProviderSecret(value: string, encodedKey: string): string {
  const payload = Buffer.from(value, 'base64');
  if (payload.length < 29) throw new Error('Invalid encrypted provider secret');
  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(12, 28);
  const ciphertext = payload.subarray(28);
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(encodedKey, 'base64'), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}
