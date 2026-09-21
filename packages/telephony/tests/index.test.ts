import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { TelnyxClient, assertTransition, canTransition, normalizeE164 } from '../src/index.js';

describe('telephony state machine', () => {
  it('allows normal outbound progression', () => {
    expect(canTransition('QUEUED', 'INITIATED')).toBe(true);
    expect(canTransition('INITIATED', 'RINGING')).toBe(true);
    expect(canTransition('RINGING', 'ANSWERED')).toBe(true);
    expect(canTransition('ANSWERED', 'ENDED')).toBe(true);
    expect(() => assertTransition('ENDED', 'ANSWERED')).toThrow();
  });

  it('normalizes and validates E.164', () => {
    expect(normalizeE164('+1 (555) 123-4567')).toBe('+15551234567');
    expect(() => normalizeE164('5551234')).toThrow();
  });
});

describe('Telnyx webhook verification', () => {
  it('accepts a valid Ed25519 signature and rejects stale timestamps', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const raw = Buffer.from(JSON.stringify({ data: { id: 'evt_1' } }));
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = sign(null, Buffer.from(`${timestamp}|${raw.toString('utf8')}`), privateKey).toString('base64');
    const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const client = new TelnyxClient({ apiKey: 'test', publicKey: publicKeyDer });
    expect(client.verifyWebhook(raw, signature, timestamp)).toBe(true);
    expect(client.verifyWebhook(raw, signature, String(Number(timestamp) - 1000))).toBe(false);
  });
});
