import { randomUUID } from 'node:crypto';

export function uuidv7(): string {
  return randomUUID();
}
