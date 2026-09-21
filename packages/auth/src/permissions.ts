import type { Permission, Role } from '@platform/domain/types';

const BASE: Record<Role, readonly Permission[]> = {
  OWNER: ['tenant.read','tenant.update','users.read','users.manage','campaigns.read','campaigns.manage','contacts.read','contacts.manage','billing.read','billing.manage','recordings.read','audit.read','telephony.read','telephony.manage'],
  ADMIN: ['tenant.read','tenant.update','users.read','users.manage','campaigns.read','campaigns.manage','contacts.read','contacts.manage','billing.read','billing.manage','recordings.read','audit.read','telephony.read','telephony.manage'],
  MANAGER: ['tenant.read','users.read','campaigns.read','campaigns.manage','contacts.read','contacts.manage','recordings.read','audit.read','telephony.read','telephony.manage'],
  AGENT: ['tenant.read','campaigns.read','contacts.read','contacts.manage','recordings.read'],
  READ_ONLY: ['tenant.read','campaigns.read','contacts.read'],
};

export function hasPermission(role: Role, permission: Permission): boolean {
  return BASE[role].includes(permission);
}
