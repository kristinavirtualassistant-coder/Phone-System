import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { Redis } from 'ioredis';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import {
  generateRecoveryCodes, hashPassword, hashRecoveryCode, hashSecret,
  hasPermission, normalizeEmail, randomToken, verifyPassword, verifyRecoveryCode,
  verifySecret, verifyTotp, createTotpSecret, createTotpUri,
} from '@platform/auth';
import { query, withTransaction } from '@platform/database';
import { writeAuditEvent } from '@platform/compliance';
import { logger } from '@platform/observability';
import { config } from './config.js';
import { decryptMfaSecret, encryptMfaSecret, secret, sha256 } from './security.js';

const redis = new Redis(config.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 2 });
const app = Fastify({
  loggerInstance: logger,
  genReqId: () => randomUUID(),
  trustProxy: true,
});

await app.register(cookie, { secret: secret(32) });
await app.register(cors, { origin: config.WEB_ORIGIN, credentials: true });
await app.register(helmet);
await app.register(rateLimit, {
  global: false,
  redis,
  keyGenerator: (request) => `${request.ip}:${request.routeOptions.url ?? request.url}`,
});

declare module 'fastify' {
  interface FastifyRequest {
    userId?: string;
    tenantId?: string;
    role?: import('@platform/domain/types').Role;
    authType?: 'session' | 'api_key';
  }
}

const ALLOWED_API_KEY_SCOPES = [
  'tenant.settings',
  'users.manage',
  'campaigns.manage',
  'contacts.manage',
  'billing.manage',
  'audit.read',
  'recordings.read',
] as const;

function ok<T>(requestId: string, data: T, meta: Record<string, unknown> = {}) {
  return { data, meta: { request_id: requestId, ...meta } };
}
function fail(requestId: string, statusCode: number, code: string, message: string, details?: unknown) {
  return { statusCode, body: { error: { code, message, details }, meta: { request_id: requestId } } };
}

async function resolveTenant(
  userId: string,
  tenantId: string,
): Promise<{ role: import('@platform/domain/types').Role } | null> {
  return withTransaction({ tenantId, userId }, async (client) => {
    const result = await client.query<{ role: import('@platform/domain/types').Role }>(
      'SELECT role FROM tenant_memberships WHERE user_id=$1 AND tenant_id=$2 AND status=$3',
      [userId, tenantId, 'ACTIVE'],
    );
    return result.rows[0] ?? null;
  });
}

async function authenticate(request: import('fastify').FastifyRequest, reply: import('fastify').FastifyReply) {
  const sessionCookie = request.cookies.session;
  const bearer = request.headers.authorization?.startsWith('Bearer ')
    ? request.headers.authorization.slice(7)
    : undefined;

  if (sessionCookie) {
    const result = await query<{ user_id: string; id: string; expires_at: Date }>(
      `SELECT user_id,id,expires_at FROM sessions
       WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > NOW()`,
      [sha256(sessionCookie)],
    );
    const session = result.rows[0];
    if (session) {
      request.userId = session.user_id;
      request.authType = 'session';
    }
  } else if (bearer) {
    const key = await withTransaction(
      { apiKeyHash: sha256(bearer) },
      async (client) => {
        const result = await client.query<{ id: string; tenant_id: string; scopes: string[] }>(
          `SELECT id,tenant_id,scopes FROM api_keys
           WHERE key_hash=$1 AND revoked_at IS NULL`,
          [sha256(bearer)],
        );
        return result.rows[0];
      },
    );
    if (key) {
      // request.userId = undefined;
      request.tenantId = key.tenant_id;
      request.authType = 'api_key';
      request.headers['x-api-scopes'] = JSON.stringify(key.scopes);
      await withTransaction({ tenantId: key.tenant_id, apiKeyHash: sha256(bearer) }, async (client) => {
        await client.query('UPDATE api_keys SET last_used_at=NOW() WHERE id=$1', [key.id]);
      });
      return;
    }
  }

  if (!request.userId && !request.tenantId) {
    const error = fail(request.id, 401, 'UNAUTHORIZED', 'Authentication required');
    return reply.code(error.statusCode).send(error.body);
  }

  const tenantId = typeof request.headers['x-tenant-id'] === 'string'
    ? request.headers['x-tenant-id']
    : undefined;

  if (request.authType === 'session') {
    if (!tenantId) {
      const error = fail(request.id, 400, 'TENANT_REQUIRED', 'Tenant selection is required');
      return reply.code(error.statusCode).send(error.body);
    }
    const membership = await resolveTenant(request.userId!, tenantId);
    if (!membership) {
      const error = fail(request.id, 403, 'TENANT_ACCESS_DENIED', 'Tenant access denied');
      return reply.code(error.statusCode).send(error.body);
    }
    request.tenantId = tenantId;
    request.role = membership.role;
  }
}

async function requireAuth(request: import('fastify').FastifyRequest, reply: import('fastify').FastifyReply) {
  const result = await authenticate(request, reply);
  if (result) return result;
}

async function withRequestTenant<T>(
  request: import('fastify').FastifyRequest,
  fn: (client: import('@platform/database').PoolClient) => Promise<T>,
): Promise<T> {
  if (!request.tenantId) throw new Error('Tenant context is required');
  return withTransaction({ tenantId: request.tenantId, userId: request.userId ?? null }, fn);
}

function requirePermission(permission: import('@platform/domain/types').Permission) {
  return async (request: import('fastify').FastifyRequest, reply: import('fastify').FastifyReply) => {
    const result = await requireAuth(request, reply);
    if (result) return result;
    if (request.authType === 'api_key') {
      const scopes = JSON.parse(String(request.headers['x-api-scopes'] ?? '[]')) as string[];
      if (!scopes.includes(permission)) {
        const error = fail(request.id, 403, 'FORBIDDEN', 'Permission denied');
        return reply.code(error.statusCode).send(error.body);
      }
      return;
    }
    if (!request.role || !hasPermission(request.role, permission)) {
      const error = fail(request.id, 403, 'FORBIDDEN', 'Permission denied');
      return reply.code(error.statusCode).send(error.body);
    }
  };
}

app.addHook('onRequest', async (request, reply) => {
  reply.header('X-Request-Id', request.id);
});

app.addHook('onResponse', async (request, reply) => {
  request.log.info({
    request_id: request.id,
    tenant_id: request.tenantId,
    user_id: request.userId,
    operation: `${request.method} ${request.routeOptions.url}`,
    duration_ms: reply.elapsedTime,
    result: reply.statusCode,
  });
});

app.get('/health/live', async () => ({ status: 'ok' }));

app.get('/health/ready', async (request, reply) => {
  try {
    await query('SELECT 1');
    const pong = await redis.ping();
    if (pong !== 'PONG') throw new Error('Redis unavailable');
    return ok(request.id, { status: 'ready' });
  } catch {
    return reply.code(503).send(fail(request.id, 503, 'NOT_READY', 'Required dependency unavailable').body);
  }
});

app.get('/api/v1/openapi.json', async () => ({
  openapi: '3.1.0',
  info: { title: 'Platform API', version: '1.0.0' },
  servers: [{ url: '/api/v1' }],
  paths: {
    '/auth/register': { post: { summary: 'Register a user' } },
    '/auth/login': { post: { summary: 'Login' } },
    '/auth/logout': { post: { summary: 'Logout' } },
    '/auth/verify-email': { post: { summary: 'Verify email' } },
    '/auth/password-reset/request': { post: { summary: 'Request password reset' } },
    '/auth/password-reset/confirm': { post: { summary: 'Confirm password reset' } },
    '/auth/sessions': { get: { summary: 'List active sessions' } },
    '/auth/sessions/{id}': { delete: { summary: 'Revoke a session' } },
    '/tenants': { get: { summary: 'List memberships' }, post: { summary: 'Create tenant' } },
    '/api-keys': { post: { summary: 'Create API key' }, get: { summary: 'List API keys' } },
  },
}));

app.post('/api/v1/auth/register', {
  config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
}, async (request, reply) => {
  const body = z.object({
    email: z.string().email().max(320),
    password: z.string().min(12).max(256),
    first_name: z.string().max(100).optional(),
    last_name: z.string().max(100).optional(),
  }).parse(request.body);

  const normalized = normalizeEmail(body.email);
  const existing = await query('SELECT 1 FROM users WHERE email_normalized=$1', [normalized]);
  if (existing.rowCount) {
    return reply.code(409).send(fail(request.id, 409, 'EMAIL_ALREADY_REGISTERED', 'Email is already registered').body);
  }

  const userId = randomUUID();
  const token = randomToken();
  await query(
    `INSERT INTO users(id,email,email_normalized,password_hash,first_name,last_name)
     VALUES($1,$2,$3,$4,$5,$6)`,
    [userId, body.email, normalized, await hashPassword(body.password), body.first_name ?? null, body.last_name ?? null],
  );
  await query(
    `INSERT INTO email_verification_tokens(id,user_id,token_hash,expires_at)
     VALUES($1,$2,$3,NOW()+($4 || ' seconds')::interval)`,
    [randomUUID(), userId, sha256(token), config.EMAIL_VERIFICATION_TTL_SECONDS],
  );
  return reply.code(201).send(ok(request.id, { id: userId, email: body.email }));
});

app.post('/api/v1/auth/verify-email', async (request, reply) => {
  const body = z.object({ token: z.string().min(20) }).parse(request.body);
  const result = await query<{ user_id: string }>(
    `UPDATE email_verification_tokens
     SET used_at=NOW()
     WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW()
     RETURNING user_id`,
    [sha256(body.token)],
  );
  const row = result.rows[0];
  if (!row) return reply.code(400).send(fail(request.id, 400, 'INVALID_VERIFICATION_TOKEN', 'Verification token is invalid or expired').body);
  await query('UPDATE users SET email_verified_at=NOW(),updated_at=NOW() WHERE id=$1', [row.user_id]);
  await writeAuditEvent({ tenantId: null, actorUserId: row.user_id, action: 'email_verified' });
  return ok(request.id, { verified: true });
});

app.post('/api/v1/auth/login', {
  config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
}, async (request, reply) => {
  const body = z.object({ email: z.string().email(), password: z.string(), mfa_code: z.string().optional(), recovery_code: z.string().optional() }).parse(request.body);
  const result = await query<{ id: string; password_hash: string | null; status: string }>(
    'SELECT id,password_hash,status FROM users WHERE email_normalized=$1',
    [normalizeEmail(body.email)],
  );
  const user = result.rows[0];
  if (!user?.password_hash || user.status !== 'ACTIVE' || !(await verifyPassword(user.password_hash, body.password))) {
    await writeAuditEvent({ tenantId: null, actorUserId: user?.id ?? null, action: 'failed_login', metadata: { email: normalizeEmail(body.email) } });
    return reply.code(401).send(fail(request.id, 401, 'INVALID_CREDENTIALS', 'Invalid credentials').body);
  }

  const mfa = await query<{ secret_encrypted: string; enabled_at: Date | null }>(
    'SELECT secret_encrypted,enabled_at FROM mfa_credentials WHERE user_id=$1', [user.id],
  );
  const mfaRecord = mfa.rows[0];
  if (mfaRecord?.enabled_at) {
    let valid = false;
    if (body.mfa_code) valid = await verifyTotp(decryptMfaSecret(mfaRecord.secret_encrypted, config.MFA_ENCRYPTION_KEY), body.mfa_code);
    if (!valid && body.recovery_code) {
      const codes = await query<{ id: string; code_hash: string }>(
        'SELECT id,code_hash FROM mfa_recovery_codes WHERE user_id=$1 AND used_at IS NULL', [user.id],
      );
      for (const code of codes.rows) {
        if (await verifyRecoveryCode(code.code_hash, body.recovery_code)) {
          await query('UPDATE mfa_recovery_codes SET used_at=NOW() WHERE id=$1', [code.id]);
          valid = true;
          break;
        }
      }
    }
    if (!valid) return reply.code(401).send(fail(request.id, 401, 'MFA_REQUIRED', 'Valid MFA verification is required').body);
  }

  const rawSession = randomToken(48);
  await query(
    `INSERT INTO sessions(id,user_id,token_hash,authenticated_at,expires_at)
     VALUES($1,$2,$3,NOW(),NOW()+($4 || ' seconds')::interval)`,
    [randomUUID(), user.id, sha256(rawSession), config.SESSION_TTL_SECONDS],
  );
  await query('UPDATE users SET last_login_at=NOW(),updated_at=NOW() WHERE id=$1', [user.id]);
  await writeAuditEvent({ tenantId: null, actorUserId: user.id, action: 'login' });

  reply.setCookie('session', rawSession, {
    httpOnly: true, secure: config.COOKIE_SECURE, sameSite: 'lax',
    path: '/', maxAge: config.SESSION_TTL_SECONDS,
  });
  return ok(request.id, { authenticated: true, user_id: user.id });
});

app.post('/api/v1/auth/logout', { preHandler: requireAuth }, async (request, reply) => {
  const session = request.cookies.session;
  if (session) await query('UPDATE sessions SET revoked_at=NOW() WHERE token_hash=$1', [sha256(session)]);
  if (request.userId) await writeAuditEvent({ tenantId: request.tenantId ?? null, ...(request.userId ? { actorUserId: request.userId } : {}), action: 'logout' });
  reply.clearCookie('session', { path: '/' });
  return reply.code(204).send();
});

app.post('/api/v1/auth/password-reset/request', {
  config: { rateLimit: { max: 5, timeWindow: '1 hour' } },
}, async (request) => {
  const body = z.object({ email: z.string().email() }).parse(request.body);
  const user = await query<{ id: string }>('SELECT id FROM users WHERE email_normalized=$1', [normalizeEmail(body.email)]);
  if (user.rows[0]) {
    const token = randomToken();
    await query(
      `INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at)
       VALUES($1,$2,$3,NOW()+($4 || ' seconds')::interval)`,
      [randomUUID(), user.rows[0].id, sha256(token), config.PASSWORD_RESET_TTL_SECONDS],
    );
    request.log.info({ user_id: user.rows[0].id, reset_token: token }, 'development password reset token');
  }
  return ok(request.id, { accepted: true });
});

app.post('/api/v1/auth/password-reset/confirm', async (request, reply) => {
  const body = z.object({ token: z.string().min(20), password: z.string().min(12).max(256) }).parse(request.body);
  const token = await query<{ id: string; user_id: string }>(
    `UPDATE password_reset_tokens SET used_at=NOW()
     WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW()
     RETURNING id,user_id`,
    [sha256(body.token)],
  );
  const row = token.rows[0];
  if (!row) return reply.code(400).send(fail(request.id, 400, 'INVALID_RESET_TOKEN', 'Reset token is invalid or expired').body);
  await query('UPDATE users SET password_hash=$1,updated_at=NOW() WHERE id=$2', [await hashPassword(body.password), row.user_id]);
  await query('UPDATE sessions SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL', [row.user_id]);
  await writeAuditEvent({ tenantId: null, actorUserId: row.user_id, action: 'password_reset' });
  return ok(request.id, { reset: true });
});

app.get('/api/v1/auth/sessions', { preHandler: requireAuth }, async (request, reply) => {
  if (!request.userId) {
    return reply.code(403).send(fail(request.id, 403, 'FORBIDDEN', 'Session authentication required').body);
  }

  const result = await query(
    `SELECT id,authenticated_at,expires_at,created_at
     FROM sessions
     WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>NOW()
     ORDER BY created_at DESC`,
    [request.userId],
  );

  return ok(request.id, result.rows);
});

app.delete('/api/v1/auth/sessions/:id', { preHandler: requireAuth }, async (request, reply) => {
  if (!request.userId) {
    return reply.code(403).send(fail(request.id, 403, 'FORBIDDEN', 'Session authentication required').body);
  }

  const params = z.object({ id: z.string().uuid() }).parse(request.params);
  const result = await query(
    `UPDATE sessions
     SET revoked_at=NOW()
     WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL
     RETURNING id`,
    [params.id, request.userId],
  );

  if (!result.rowCount) {
    return reply.code(404).send(fail(request.id, 404, 'RESOURCE_NOT_FOUND', 'Resource does not exist').body);
  }

  return reply.code(204).send();
});

app.get('/api/v1/tenants', { preHandler: requireAuth }, async (request, reply) => {
  if (!request.userId) return reply.code(403).send(fail(request.id, 403, 'FORBIDDEN', 'Session authentication required').body);
  const result = await query<{ tenant_id: string; name: string; role: string }>(
    `SELECT m.tenant_id,t.name,m.role FROM tenant_memberships m JOIN tenants t ON t.id=m.tenant_id
     WHERE m.user_id=$1 AND m.status='ACTIVE' ORDER BY t.name`, [request.userId],
  );
  return ok(request.id, result.rows);
});

app.post('/api/v1/tenants', { preHandler: requireAuth }, async (request, reply) => {
  if (!request.userId) return reply.code(403).send(fail(request.id, 403, 'FORBIDDEN', 'Session authentication required').body);
  const body = z.object({ name: z.string().min(1).max(150), timezone: z.string().max(64).default('UTC') }).parse(request.body);
  const tenantId = randomUUID();
  const membershipId = randomUUID();
  await withTransaction({ tenantId, userId: request.userId }, async (client) => {
    await client.query('INSERT INTO tenants(id,name,timezone) VALUES($1,$2,$3)', [tenantId, body.name, body.timezone]);
    await client.query(
      'INSERT INTO tenant_memberships(id,tenant_id,user_id,role) VALUES($1,$2,$3,$4)',
      [membershipId, tenantId, request.userId, 'OWNER'],
    );
  });
  await writeAuditEvent({ tenantId, ...(request.userId ? { actorUserId: request.userId } : {}), action: 'membership_created', resourceType: 'tenant', resourceId: tenantId });
  return reply.code(201).send(ok(request.id, { id: tenantId, name: body.name }));
});

app.post('/api/v1/mfa/setup', { preHandler: requireAuth }, async (request, reply) => {
  if (!request.userId) return reply.code(403).send(fail(request.id, 403, 'FORBIDDEN', 'Session authentication required').body);
  const secretValue = createTotpSecret();
  await query(
    `INSERT INTO mfa_credentials(id,user_id,secret_encrypted)
     VALUES($1,$2,$3)
     ON CONFLICT(user_id) DO UPDATE SET secret_encrypted=EXCLUDED.secret_encrypted,enabled_at=NULL`,
    [randomUUID(), request.userId, encryptMfaSecret(secretValue, config.MFA_ENCRYPTION_KEY)],
  );
  return ok(request.id, { otpauth_uri: createTotpUri(secretValue, request.userId, 'Platform') });
});

app.post('/api/v1/mfa/enable', { preHandler: requireAuth }, async (request, reply) => {
  if (!request.userId) return reply.code(403).send(fail(request.id, 403, 'FORBIDDEN', 'Session authentication required').body);
  const body = z.object({ code: z.string().length(6) }).parse(request.body);
  const mfa = await query<{ secret_encrypted: string }>('SELECT secret_encrypted FROM mfa_credentials WHERE user_id=$1', [request.userId]);
  if (!mfa.rows[0] || !(await verifyTotp(decryptMfaSecret(mfa.rows[0].secret_encrypted, config.MFA_ENCRYPTION_KEY), body.code))) {
    return reply.code(400).send(fail(request.id, 400, 'INVALID_MFA_CODE', 'Invalid MFA code').body);
  }
  const codes = generateRecoveryCodes();
  await withTransaction(null, async (client) => {
    await client.query('UPDATE mfa_credentials SET enabled_at=NOW() WHERE user_id=$1', [request.userId]);
    await client.query('DELETE FROM mfa_recovery_codes WHERE user_id=$1', [request.userId]);
    for (const code of codes) {
      await client.query('INSERT INTO mfa_recovery_codes(id,user_id,code_hash) VALUES($1,$2,$3)', [randomUUID(), request.userId, await hashRecoveryCode(code)]);
    }
  });
  await writeAuditEvent({ tenantId: request.tenantId ?? null, ...(request.userId ? { actorUserId: request.userId } : {}), action: 'mfa_enabled' });
  return ok(request.id, { enabled: true, recovery_codes: codes });
});

app.post('/api/v1/mfa/disable', { preHandler: requireAuth }, async (request, reply) => {
  if (!request.userId) return reply.code(403).send(fail(request.id, 403, 'FORBIDDEN', 'Session authentication required').body);
  const body = z.object({ code: z.string().length(6) }).parse(request.body);
  const mfa = await query<{ secret_encrypted: string }>('SELECT secret_encrypted FROM mfa_credentials WHERE user_id=$1', [request.userId]);
  if (!mfa.rows[0] || !(await verifyTotp(decryptMfaSecret(mfa.rows[0].secret_encrypted, config.MFA_ENCRYPTION_KEY), body.code))) {
    return reply.code(400).send(fail(request.id, 400, 'INVALID_MFA_CODE', 'Invalid MFA code').body);
  }
  await query('UPDATE mfa_credentials SET enabled_at=NULL WHERE user_id=$1', [request.userId]);
  await query('UPDATE mfa_recovery_codes SET used_at=COALESCE(used_at,NOW()) WHERE user_id=$1', [request.userId]);
  await writeAuditEvent({ tenantId: request.tenantId ?? null, ...(request.userId ? { actorUserId: request.userId } : {}), action: 'mfa_disabled' });
  return ok(request.id, { enabled: false });
});

app.post('/api/v1/api-keys', { preHandler: requirePermission('users.manage') }, async (request, reply) => {
  const body = z.object({ name: z.string().min(1).max(150), scopes: z.array(z.enum(ALLOWED_API_KEY_SCOPES)).max(50) }).parse(request.body);
  const raw = `pk_${randomToken(32)}`;
  const id = randomUUID();
  await withTransaction({ tenantId: request.tenantId!, ...(request.userId ? { userId: request.userId } : {}) }, async (client) => {
    await client.query(
      'INSERT INTO api_keys(id,tenant_id,name,key_hash,scopes) VALUES($1,$2,$3,$4,$5)',
      [id, request.tenantId, body.name, sha256(raw), JSON.stringify(body.scopes)],
    );
  });
  await writeAuditEvent({ tenantId: request.tenantId!, ...(request.userId ? { actorUserId: request.userId } : {}), action: 'api_key_created', resourceType: 'api_key', resourceId: id });
  return reply.code(201).send(ok(request.id, { id, name: body.name, secret: raw, scopes: body.scopes }));
});

app.get('/api/v1/api-keys', { preHandler: requirePermission('users.manage') }, async (request) => {
  const result = await withTransaction(request.tenantId!, async (client) =>
    client.query('SELECT id,name,scopes,created_at,last_used_at,revoked_at FROM api_keys ORDER BY created_at DESC'),
  );
  return ok(request.id, result.rows);
});

app.delete('/api/v1/api-keys/:id', { preHandler: requirePermission('users.manage') }, async (request, reply) => {
  const params = z.object({ id: z.string().uuid() }).parse(request.params);
  const result = await withTransaction(request.tenantId!, async (client) =>
    client.query('UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 RETURNING id', [params.id]),
  );
  if (!result.rowCount) return reply.code(404).send(fail(request.id, 404, 'RESOURCE_NOT_FOUND', 'Resource does not exist').body);
  await writeAuditEvent({ tenantId: request.tenantId!, ...(request.userId ? { actorUserId: request.userId } : {}), action: 'api_key_revoked', resourceType: 'api_key', resourceId: params.id });
  return reply.code(204).send();
});

app.get('/api/v1/audit-events', { preHandler: requirePermission('audit.read') }, async (request) => {
  const queryParams = z.object({ limit: z.coerce.number().int().min(1).max(100).default(50), after: z.string().optional() }).parse(request.query);
  const result = await withTransaction({ tenantId: request.tenantId!, ...(request.userId ? { userId: request.userId } : {}) }, async (client) => {
    const values: unknown[] = [queryParams.limit + 1];
    let where = '';
    if (queryParams.after) {
      values.unshift(new Date(queryParams.after));
      where = 'WHERE created_at < $1';
    }
    const limitIndex = values.length;
    return client.query(`SELECT id,actor_user_id,action,resource_type,resource_id,ip_address,user_agent,metadata,created_at
      FROM audit_events ${where} ORDER BY created_at DESC LIMIT $${limitIndex}`, values);
  });
  const rows = result.rows;
  const hasNext = rows.length > queryParams.limit;
  const data = rows.slice(0, queryParams.limit);
  return ok(request.id, data, { next_cursor: hasNext ? data.at(-1)?.created_at : null });
});

app.setErrorHandler((error, request, reply) => {
  request.log.error({ err: error, request_id: request.id }, 'request failed');
  const status = error instanceof z.ZodError ? 422 : ((error as { statusCode?: number }).statusCode ?? 500);
  const code = error instanceof z.ZodError ? 'VALIDATION_ERROR' : 'INTERNAL_ERROR';
  const message = error instanceof z.ZodError ? 'Request validation failed' : status >= 500 ? 'Internal server error' : (error as Error).message;
  return reply.code(status).send(fail(request.id, status, code, message, error instanceof z.ZodError ? error.issues : undefined).body);
});

const shutdown = async () => {
  await app.close();
  await redis.quit();
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await app.listen({ host: '0.0.0.0', port: config.PORT });
