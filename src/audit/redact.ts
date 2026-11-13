const DEFAULT_AUDIT_REDACT_KEYS = [
  'access_token',
  'token',
  'secret',
  'password',
  'api_key',
  'authorization',
  'approval_token',
  'approval-token',
  'private_key',
  'privatekey',
  'seed',
  'signing_key',
  'signing-key',
];

function envRedactKeys(env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = env.LOG_REDACT_KEYS;
  if (!raw) return DEFAULT_AUDIT_REDACT_KEYS;
  return raw
    .split(',')
    .map((key) => key.trim().toLowerCase())
    .filter(Boolean);
}

export function redactForAudit(
  value: unknown,
  keys: string[] = envRedactKeys(),
): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactForAudit(item, keys));
  }

  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = keys.includes(key.toLowerCase())
        ? '[REDACTED]'
        : redactForAudit(item, keys);
    }
    return out;
  }

  return value;
}

export function auditRedactKeys(env: NodeJS.ProcessEnv = process.env): string[] {
  return envRedactKeys(env);
}
