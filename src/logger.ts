import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_REDACT_KEYS = ['access_token', 'token', 'secret', 'password', 'api_key', 'authorization'];

function envRedactKeys(): string[] {
  const raw = process.env.LOG_REDACT_KEYS;
  if (!raw) return DEFAULT_REDACT_KEYS;
  return raw.split(',').map((k) => k.trim().toLowerCase()).filter(Boolean);
}

function redact(value: unknown, keys: string[]): unknown {
  if (Array.isArray(value)) return value.map((v) => redact(v, keys));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = keys.includes(k.toLowerCase()) ? '[REDACTED]' : redact(v, keys);
    }
    return out;
  }
  return value;
}

export interface ExecutionLogEntry {
  ts: string;
  target: string;
  event?: unknown;
  ok: boolean;
  result?: unknown;
  error?: { message: string; stack?: string };
  durationMs: number;
  attempts: number;
}

/**
 * JSON-lines execution logger. Appends one JSON object per execution to
 * logs/executions.jsonl. Sensitive keys are redacted before writing.
 */
export class ExecutionLogger {
  private redactKeys: string[];
  private file: string;
  private ready: Promise<unknown> | null = null;

  constructor(
    private rootDir: string,
    opts: { file?: string; redactKeys?: string[] } = {},
  ) {
    this.file = opts.file ?? path.join(rootDir, 'logs', 'executions.jsonl');
    this.redactKeys = (opts.redactKeys ?? envRedactKeys()).map((k) => k.toLowerCase());
  }

  private async ensureDir(): Promise<void> {
    if (!this.ready) {
      this.ready = mkdir(path.dirname(this.file), { recursive: true }).catch(() => {});
    }
    await this.ready;
  }

  async logExecution(entry: ExecutionLogEntry): Promise<void> {
    try {
      await this.ensureDir();
      const safe = redact(entry, this.redactKeys);
      await appendFile(this.file, JSON.stringify(safe) + '\n', 'utf8');
    } catch (err) {
      // Logging must never break execution.
      console.error('execution log write failed:', err instanceof Error ? err.message : err);
    }
  }
}

/** Component-facing namespaced logger: JSON line to stdout. */
export function makeComponentLogger(namespace: string) {
  return (level: 'info' | 'warn' | 'error', msg: string, data?: unknown): void => {
    const line = JSON.stringify({ ts: new Date().toISOString(), level, ns: namespace, msg, data });
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
  };
}
