export type AuditEntry = 'rest' | 'a2a';

export interface AuditExecutionObservation {
  caller: string;
  target: string;
  entry: AuditEntry;
  outcome: 'allowed' | 'denied';
  reason?: string;
  tokenId?: string;
  permissionVersion?: string | number;
  grantId?: string;
  durationMs: number;
  attempts: number;
  failed?: boolean;
}

export interface AuditAlertPayload {
  rule: string;
  caller?: string;
  target?: string;
  count: number;
  window_s: number;
  first_ts: string;
}

export interface AlertEngineOptions {
  env?: NodeJS.ProcessEnv;
  emitAlert: (payload: AuditAlertPayload) => Promise<void>;
}

interface WindowState {
  start: number;
  count: number;
  alerted: boolean;
}

function envInt(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  min = 1,
): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < min) return fallback;
  return Math.floor(value);
}

function isTokenFailure(reason: string): boolean {
  return /(token|approval|missing|expired|replay|cross[- ]target|unauthorized|forbidden)/i.test(reason);
}

export class AlertEngine {
  private denialBurst: number;
  private errorBurst: number;
  private windowSeconds: number;
  private windowMs: number;
  private denialWindows = new Map<string, WindowState>();
  private errorWindows = new Map<string, WindowState>();
  private emitAlert: (payload: AuditAlertPayload) => Promise<void>;

  constructor(opts: AlertEngineOptions) {
    const env = opts.env ?? process.env;
    this.emitAlert = opts.emitAlert;
    this.denialBurst = envInt(env, 'AUDIT_ALERT_DENIAL_BURST', 5, 1);
    this.errorBurst = envInt(env, 'AUDIT_ALERT_ERROR_BURST', 5, 1);
    this.windowSeconds = envInt(env, 'AUDIT_ALERT_WINDOW_S', 600, 0);
    this.windowMs = this.windowSeconds * 1000;
  }

  async observeExecution(
    event: { type: string; payload?: unknown },
    input: { failed?: boolean } = {},
  ): Promise<void> {
    const payload =
      event.payload && typeof event.payload === 'object'
        ? (event.payload as Record<string, unknown>)
        : {};

    const outcome = payload.outcome;
    const caller =
      typeof payload.caller === 'string' && payload.caller
        ? payload.caller
        : 'unknown';
    const target = typeof payload.target === 'string' ? payload.target : '';
    const reason = typeof payload.reason === 'string' ? payload.reason : '';

    // R1: any approval-token rejection alerts immediately.
    if (outcome === 'denied' && isTokenFailure(reason)) {
      await this.emitAlert({
        rule: 'token_failure',
        caller,
        target,
        count: 1,
        window_s: 0,
        first_ts: new Date().toISOString(),
      });
    }

    // R2: denial burst per caller, suppressed inside the window.
    if (outcome === 'denied') {
      await this.denialBurstFor(caller);
    }

    // R4: failed-execution burst per target, suppressed inside the window.
    if (input.failed) {
      await this.errorBurstFor(target || 'unknown');
    }
  }

  async observeFreeze(event: { payload?: unknown }): Promise<void> {
    const payload =
      event.payload && typeof event.payload === 'object'
        ? (event.payload as Record<string, unknown>)
        : {};

    const caller =
      typeof payload.caller === 'string'
        ? payload.caller
        : typeof payload.caller_id === 'string'
          ? payload.caller_id
          : undefined;

    const target =
      typeof payload.target === 'string'
        ? payload.target
        : payload.scope === 'all'
          ? 'all'
          : undefined;

    await this.emitAlert({
      rule: 'freeze',
      ...(caller ? { caller } : {}),
      ...(target ? { target } : {}),
      count: 1,
      window_s: 0,
      first_ts: new Date().toISOString(),
    });
  }

  private async denialBurstFor(caller: string): Promise<void> {
    const now = Date.now();
    let state = this.denialWindows.get(caller);
    if (!state || now - state.start > this.windowMs) {
      state = { start: now, count: 0, alerted: false };
      this.denialWindows.set(caller, state);
    }

    state.count += 1;

    if (state.count >= this.denialBurst && !state.alerted) {
      state.alerted = true;
      await this.emitAlert({
        rule: 'denial_burst',
        caller,
        count: state.count,
        window_s: this.windowSeconds,
        first_ts: new Date(state.start).toISOString(),
      });
    }
  }

  private async errorBurstFor(target: string): Promise<void> {
    const now = Date.now();
    let state = this.errorWindows.get(target);
    if (!state || now - state.start > this.windowMs) {
      state = { start: now, count: 0, alerted: false };
      this.errorWindows.set(target, state);
    }

    state.count += 1;

    if (state.count >= this.errorBurst && !state.alerted) {
      state.alerted = true;
      await this.emitAlert({
        rule: 'error_burst',
        target,
        count: state.count,
        window_s: this.windowSeconds,
        first_ts: new Date(state.start).toISOString(),
      });
    }
  }
}
