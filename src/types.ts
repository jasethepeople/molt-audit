export interface RuntimeContext {
  /** per-app auth/config; replaces Pipedream's `this.app.$auth` */
  auth: Record<string, string | undefined>;
  /** app-level config (env-resolved) */
  config: Record<string, unknown>;
  /** fetch-compatible HTTP client */
  http: typeof fetch;
  /** namespaced logger */
  log: (level: 'info' | 'warn' | 'error', msg: string, data?: unknown) => void;
  /** emit to the local event bus */
  emit: (topic: string, payload: CanonicalEvent) => Promise<void>;
  /** key-value store for source dedup/cursors (in-memory + optional file persistence) */
  store: {
    get<T = unknown>(k: string): Promise<T | undefined>;
    set(k: string, v: unknown): Promise<void>;
  };
}

export interface ComponentDef {
  key: string; // "app_component_key" unique
  name: string;
  description: string;
  version: string;
  type: 'action' | 'source';
  /** JSON Schema for props */
  propsSchema?: Record<string, unknown>;
}

export interface IIntegrationComponent {
  def: ComponentDef;
  run(ctx: RuntimeContext, event: unknown, steps: Steps): Promise<unknown>;
}

export interface Steps {
  [stepName: string]: { $return_value?: unknown; $summary?: string };
}

export interface CanonicalEvent {
  id: string; // uuid
  source: string; // component key that produced it
  topic: string; // e.g. "github.new_issue"
  timestamp: string; // ISO8601
  data: Record<string, unknown>;
  meta?: Record<string, unknown>;
}

export interface ExecuteRequest {
  target: string; // "external/<app>/<component>" or "native/<module>/<component>"
  event?: unknown; // webhook body / trigger payload
  auth?: Record<string, string>;
  config?: Record<string, unknown>;
  retry?: { attempts?: number; backoffMs?: number };

  /** Audit-only entry marker. REST and A2A set this before calling Router.execute. */
  entry?: 'rest' | 'a2a';
  /** Audit-only caller identity. */
  caller?: string;
  callerId?: string;
  /** Approval token value. Never written to audit; only a fingerprint is written. */
  approvalToken?: string;
  token?: string;
  /** Optional already-computed token id/fingerprint. */
  tokenId?: string;
  /** #13 fields recorded when available; #13 itself is not implemented here. */
  permissionVersion?: string | number;
  grantId?: string;
}

export interface ExecuteResponse {
  ok: boolean;
  target: string;
  result?: unknown;
  error?: { message: string; stack?: string };
  durationMs: number;
  attempts: number;
}
