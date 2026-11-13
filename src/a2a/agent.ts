// Minimal stub for the verify harness: the A2A agent front door is not part
// of the #29 file pack. server.ts only constructs it and calls handleRpc;
// the audit tests never touch server.ts.
import type { ExecuteRequest, ExecuteResponse } from '../types.js';

export class A2aAgent {
  private execute: (req: ExecuteRequest) => Promise<ExecuteResponse>;

  constructor(opts: { execute: (req: ExecuteRequest) => Promise<ExecuteResponse> }) {
    this.execute = opts.execute;
  }

  async handleRpc(body: unknown): Promise<unknown> {
    const req = body as { params?: ExecuteRequest; id?: unknown };
    if (!req || typeof req !== 'object' || !req.params) {
      return { jsonrpc: '2.0', id: (req as { id?: unknown })?.id ?? null, error: { code: -32602, message: 'Invalid params' } };
    }
    const result = await this.execute(req.params);
    return { jsonrpc: '2.0', id: req.id ?? null, result };
  }
}
