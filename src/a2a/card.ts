// Minimal stub for the verify harness: agent-card builders are not part of
// the #29 file pack. server.ts only calls them for card endpoints; the audit
// tests never touch server.ts.
import type { RegistryScan } from '../loader.js';

export function buildGatewayCard(_scan: RegistryScan, base: string): Record<string, unknown> {
  return { name: 'gateway', url: base };
}

export function buildAppCards(
  _scan: RegistryScan,
  _base: () => string,
): Map<string, Record<string, unknown>> {
  return new Map();
}
