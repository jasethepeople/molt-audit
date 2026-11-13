// Minimal stub for the verify harness: in-memory event bus. The real
// gateway's EventBus is not part of the #29 file pack. The audit tests never
// subscribe, so emit is a no-op that resolves.
import type { CanonicalEvent } from './types.js';

export class EventBus {
  async emit(_topic: string, _payload: CanonicalEvent): Promise<void> {
    // No subscribers in the verify harness.
  }
}
