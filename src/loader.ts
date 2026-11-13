// Minimal stub for the verify harness: the real gateway's Loader walks a
// ~14k-component registry that is not part of the #29 file pack. The audit
// tests always inject their own loader via RouterOptions, so this stub only
// needs to satisfy the import and the default-construction path.
import type { IIntegrationComponent } from './types.js';

export interface RegistryScan {
  apps: string[];
  components: string[];
}

export class Loader {
  constructor(private rootDir: string) {}

  async load(target: string): Promise<IIntegrationComponent> {
    throw new Error(`Loader stub: no component registered for ${target}`);
  }

  async list(): Promise<RegistryScan> {
    return { apps: [], components: [] };
  }
}
