import {
  appendFile,
  chmod,
  copyFile,
  mkdir,
  readFile,
  readdir,
  rename,
  writeFile,
} from 'node:fs/promises';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import path from 'node:path';

// The pack supplies this as an ESM .mjs file. Keep it at the project root.
// @ts-expect-error - no bundled TypeScript declaration for the L1 canonicalizer.
import { canonicalizeJsonText } from '../../molt-canonical.mjs';

import { AlertEngine } from './alerts.js';
import type {
  AuditAlertPayload,
  AuditExecutionObservation,
} from './alerts.js';

const ZERO_HASH = '0'.repeat(64);
const PRIVATE_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const IDENTITY_SCHEMA = 'molt.ed25519-identity.v1';
const HEX_32 = /^[0-9a-f]{64}$/;

interface AuditIdentity {
  schema: string;
  algorithm: string;
  purpose: string;
  privateKeyHex: string;
  publicKeyHex: string;
  keyId: string;
}

function sha256(value: Buffer | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function rawPublicKey(key: KeyObject): Buffer {
  return Buffer.from(key.export({ format: 'der', type: 'spki' })).subarray(-32);
}

function privateKeyFromSeed(seedHex: string): KeyObject {
  const seed = Buffer.from(seedHex, 'hex');
  return createPrivateKey({
    key: Buffer.concat([PRIVATE_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

function envInt(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return Math.floor(value);
}

export class AuditLedger {
  private auditDir: string;
  private identityPath: string;
  private env: NodeJS.ProcessEnv;
  private ready?: Promise<void>;
  private queue: Promise<void> = Promise.resolve();

  private privateKey!: KeyObject;
  private publicKey!: KeyObject;
  private publicHex!: string;
  private keyId!: string;

  private nextSeq = 0;
  private headHash = ZERO_HASH;
  private ledgerBytes = 0;
  private eventCount = 0;
  private segmentNumber = 0;
  private prevSegmentHeadHash?: string;

  private alerts: AlertEngine;

  constructor(
    rootDir: string,
    opts: { auditDir?: string; env?: NodeJS.ProcessEnv } = {},
  ) {
    this.auditDir = opts.auditDir ?? path.join(rootDir, 'audit');
    this.identityPath = path.join(this.auditDir, 'identity.json');
    this.env = opts.env ?? process.env;

    this.alerts = new AlertEngine({
      env: this.env,
      emitAlert: (payload) => this.appendAlertEvent(payload),
    });
  }

  get directory(): string {
    return this.auditDir;
  }

  get currentHeadHash(): string {
    return this.headHash;
  }

  async recordExecution(
    observation: AuditExecutionObservation,
  ): Promise<void> {
    try {
      await this.ensureReady();

      const payload: Record<string, unknown> = {
        caller: observation.caller || 'unknown',
        target: observation.target,
        entry: observation.entry,
        outcome: observation.outcome,
        duration_ms: observation.durationMs,
        attempts: observation.attempts,
      };

      if (observation.reason) payload.reason = observation.reason;
      if (observation.tokenId) payload.token_id = observation.tokenId;
      if (observation.permissionVersion !== undefined) {
        payload.permission_version = observation.permissionVersion;
      }
      if (observation.grantId) payload.grant_id = observation.grantId;

      const event = await this.enqueue(() =>
        this.appendEvent('gateway.execution', payload),
      );

      await this.alerts.observeExecution(event, {
        failed: observation.failed === true,
      });
    } catch (error) {
      this.stderr(
        `append failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async appendFreeze(payload: Record<string, unknown>): Promise<void> {
    try {
      await this.ensureReady();
      const event = await this.enqueue(() =>
        this.appendEvent('gateway.freeze', payload),
      );
      await this.alerts.observeFreeze(event);
    } catch (error) {
      this.stderr(
        `freeze append failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  async appendSyntheticFreeze(payload: Record<string, unknown>): Promise<void> {
    await this.appendFreeze(payload);
  }

  private ensureReady(): Promise<void> {
    if (!this.ready) {
      this.ready = this.init().catch((error) => {
        this.ready = undefined;
        throw error;
      });
    }
    return this.ready;
  }

  private async init(): Promise<void> {
    await mkdir(this.auditDir, { recursive: true });
    await this.loadOrCreateIdentity();
    await this.ensurePublicPem();
    await this.scanSegments();
    await this.loadActiveState();
  }

  private async scanSegments(): Promise<void> {
    let max = -1;
    try {
      const entries = await readdir(this.auditDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const match = /^seg-(\d{6})$/.exec(entry.name);
        if (match) max = Math.max(max, Number(match[1]));
      }
    } catch {
      // init() creates the directory before this.
    }
    this.segmentNumber = max + 1;
  }

  private async loadOrCreateIdentity(): Promise<void> {
    let text: string | undefined;
    try {
      text = await readFile(this.identityPath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    if (text !== undefined) {
      const identity = JSON.parse(text) as AuditIdentity;
      if (
        identity.schema !== IDENTITY_SCHEMA ||
        identity.algorithm !== 'Ed25519' ||
        !HEX_32.test(identity.privateKeyHex) ||
        !HEX_32.test(identity.publicKeyHex) ||
        !HEX_32.test(identity.keyId)
      ) {
        throw new Error('Invalid audit identity file.');
      }

      const privateKey = privateKeyFromSeed(identity.privateKeyHex);
      const publicKey = createPublicKey(privateKey);
      const raw = rawPublicKey(publicKey);

      if (raw.toString('hex') !== identity.publicKeyHex) {
        throw new Error('Audit identity public key does not match private key.');
      }

      this.privateKey = privateKey;
      this.publicKey = publicKey;
      this.publicHex = identity.publicKeyHex;
      this.keyId = identity.keyId;
      return;
    }

    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const seed = Buffer.from(
      privateKey.export({ format: 'der', type: 'pkcs8' }),
    ).subarray(-32);
    const raw = rawPublicKey(publicKey);
    const identity: AuditIdentity = {
      schema: IDENTITY_SCHEMA,
      algorithm: 'Ed25519',
      purpose: 'gateway audit ledger (ephemeral test key)',
      privateKeyHex: seed.toString('hex'),
      publicKeyHex: raw.toString('hex'),
      keyId: sha256(raw),
    };

    await writeFile(
      this.identityPath,
      `${JSON.stringify(identity, null, 2)}\n`,
      { mode: 0o600 },
    );
    await chmod(this.identityPath, 0o600).catch(() => {});

    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.publicHex = identity.publicKeyHex;
    this.keyId = identity.keyId;
  }

  private async ensurePublicPem(): Promise<void> {
    const pemPath = path.join(this.auditDir, 'ed25519-public.pem');
    try {
      await readFile(pemPath);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    const pem = this.publicKey
      .export({ format: 'pem', type: 'spki' })
      .toString();
    await writeFile(pemPath, pem, 'utf8');
  }

  private async loadActiveState(): Promise<void> {
    const manifestPath = path.join(this.auditDir, 'manifest.json');
    const eventsPath = path.join(this.auditDir, 'events.jsonl');

    let manifestText: string | undefined;
    try {
      manifestText = await readFile(manifestPath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    if (manifestText !== undefined) {
      const manifest = JSON.parse(manifestText) as Record<string, unknown>;
      if (typeof manifest.prev_segment_head_hash === 'string') {
        this.prevSegmentHeadHash = manifest.prev_segment_head_hash;
      }
    }

    let eventsText: string;
    try {
      eventsText = await readFile(eventsPath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      eventsText = '';
      await writeFile(eventsPath, '', 'utf8');
    }

    const lines = eventsText.split('\n').filter((line) => line.length > 0);
    this.eventCount = lines.length;
    this.nextSeq = lines.length;
    this.ledgerBytes = Buffer.byteLength(eventsText, 'utf8');

    if (lines.length > 0) {
      const last = JSON.parse(lines[lines.length - 1]) as { hash?: unknown };
      if (typeof last.hash !== 'string' || !HEX_32.test(last.hash)) {
        throw new Error('Active audit ledger has an invalid last event hash.');
      }
      this.headHash = last.hash;
    } else {
      this.headHash = ZERO_HASH;
    }

    if (manifestText === undefined) {
      await this.writeManifest();
    }
  }

  private async writeManifest(): Promise<void> {
    const manifest: Record<string, unknown> = {
      ledger_bytes: this.ledgerBytes,
      agent_pubkeys: { gateway: this.publicHex },
      artifacts: {},
      artifact_bytes: {},
    };

    if (this.prevSegmentHeadHash) {
      manifest.prev_segment_head_hash = this.prevSegmentHeadHash;
    }

    await writeFile(
      path.join(this.auditDir, 'manifest.json'),
      `${JSON.stringify(manifest, null, 2)}\n`,
      'utf8',
    );
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async appendEvent(
    type: string,
    payload: unknown,
  ): Promise<Record<string, unknown>> {
    const body = {
      seq: this.nextSeq,
      ts: Math.floor(Date.now() / 1000),
      type,
      payload,
      actor: 'gateway',
    };

    const canonicalBody = canonicalizeJsonText(JSON.stringify(body));
    const hash = createHash('sha256')
      .update(`${this.headHash}${canonicalBody}`, 'utf8')
      .digest('hex');

    const signature = sign(
      null,
      Buffer.from(hash, 'hex'),
      this.privateKey,
    ).toString('hex');

    const event = {
      seq: body.seq,
      ts: body.ts,
      type,
      actor: 'gateway',
      payload,
      prev_hash: this.headHash,
      pub: this.publicHex,
      sig: signature,
      hash,
    };

    const line = `${canonicalizeJsonText(JSON.stringify(event))}\n`;
    const eventsPath = path.join(this.auditDir, 'events.jsonl');

    await appendFile(eventsPath, line, 'utf8');

    this.nextSeq += 1;
    this.headHash = hash;
    this.ledgerBytes += Buffer.byteLength(line, 'utf8');
    this.eventCount += 1;

    try {
      await this.writeManifest();
    } catch (error) {
      this.stderr(
        `manifest update failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    if (this.shouldRotate()) {
      try {
        await this.rotate();
      } catch (error) {
        this.stderr(
          `rotation failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    }

    return event;
  }

  private shouldRotate(): boolean {
    const maxBytes = envInt(
      this.env,
      'AUDIT_ROTATE_BYTES',
      10 * 1024 * 1024,
    );
    const maxEvents = envInt(this.env, 'AUDIT_ROTATE_EVENTS', 10_000);

    return this.eventCount >= maxEvents || this.ledgerBytes >= maxBytes;
  }

  private async rotate(): Promise<void> {
    if (this.eventCount === 0) return;

    const oldHead = this.headHash;
    const segmentName = `seg-${String(this.segmentNumber).padStart(6, '0')}`;
    const segmentDir = path.join(this.auditDir, segmentName);

    await mkdir(segmentDir, { recursive: true });

    const eventsPath = path.join(this.auditDir, 'events.jsonl');
    const manifestPath = path.join(this.auditDir, 'manifest.json');
    const pemPath = path.join(this.auditDir, 'ed25519-public.pem');

    await rename(eventsPath, path.join(segmentDir, 'events.jsonl'));
    await rename(manifestPath, path.join(segmentDir, 'manifest.json'));
    await copyFile(pemPath, path.join(segmentDir, 'ed25519-public.pem'));

    this.segmentNumber += 1;
    this.prevSegmentHeadHash = oldHead;
    this.nextSeq = 0;
    this.headHash = ZERO_HASH;
    this.ledgerBytes = 0;
    this.eventCount = 0;

    await writeFile(eventsPath, '', 'utf8');
    await this.writeManifest();
  }

  private async appendAlertEvent(payload: AuditAlertPayload): Promise<void> {
    try {
      await this.ensureReady();
      await this.enqueue(() => this.appendEvent('gateway.alert', payload));
    } catch (error) {
      this.stderr(
        `alert event append failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    const parts = [
      'AUDIT ALERT',
      `rule=${payload.rule}`,
      ...(payload.caller ? [`caller=${payload.caller}`] : []),
      ...(payload.target ? [`target=${payload.target}`] : []),
      `count=${payload.count}`,
      `window_s=${payload.window_s}`,
      `first_ts=${payload.first_ts}`,
    ];

    process.stderr.write(`${parts.join(' ')}\n`);
  }

  private stderr(message: string): void {
    process.stderr.write(`audit: ${message}\n`);
  }
}
