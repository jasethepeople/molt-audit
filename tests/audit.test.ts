import { afterEach, describe, expect, it, vi } from 'vitest';
import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { promisify } from 'node:util';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { Router } from '../src/router.js';
import type { ExecuteRequest } from '../src/types.js';

// @ts-expect-error - verifier.mjs is supplied by the L1 file pack.
import { verifyMoltPackage } from '../verifier.mjs';

const execFileAsync = promisify(execFile);
const eventWriterPath = new URL('../molt-event.mjs', import.meta.url);
const roots: string[] = [];

async function makeRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-audit-'));
  roots.push(root);
  return root;
}

function loaderReturning(value: unknown) {
  return {
    load: async () => ({
      def: {
        key: 'test_component',
        name: 'test component',
        description: '',
        version: '1.0.0',
        type: 'action',
      },
      run: async () => value,
    }),
  } as any;
}

function loaderThrowing(message: string) {
  return {
    load: async () => ({
      def: {
        key: 'test_component',
        name: 'test component',
        description: '',
        version: '1.0.0',
        type: 'action',
      },
      run: async () => {
        throw new Error(message);
      },
    }),
  } as any;
}

async function readEvents(auditDir: string): Promise<any[]> {
  const text = await readFile(path.join(auditDir, 'events.jsonl'), 'utf8');
  return text
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));
}

async function readAllFiles(dir: string): Promise<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  const chunks: string[] = [];

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      chunks.push(await readAllFiles(full));
    } else if (entry.isFile()) {
      chunks.push(await readFile(full, 'utf8'));
    }
  }

  return chunks.join('\n');
}

afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.AUDIT_ROTATE_EVENTS;
  delete process.env.AUDIT_ROTATE_BYTES;
  delete process.env.AUDIT_ALERT_DENIAL_BURST;
  delete process.env.AUDIT_ALERT_ERROR_BURST;
  delete process.env.AUDIT_ALERT_WINDOW_S;

  for (const root of roots.splice(0)) {
    await chmod(path.join(root, 'audit'), 0o700).catch(() => {});
    await rm(root, { recursive: true, force: true });
  }
});

describe('gateway audit ledger', () => {
  it('standalone event writer emits a Camp 1 package accepted by the L1 verifier', async () => {
    const root = await makeRoot();
    const packageDir = path.join(root, 'package');
    await mkdir(packageDir);
    const pair = generateKeyPairSync('ed25519');
    const privateHex = Buffer.from(pair.privateKey.export({ format: 'der', type: 'pkcs8' })).subarray(-32).toString('hex');
    const publicHex = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' })).subarray(-32).toString('hex');
    const identityPath = path.join(root, 'identity.json');
    const payloadPath = path.join(root, 'payload.json');
    const ledgerPath = path.join(packageDir, 'events.jsonl');

    await writeFile(identityPath, JSON.stringify({ 'manifest-signer': { priv: privateHex, pub: publicHex } }), { mode: 0o600 });
    await writeFile(payloadPath, JSON.stringify({ source: 'molt-audit', ok: true }));
    await execFileAsync(process.execPath, [
      eventWriterPath.pathname,
      '--key', identityPath,
      '--ledger', ledgerPath,
      '--type', 'integration.test',
      '--actor', 'agent',
      '--payload', payloadPath,
    ]);

    const ledger = await readFile(ledgerPath);
    await writeFile(path.join(packageDir, 'ed25519-public.pem'), pair.publicKey.export({ format: 'pem', type: 'spki' }));
    await writeFile(path.join(packageDir, 'manifest.json'), JSON.stringify({
      artifacts: {},
      artifact_bytes: {},
      agent_pubkeys: { agent: publicHex },
      ledger_bytes: ledger.byteLength,
    }));

    const verification = await verifyMoltPackage(packageDir);
    expect(verification.valid).toBe(true);
  });

  it('logs an allowed execution and verifies VALID with the L1 verifier', async () => {
    const root = await makeRoot();
    const router = new Router(root, { loader: loaderReturning({ ok: true }) });

    const response = await router.execute({
      target: 'external/app/action',
      entry: 'rest',
      callerId: 'alice',
      approvalToken: 'tok-1',
    });

    expect(response.ok).toBe(true);

    const auditDir = path.join(root, 'audit');
    const verification = await verifyMoltPackage(auditDir);
    expect(verification.valid).toBe(true);

    const events = await readEvents(auditDir);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('gateway.execution');
    expect(events[0].payload).toMatchObject({
      caller: 'alice',
      target: 'external/app/action',
      entry: 'rest',
      outcome: 'allowed',
      attempts: 1,
    });
    expect(events[0].payload.token_id).toBeDefined();
  });

  it('logs a denial with the denial reason and only section-1 payload fields', async () => {
    const root = await makeRoot();
    const router = new Router(root, {
      loader: loaderThrowing('missing approval token'),
    });

    await router.execute({
      target: 'external/app/action',
      entry: 'rest',
    });

    const auditDir = path.join(root, 'audit');
    const events = await readEvents(auditDir);
    const execution = events.find((event) => event.type === 'gateway.execution');

    expect(execution).toBeTruthy();
    expect(execution.payload.outcome).toBe('denied');
    expect(execution.payload.reason).toBe('missing approval token');
    expect(Object.keys(execution.payload).sort()).toEqual([
      'attempts',
      'caller',
      'duration_ms',
      'entry',
      'outcome',
      'reason',
      'target',
    ]);
  });

  it('never writes the approval-token value into the audit directory', async () => {
    const root = await makeRoot();
    const router = new Router(root, { loader: loaderReturning({ ok: true }) });
    const secret = 'SUPER_SECRET_APPROVAL_TOKEN_VALUE';

    await router.execute({
      target: 'external/app/action',
      entry: 'rest',
      callerId: 'alice',
      approvalToken: secret,
    });

    const all = await readAllFiles(path.join(root, 'audit'));
    expect(all).not.toContain(secret);
  });

  it('fails verification when one byte in an audit event line is flipped', async () => {
    const root = await makeRoot();
    const router = new Router(root, { loader: loaderReturning({ ok: true }) });

    await router.execute({
      target: 'external/app/action',
      entry: 'rest',
    });

    const auditDir = path.join(root, 'audit');
    const eventsPath = path.join(auditDir, 'events.jsonl');
    const original = await readFile(eventsPath, 'utf8');
    const tampered = original.replace('"actor":"gateway"', '"actor":"gatewax"');

    expect(tampered).not.toBe(original);
    await writeFile(eventsPath, tampered, 'utf8');

    const verification = await verifyMoltPackage(auditDir);
    expect(verification.valid).toBe(false);
  });

  it('fails verification when events.jsonl is truncated', async () => {
    const root = await makeRoot();
    const router = new Router(root, { loader: loaderReturning({ ok: true }) });

    await router.execute({
      target: 'external/app/action',
      entry: 'rest',
    });

    const auditDir = path.join(root, 'audit');
    const eventsPath = path.join(auditDir, 'events.jsonl');
    const original = await readFile(eventsPath, 'utf8');
    await writeFile(eventsPath, original.slice(0, -5), 'utf8');

    const verification = await verifyMoltPackage(auditDir);
    expect(verification.valid).toBe(false);
  });

  it('raises a token_failure alert event and stderr line for a replayed token', async () => {
    const root = await makeRoot();
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const router = new Router(root, {
      loader: loaderThrowing('replayed approval token'),
    });

    await router.execute({
      target: 'external/app/action',
      entry: 'rest',
      callerId: 'alice',
    });

    const auditDir = path.join(root, 'audit');
    const events = await readEvents(auditDir);
    expect(
      events.some(
        (event) =>
          event.type === 'gateway.alert' &&
          event.payload.rule === 'token_failure',
      ),
    ).toBe(true);
    expect(
      stderr.mock.calls.some((call) => String(call[0]).includes('AUDIT ALERT')),
    ).toBe(true);
  });

  it('raises exactly one denial_burst alert for five denials in the window', async () => {
    const root = await makeRoot();
    const router = new Router(root, {
      loader: loaderThrowing('permission denied'),
    });

    for (let index = 0; index < 6; index += 1) {
      await router.execute({
        target: 'external/app/action',
        entry: 'rest',
        callerId: 'bob',
      });
    }

    const auditDir = path.join(root, 'audit');
    const events = await readEvents(auditDir);
    const alerts = events.filter(
      (event) =>
        event.type === 'gateway.alert' &&
        event.payload.rule === 'denial_burst',
    );

    expect(alerts).toHaveLength(1);
    expect(alerts[0].payload.count).toBeGreaterThanOrEqual(5);
  });

  it('raises a freeze alert when a synthetic freeze event is appended', async () => {
    const root = await makeRoot();
    const router = new Router(root, { loader: loaderReturning({ ok: true }) });

    await router.auditLedger.appendSyntheticFreeze({
      scope: 'caller',
      caller_id: 'bob',
      reason: 'test freeze',
    });

    const auditDir = path.join(root, 'audit');
    const events = await readEvents(auditDir);

    expect(
      events.some(
        (event) =>
          event.type === 'gateway.alert' && event.payload.rule === 'freeze',
      ),
    ).toBe(true);
  });

  it('rotates at a tiny cap and links the second manifest to the first segment head', async () => {
    process.env.AUDIT_ROTATE_EVENTS = '1';

    const root = await makeRoot();
    const router = new Router(root, { loader: loaderReturning({ ok: true }) });

    await router.execute({
      target: 'external/app/action',
      entry: 'rest',
    });

    const auditDir = path.join(root, 'audit');
    const entries = await readdir(auditDir, { withFileTypes: true });
    const segments = entries
      .filter((entry) => entry.isDirectory() && entry.name.startsWith('seg-'))
      .map((entry) => entry.name);

    expect(segments).toHaveLength(1);

    const segmentEvents = await readEvents(path.join(auditDir, segments[0]));
    const segmentHead = segmentEvents[segmentEvents.length - 1].hash;
    const activeManifest = JSON.parse(
      await readFile(path.join(auditDir, 'manifest.json'), 'utf8'),
    );

    expect(activeManifest.prev_segment_head_hash).toBe(segmentHead);

    const activeVerify = await verifyMoltPackage(auditDir);
    const segmentVerify = await verifyMoltPackage(path.join(auditDir, segments[0]));
    expect(activeVerify.valid).toBe(true);
    expect(segmentVerify.valid).toBe(true);

    const { stdout } = await execFileAsync(
      process.execPath,
      ['audit.mjs', 'verify', auditDir],
      { cwd: process.cwd() },
    );
    expect(stdout).toContain('VALID');
  });

  it('still succeeds when the audit directory is read-only', async () => {
    const root = await makeRoot();
    const auditDir = path.join(root, 'audit');
    await mkdir(auditDir, { recursive: true });
    await chmod(auditDir, 0o500);

    const router = new Router(root, { loader: loaderReturning({ ok: true }) });
    const response = await router.execute({
      target: 'external/app/action',
      entry: 'rest',
    });

    expect(response.ok).toBe(true);
    await chmod(auditDir, 0o700);
  });

  it('verify CLI exits 0 on a good ledger and 1 on a tampered ledger', async () => {
    const root = await makeRoot();
    const router = new Router(root, { loader: loaderReturning({ ok: true }) });

    await router.execute({
      target: 'external/app/action',
      entry: 'rest',
    });

    const auditDir = path.join(root, 'audit');

    await expect(
      execFileAsync(process.execPath, ['audit.mjs', 'verify', auditDir], {
        cwd: process.cwd(),
      }),
    ).resolves.toBeTruthy();

    const eventsPath = path.join(auditDir, 'events.jsonl');
    const original = await readFile(eventsPath, 'utf8');
    await writeFile(
      eventsPath,
      original.replace('"actor":"gateway"', '"actor":"gatewax"'),
      'utf8',
    );

    await expect(
      execFileAsync(process.execPath, ['audit.mjs', 'verify', auditDir], {
        cwd: process.cwd(),
      }),
    ).rejects.toMatchObject({ code: 1 });
  });

  it('logs both entry points with the same shape, differing only in entry', async () => {
    const root = await makeRoot();
    const router = new Router(root, { loader: loaderReturning({ ok: true }) });

    const base: ExecuteRequest = {
      target: 'external/app/action',
      callerId: 'alice',
    };

    await router.execute({ ...base, entry: 'rest' });
    await router.execute({ ...base, entry: 'a2a' });

    const auditDir = path.join(root, 'audit');
    const events = await readEvents(auditDir);
    const executions = events.filter(
      (event) => event.type === 'gateway.execution',
    );

    expect(executions).toHaveLength(2);
    expect(executions[0].payload.entry).toBe('rest');
    expect(executions[1].payload.entry).toBe('a2a');
    expect(Object.keys(executions[0].payload).sort()).toEqual(
      Object.keys(executions[1].payload).sort(),
    );
  });
});
