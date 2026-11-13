import { expect, it } from 'vitest';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { buildEvent } from '../molt-event.mjs';
// @ts-expect-error - no bundled TypeScript declaration for the L1 canonicalizer.
import { canonicalizeJsonText } from '../molt-canonical.mjs';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

it('standalone event writer uses the Camp 1 five-field hash and signs the raw hash bytes', () => {
  const pair = generateKeyPairSync('ed25519');
  const publicBytes = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' })).subarray(-32);
  const publicHex = publicBytes.toString('hex');
  const event = buildEvent({
    seq: 0,
    ts: 1700000000,
    type: 'gateway.execution',
    actor: 'gateway',
    payload: null,
    prevHash: '0'.repeat(64),
    publicHex,
    privateKey: pair.privateKey,
  });
  const body = { seq: event.seq, ts: event.ts, type: event.type, payload: event.payload, actor: event.actor };
  const canonicalBody = canonicalizeJsonText(JSON.stringify(body));
  const expectedHash = createHash('sha256').update(`${event.prev_hash}${canonicalBody}`, 'utf8').digest('hex');
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicBytes]),
    format: 'der',
    type: 'spki',
  });

  expect(event.hash).toBe(expectedHash);
  expect(verify(null, Buffer.from(event.hash, 'hex'), publicKey, Buffer.from(event.sig, 'hex'))).toBe(true);
});
