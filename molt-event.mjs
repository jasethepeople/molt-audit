#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify as verifySignature } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import { TextDecoder } from 'node:util';
import { pathToFileURL } from 'node:url';
import { canonicalizeJsonText } from './molt-canonical.mjs';

const PRIVATE_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const HEX_32 = /^[0-9a-f]{64}$/;
const ZERO_HASH = '0'.repeat(64);
const USAGE = 'Usage: node molt-event.mjs --key KEYFILE --ledger LEDGER --type TYPE --actor ACTOR [--payload PAYLOAD]';

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const allowed = new Set(['--key', '--ledger', '--type', '--actor', '--payload']);
  const options = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!allowed.has(flag)) fail(`Unknown or unsupported flag: ${flag}. ${USAGE}`);
    if (options.has(flag)) fail(`Duplicate flag: ${flag}.`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) fail(`Missing value for ${flag}.`);
    options.set(flag, value);
    index += 1;
  }
  for (const required of ['--key', '--ledger', '--type', '--actor']) {
    if (!options.has(required)) fail(`Missing required ${required}. ${USAGE}`);
  }
  return options;
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8.`);
  }
}

function parseJson(text, label) {
  try {
    canonicalizeJsonText(text);
    return JSON.parse(text);
  } catch (error) {
    if (label === 'Identity file') fail('Identity file is not valid JSON.');
    if (label === 'Payload') {
      const detail = error instanceof Error ? error.message : 'invalid JSON';
      fail(`Invalid payload JSON: ${detail}`);
    }
    throw error;
  }
}

function rawPublicKey(publicKey) {
  return Buffer.from(publicKey.export({ format: 'der', type: 'spki' })).subarray(-32);
}

async function readIdentity(path) {
  let text;
  try {
    text = decodeUtf8(await readFile(path), 'Identity file');
  } catch (error) {
    if (error instanceof Error && error.message === 'Identity file is not valid UTF-8.') throw error;
    fail('Identity file is not readable.');
  }

  const identity = parseJson(text, 'Identity file');
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) fail('Identity file must contain a JSON object.');

  let privateHex;
  let publicHex;
  if (Object.hasOwn(identity, 'manifest-signer')) {
    if (Object.keys(identity).length !== 1) fail('Manifest signer identity must have only the manifest-signer top-level property.');
    const signer = identity['manifest-signer'];
    if (!signer || typeof signer !== 'object' || Array.isArray(signer) || Object.keys(signer).length !== 2 || !Object.hasOwn(signer, 'priv') || !Object.hasOwn(signer, 'pub')) {
      fail('Manifest signer identity must contain exactly priv and pub.');
    }
    privateHex = signer.priv;
    publicHex = signer.pub;
  } else {
    if (identity.schema !== 'molt.ed25519-identity.v1' || identity.algorithm !== 'Ed25519' || typeof identity.purpose !== 'string' || !identity.purpose.trim()) {
      fail('Identity file must use the documented molt.ed25519-identity.v1 schema.');
    }
    privateHex = identity.privateKeyHex;
    publicHex = identity.publicKeyHex;
    if (typeof identity.keyId !== 'string' || !HEX_32.test(identity.keyId)) fail('Identity keyId must be 64 lowercase hexadecimal characters.');
  }

  if (typeof privateHex !== 'string' || !HEX_32.test(privateHex) || typeof publicHex !== 'string' || !HEX_32.test(publicHex)) {
    fail('Identity private and public keys must be 64 lowercase hexadecimal characters.');
  }

  const seed = Buffer.from(privateHex, 'hex');
  const statedPublic = Buffer.from(publicHex, 'hex');
  let privateKey;
  try {
    privateKey = createPrivateKey({ key: Buffer.concat([PRIVATE_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  } catch {
    fail('Identity private key is not a valid Ed25519 seed.');
  }
  const derivedPublic = rawPublicKey(createPublicKey(privateKey));
  if (!derivedPublic.equals(statedPublic)) fail('Identity private key does not match the stated public key.');

  if (!Object.hasOwn(identity, 'manifest-signer')) {
    const expectedKeyId = createHash('sha256').update(statedPublic).digest('hex');
    if (identity.keyId !== expectedKeyId) fail('Identity keyId does not match the stated public key.');
  }

  return { privateKey, publicHex };
}

async function readLedger(path) {
  let bytes;
  try {
    bytes = await readFile(path);
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') return { bytes: Buffer.alloc(0), count: 0, lastHash: ZERO_HASH, publicHex: null };
    fail(`Unable to read ledger file: ${path}`);
  }

  const text = decodeUtf8(bytes, 'Ledger file');
  if (text !== '' && !text.endsWith('\n')) fail('Ledger file is not newline-terminated.');
  const lines = text === '' ? [] : text.slice(0, -1).split('\n');
  let lastHash = ZERO_HASH;
  let ledgerPublicHex = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const label = `Ledger event on line ${index + 1}`;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      fail(`Ledger contains invalid JSON on line ${index + 1}.`);
    }
    if (!event || typeof event !== 'object' || Array.isArray(event)) fail(`${label} is not an object.`);
    if (canonicalizeJsonText(line) !== line) fail(`${label} is not canonical.`);

    const fields = ['seq', 'ts', 'type', 'actor', 'payload', 'prev_hash', 'pub', 'sig', 'hash'];
    if (Object.keys(event).length !== fields.length || !fields.every(field => Object.hasOwn(event, field))) {
      fail(`${label} does not have the exact Camp 1 fields.`);
    }
    if (event.seq !== index || !Number.isSafeInteger(event.ts) || event.ts < 0
        || typeof event.type !== 'string' || typeof event.actor !== 'string'
        || typeof event.prev_hash !== 'string' || !HEX_32.test(event.prev_hash)
        || typeof event.pub !== 'string' || !HEX_32.test(event.pub)
        || typeof event.sig !== 'string' || !/^[0-9a-f]{128}$/.test(event.sig)
        || typeof event.hash !== 'string' || !HEX_32.test(event.hash)) {
      fail(`${label} has invalid Camp 1 field formats.`);
    }
    if (event.prev_hash !== lastHash) fail(`${label} has a broken hash chain.`);

    const body = { seq: event.seq, ts: event.ts, type: event.type, payload: event.payload, actor: event.actor };
    const canonicalBody = canonicalizeJsonText(JSON.stringify(body));
    const recomputedHash = createHash('sha256').update(`${lastHash}${canonicalBody}`, 'utf8').digest('hex');
    if (event.hash !== recomputedHash) fail(`${label} does not use the Camp 1 hash scheme.`);

    let signatureIsValid = false;
    try {
      const publicKey = createPublicKey({
        key: Buffer.concat([PUBLIC_PREFIX, Buffer.from(event.pub, 'hex')]),
        format: 'der',
        type: 'spki',
      });
      signatureIsValid = verifySignature(null, Buffer.from(recomputedHash, 'hex'), publicKey, Buffer.from(event.sig, 'hex'));
    } catch {
      signatureIsValid = false;
    }
    if (!signatureIsValid) fail(`${label} has an invalid Camp 1 signature.`);
    if (ledgerPublicHex !== null && event.pub !== ledgerPublicHex) fail(`${label} uses a different public key; one MOLT package must use one ledger key.`);
    ledgerPublicHex = event.pub;
    lastHash = recomputedHash;
  }

  return { bytes, count: lines.length, lastHash, publicHex: ledgerPublicHex };
}

async function readPayload(path) {
  let bytes;
  try {
    bytes = path === undefined ? await readStdin() : await readFile(path);
  } catch {
    fail(path === undefined ? 'Unable to read payload from stdin.' : `Unable to read payload file: ${path}`);
  }
  const text = decodeUtf8(bytes, 'Payload');
  return parseJson(text, 'Payload');
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

export function buildEvent({ seq, ts, type, actor, payload, prevHash, publicHex, privateKey }) {
  const body = { seq, ts, type, payload, actor };
  const canonicalBody = canonicalizeJsonText(JSON.stringify(body));
  const hash = createHash('sha256').update(`${prevHash}${canonicalBody}`, 'utf8').digest('hex');
  const sig = sign(null, Buffer.from(hash, 'hex'), privateKey).toString('hex');
  return { seq, ts, type, actor, payload, prev_hash: prevHash, pub: publicHex, sig, hash };
}

async function main(argv) {
  const options = parseArgs(argv);
  const ledgerPath = options.get('--ledger');
  const ledger = await readLedger(ledgerPath);
  const { privateKey, publicHex } = await readIdentity(options.get('--key'));
  if (ledger.publicHex !== null && ledger.publicHex !== publicHex) fail('Signing key does not match the existing MOLT package ledger key.');
  const payload = await readPayload(options.get('--payload'));

  const fullEvent = buildEvent({
    seq: ledger.count,
    ts: Math.floor(Date.now() / 1000),
    type: options.get('--type'),
    actor: options.get('--actor'),
    payload,
    prevHash: ledger.lastHash,
    publicHex,
    privateKey,
  });
  const canonicalEvent = canonicalizeJsonText(JSON.stringify(fullEvent));
  const separator = ledger.bytes.length > 0 && ledger.bytes[ledger.bytes.length - 1] !== 0x0a ? '\n' : '';

  try {
    await appendFile(ledgerPath, `${separator}${canonicalEvent}\n`, { encoding: 'utf8', flag: 'a' });
  } catch {
    fail(`Unable to append to ledger file: ${ledgerPath}`);
  }
  process.stdout.write(`${canonicalEvent}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(error => {
    const message = error instanceof Error ? error.message : 'Unexpected failure.';
    process.stderr.write(`molt-event: ${message}\n`);
    process.exitCode = 1;
  });
}
