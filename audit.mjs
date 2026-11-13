#!/usr/bin/env node
import { open, readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyMoltPackage } from './verifier.mjs';

const ZERO_HASH = '0'.repeat(64);
const HEX_32 = /^[0-9a-f]{64}$/;

async function listSegments(auditDir) {
  const entries = await readdir(auditDir, { withFileTypes: true });
  const segments = entries
    .filter((entry) => entry.isDirectory() && /^seg-\d{6}$/.test(entry.name))
    .map((entry) => entry.name)
    .sort();

  // Oldest completed segments first, active root last.
  return [...segments.map((name) => path.join(auditDir, name)), auditDir];
}

async function lastEventHash(dir) {
  const text = await readFile(path.join(dir, 'events.jsonl'), 'utf8');
  const lines = text.split('\n').filter((line) => line.length > 0);
  if (lines.length === 0) return ZERO_HASH;
  const event = JSON.parse(lines[lines.length - 1]);
  return event.hash;
}

async function verify(auditDir) {
  const abs = path.resolve(auditDir);

  let segments;
  try {
    segments = await listSegments(abs);
  } catch (error) {
    console.error(`INVALID: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  let previousHead = null;

  for (let index = 0; index < segments.length; index += 1) {
    const dir = segments[index];
    const label = dir === abs ? 'active' : path.basename(dir);
    const result = await verifyMoltPackage(dir);

    if (!result.valid) {
      console.error(
        `INVALID ${label}: ${result.checkId} ${result.checkName}: ${result.reason}`,
      );
      return 1;
    }

    if (index > 0) {
      let manifest;
      try {
        manifest = JSON.parse(
          await readFile(path.join(dir, 'manifest.json'), 'utf8'),
        );
      } catch (error) {
        console.error(
          `INVALID ${label}: cannot read manifest: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return 1;
      }

      const link = manifest.prev_segment_head_hash;
      if (typeof link !== 'string' || !HEX_32.test(link)) {
        console.error(`INVALID ${label}: missing prev_segment_head_hash`);
        return 1;
      }

      if (link !== previousHead) {
        console.error(`INVALID ${label}: prev_segment_head_hash mismatch`);
        return 1;
      }
    }

    previousHead = await lastEventHash(dir);
    console.log(`VALID ${label}: ${result.count} event(s)`);
  }

  console.log(`VALID ${segments.length} segment(s)`);
  return 0;
}

async function watch(auditDir) {
  const abs = path.resolve(auditDir);
  const file = path.join(abs, 'events.jsonl');

  let offset = 0;
  let carry = '';

  console.error(`watching ${file}`);

  setInterval(async () => {
    try {
      const info = await stat(file);

      if (info.size < offset) {
        offset = 0;
        carry = '';
      }

      if (info.size === offset) return;

      const handle = await open(file, 'r');
      const buffer = Buffer.alloc(info.size - offset);
      await handle.read(buffer, 0, buffer.length, offset);
      await handle.close();

      offset = info.size;

      const text = carry + buffer.toString('utf8');
      const lines = text.split('\n');
      carry = lines.pop() ?? '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const event = JSON.parse(line);
          if (event.type === 'gateway.alert') {
            console.log(line);
          }
        } catch {
          /* incomplete or malformed line; keep tailing */
        }
      }
    } catch {
      /* file may not exist yet, or rotation is in progress */
    }
  }, 500);

  await new Promise(() => {});
}

async function main() {
  const [command, dir] = process.argv.slice(2);

  if (command === 'verify' && dir) {
    process.exitCode = await verify(dir);
    return;
  }

  if (command === 'watch' && dir) {
    await watch(dir);
    return;
  }

  console.error('usage: node audit.mjs <verify|watch> <audit-dir>');
  process.exitCode = 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
