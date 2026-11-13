# #29 — Gateway audit log + alerting

## What was built

- Additive signed MOLT-CORE audit ledger at `<gateway-root>/audit/`.
- One `gateway.execution` event per `Router.execute` call, for both REST and A2A.
- `gateway.alert` events for R1 token failures, R2 denial bursts, R3 freezes, and R4 error bursts.
- Alert events are written to the same signed audit ledger and also emitted as one human-readable stderr line.
- `audit.mjs verify <audit-dir>` verifies every segment with the supplied L1 verifier and checks segment links.
- `audit.mjs watch <audit-dir>` tails the active audit ledger and prints `gateway.alert` events.
- Rotation at `AUDIT_ROTATE_BYTES` / `AUDIT_ROTATE_EVENTS` with segment linking.

## Audit directory layout chosen

- Active/current segment lives directly in `audit/`:
  - `audit/events.jsonl`
  - `audit/manifest.json`
  - `audit/ed25519-public.pem`
- Completed rotated segments live in `audit/seg-000000/`, `audit/seg-000001/`, etc.
- The shared ephemeral test identity lives at `audit/identity.json`, mode 600.
- Each new active manifest records `prev_segment_head_hash` pointing at the recomputed head hash of the previous completed segment.
- `audit.mjs verify` checks completed segments oldest-first, then the active root segment.

## Expected build/test commands


## Camp 1 interoperability update

- The companion `molt-event.mjs` now uses the same five-field hash preimage and signature-over-hash-bytes scheme as the gateway audit ledger and `molt-verify`.
- A regression test builds a package with the standalone writer and verifies it with the L1 package verifier.
- `npm test`: 14 passed; `npm run typecheck`: passed.
