# MOLT-CORE Protocol Specification

**Status:** Camp 1 protocol specification; non-ASCII canonicalization remains an open decision  
**Version:** 1.0  
**Date:** 2026-11-12

## Version History

### 1.0 — 2026-11-12

- Camp 1 was ruled as the MOLT-CORE standard on November 12, 2026.
- This specification was verified against the L1 verifier, the Foundry reference implementation, and the verified `sample-good` package; the technical content and examples match those artifacts.
- The following decisions remain explicitly open and are deferred, not release blockers: non-ASCII canonicalization, key lifecycle, Room contract details, and the independent anchor-witness protocol.

## 1. Purpose and scope

MOLT-CORE defines a portable format for an append-only event ledger whose entries are linked by SHA-256 hashes and authenticated with Ed25519 signatures. A verifier uses the event records, a package manifest, and the referenced artifacts to determine whether the supplied package is internally consistent and whether each event was signed by the public key assigned to its actor.

A successful verification establishes integrity and key-based attribution under the stated trust assumptions. It does **not** establish that an event's claims are true, that the actor is a particular real-world person, or that the ledger has not been replaced by a different internally valid history. External anchoring is addressed in Section 8.

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express requirements in this specification.

## 2. Terminology

- **Ledger:** an ordered sequence of MOLT events, serialized as JSON Lines.
- **Event:** one signed record in the ledger.
- **Actor:** the identifier naming the agent or process responsible for an event.
- **Signer:** the holder of the Ed25519 private key used to sign an event hash.
- **Manifest:** `manifest.json`, which describes the ledger, actor-to-key bindings, and evidence artifacts.
- **Artifact:** a file included in the evidence package and identified by its SHA-256 digest and byte count in the manifest.
- **Canonical JSON:** the deterministic JSON serialization used as input to hashing.
- **Genesis event:** the event at sequence zero.
- **Head hash:** the recomputed hash of a specified event, usually the last event in a ledger.
- **Anchor:** an external checkpoint committing to a ledger identity, sequence number, and head hash.

## 3. Package layout

A verifier package contains these control files at its root:

- `manifest.json`
- `events.jsonl`
- `ed25519-public.pem`

It also contains each artifact named in `manifest.json`. Artifact paths are relative to the package root. A verifier MUST reject absolute paths, path traversal (`.` or `..` path components), backslash-separated paths, symlinks, and paths that escape the package directory.

`events.jsonl` contains one canonical JSON event per line, in sequence order. Each event line MUST end with a newline; the file's exact byte length MUST equal `manifest.ledger_bytes`. An empty ledger is represented by an empty `events.jsonl` and has no event lines.

The L1 verifier currently enforces these implementation limits: manifest no larger than 1,000,000 bytes, ledger no larger than 32 MiB, and an event line no larger than 256 KiB. These are verifier limits, not a claim that larger ledgers are intrinsically invalid. Implementations claiming L1 compatibility MUST apply the same limits unless a later profile changes them.

## 4. Event envelope

Every event MUST be a JSON object containing exactly these nine fields and no others:

| Field | Meaning | Required representation and constraints |
|---|---|---|
| `seq` | Zero-based event position in the ledger. | JSON integer; MUST be non-negative. The first event is `0`; each following event increments by exactly one. |
| `ts` | Event creation time. | Unix timestamp in whole seconds; JSON non-negative integer. |
| `type` | Event type name. | JSON string. |
| `actor` | Identifier of the event-producing agent or process. | JSON string. |
| `payload` | Event-specific data. | Any JSON value: object, array, string, number, boolean, or `null`. It MUST be valid JSON and canonicalizable under the applicable canonicalization rule. |
| `prev_hash` | Hash link to the immediately preceding event. | Exactly 64 lowercase hexadecimal characters. For sequence zero, it MUST be 64 ASCII zeroes. Otherwise it MUST equal the preceding event's **recomputed** hash. |
| `pub` | Raw Ed25519 public key of the event signer. | Exactly 64 lowercase hexadecimal characters representing 32 public-key bytes. |
| `sig` | Ed25519 signature over the event hash bytes. | Exactly 128 lowercase hexadecimal characters representing the 64-byte Ed25519 signature. |
| `hash` | SHA-256 event hash. | Exactly 64 lowercase hexadecimal characters representing 32 digest bytes. |

The event object MUST contain exactly the fields above. The serialization order of fields in the JSON line is determined by canonicalization, not by the table order.

### 4.1 Sequence and time

`seq` MUST equal the zero-based line position of the event. A gap, duplicate, negative value, non-integer, or out-of-order value invalidates the ledger.

`ts` is a Unix timestamp in whole seconds. The L1 implementation checks that it is a non-negative integer; it does not impose a clock-skew window or prove that the timestamp is accurate.

### 4.2 Actor and public-key binding

The `actor` field identifies the logical event producer. The `pub` field identifies the cryptographic key that signed this event. The manifest's `agent_pubkeys` object binds actor identifiers to public keys.

For every event, the verifier MUST require both:
1. `event.pub` equals the package's Ed25519 public key; and
2. `manifest.agent_pubkeys[event.actor]` equals that same public key.

This rule prevents an event from claiming an actor whose manifest key binding does not match the signer key. It does not independently establish the real-world identity or authorization of the actor.

## 5. Canonicalization

### 5.1 Settled rule for ASCII

The L1 canonicalization entry point is the function **`canonicalizeJsonText`** from the verified `molt-canonical.mjs` module. The L1 README identifies this canonicalization profile as **RFC 8785 (JSON Canonicalization Scheme, JCS)**.

For ASCII JSON values, implementations MUST produce the same canonical representation as `canonicalizeJsonText`. Object keys are sorted deterministically; insignificant JSON whitespace is removed; strings and numbers are serialized deterministically. The canonical output is UTF-8 encoded before hashing.

An event line in `events.jsonl` MUST itself equal the canonicalized representation of that event. A verifier MUST reject a line that parses as JSON but is not already in canonical form.

### 5.2 OPEN: non-ASCII canonicalization

**The non-ASCII rule is not settled by this specification. Implementations MUST NOT silently choose one of the competing behaviors and claim cross-implementation compatibility for non-ASCII data.**

The supplied Foundry implementation's `stableJson`/`canonical` behavior:
- escapes characters above U+007E as `\uXXXX` (using surrogate-pair escapes for supplementary code points); and
- sorts object keys by UTF-8 byte order.

The supplied L1 `canonicalizeJsonText` implementation follows the RFC 8785-style behavior described in its README:
- emits non-ASCII characters as UTF-8 rather than escaping all characters above U+007E; and
- uses JavaScript's default string sort, which compares UTF-16 code units.

These behaviors agree for ASCII and can diverge for non-ASCII strings and object keys. Consequently, the five-field body hash is interoperable for ASCII payloads under the supplied implementations, but non-ASCII compatibility remains an open protocol decision.

**What settles this:** a recorded protocol ruling by the MOLT-CORE maintainers, followed by a versioned test-vector set covering (at minimum) non-ASCII string values, BMP and supplementary-plane object keys, and keys whose UTF-8 and UTF-16 sort orders differ. The ruling must identify the canonicalization algorithm and update Foundry, the L1 verifier, and all event writers/verifiers together. Until then, implementations SHOULD restrict interoperable signed event content to ASCII strings and ASCII object keys.

## 6. Camp 1 hash and signature scheme

**Camp 1 is the normative scheme.** The signed body consists of exactly these FIVE fields:

- `seq`
- `ts`
- `type`
- `payload`
- `actor`

The body MUST NOT include `prev_hash`, `pub`, `sig`, or `hash`.

Let:

- `P` be the 64-character lowercase hexadecimal text in `prev_hash`;
- `B` be the object containing only the five fields above;
- `C` be the UTF-8 byte sequence of `canonicalizeJsonText` applied to `B`;
- `H` be the 32-byte SHA-256 digest.

The event hash is:

`hash = lowercase_hex(SHA-256(UTF-8(P || C)))`

Here `P || C` means the ASCII bytes of the 64-character hexadecimal `prev_hash` text, followed immediately by the canonical body bytes. It does **not** mean decoding `prev_hash` into 32 bytes before concatenation.

The Ed25519 signature is:

`sig = lowercase_hex(Ed25519-Sign(private_key, H))`

The signature input is the **32 raw hash bytes** obtained by decoding the hexadecimal event hash. It is NOT the canonical body string, the UTF-8 encoding of the hash's hexadecimal text, or the complete event JSON.

### 6.1 Explicit incompatibility warning

An earlier implementation of `molt-verify-ledger.mjs` used a seven-field body (adding `prev_hash` and `pub`) and signed the canonical body string. **That scheme is WRONG for Camp 1 and MUST NOT be implemented as MOLT-CORE.** It is incompatible with real Foundry output and the verified L1 `sample-good` package.

The supplied `molt-event` and `molt-verify-ledger` Camp 2 files still describe/use that incompatible seven-field, body-signature scheme. They are included as reference material for the event envelope and known implementation gap only; they do not override this section.

## 7. Hash chain

The ledger is an ordered hash chain.

1. For the genesis event (`seq = 0`), `prev_hash` MUST be 64 zeroes.
2. The verifier constructs the five-field body and recomputes the event hash using Section 6.
3. For each later event, `prev_hash` MUST equal the previous event's recomputed hash.
4. The verifier MUST carry forward the recomputed hash, not the `hash` string merely stored in the previous event.
5. The verifier MUST compare the recomputed hash with the event's stored `hash`; a mismatch invalidates the event and ledger.

A verifier MUST start at genesis and process events in sequence order. It MUST NOT begin from a stored intermediate hash and treat that value as a trusted chain root.

This construction makes changes to a prior event detectable in later links, provided the verifier starts from the expected genesis and validates the full chain.

## 8. Manifest

`manifest.json` is a JSON object containing:

| Member | Meaning and constraints |
|---|---|
| `ledger_bytes` | Exact byte length of `events.jsonl`; non-negative safe integer. |
| `agent_pubkeys` | Object mapping actor identifiers to 64-character lowercase hexadecimal raw Ed25519 public keys. |
| `artifacts` | Object mapping each relative artifact path to its SHA-256 digest as 64 hexadecimal characters. |
| `artifact_bytes` | Object mapping each artifact path to its exact non-negative safe-integer byte count. It MUST cover every key in `artifacts`, and the key sets MUST have equal size. |
| `anchor` | Optional local anchor object, described below. |

The package also contains `ed25519-public.pem`, which supplies the Ed25519 public key used by the L1 package verifier. The verifier parses this PEM, requires the Ed25519 algorithm, extracts its 32 raw public-key bytes, and derives `keyId = SHA-256(raw_public_key)`.

For every artifact, the verifier MUST:
- validate that the path is safe and remains inside the package;
- require a regular file and reject symlinks;
- compare the actual byte count with `artifact_bytes[path]`; and
- compare SHA-256 of the exact file bytes with `artifacts[path]`.

The manifest is not itself a trusted authority merely because it is present in the package. It is a set of claims that the verifier checks against the files and ledger. Trust in the signer key and the distribution of the package are separate concerns.

### 8.1 Optional manifest anchor

The L1 package manifest's optional `anchor` object has:
- `seq`: non-negative integer sequence number; and
- `hash`: 64-character lowercase hexadecimal event hash.

The verifier MUST ensure the referenced event exists and that the recomputed hash at that sequence equals the anchor hash. This is an internal consistency check. It does not, by itself, prove that the anchor was published externally or that it predates a later rewrite.

## 9. Verification procedure and stable checks

A conforming L1 package verifier MUST run the following checks in order and report the first failed check with its stable identifier. The stable IDs correspond to the verified L1 verifier.

| ID | Check | Required behavior and failure meaning |
|---|---|---|
| **V-01** | Package path and directory | Require an absolute path to an existing real directory, not a symlink. Failure means the package root cannot be safely established. |
| **V-02** | Control files present and regular | Require `manifest.json`, `events.jsonl`, and `ed25519-public.pem` to exist as regular non-symlink files and be readable. Failure means required package control data is missing or unsafe. |
| **V-03** | Size limits | Enforce the L1 manifest and ledger size limits in Section 3. Failure means the package exceeds the verifier's resource limits. |
| **V-04** | File completeness and truncation | Require valid UTF-8 for control text, a final newline for a non-empty ledger, and exact agreement between ledger byte length and `manifest.ledger_bytes`. Failure means the package may be truncated, incomplete, or byte-count inconsistent. |
| **V-05** | Manifest JSON object | Parse `manifest.json` and require its root value to be a JSON object. Failure means the manifest is malformed or has the wrong root type. |
| **V-06** | Manifest schema | Require `artifacts`, `artifact_bytes`, and `agent_pubkeys` to be objects and `ledger_bytes` to be a non-negative safe integer; require artifact digest and byte-count maps to cover the same artifact names. Failure means the manifest lacks required structure or values. |
| **V-07** | Ed25519 public key | Parse `ed25519-public.pem`, require Ed25519, and extract exactly 32 raw public-key bytes. Failure means the package verification key is absent, malformed, or the wrong algorithm. |
| **V-08** | Artifact digests and byte counts | Validate every artifact path, file type, byte count, and SHA-256 digest. Failure means an artifact is missing, unsafe, altered, or inconsistent with the manifest. |
| **V-09** | Ledger event checks | For each event, require valid JSON, canonical line representation, exactly nine fields, valid field formats, actor-key binding, contiguous sequence, correct genesis/previous link, recomputed hash equality, and a valid Ed25519 signature over the 32 hash bytes. Failure means the event ledger is malformed, out of order, tampered with, incorrectly linked, incorrectly signed, or attributed to an unbound actor key. |
| **V-10** | Anchor check | If `manifest.anchor` exists, require a well-formed anchor, an event at its sequence, and equality between its hash and the recomputed event hash at that sequence. Failure means the anchor is malformed, points outside the ledger, or does not match the recomputed chain. If no manifest anchor exists, report `anchor: none`; do not claim external anchoring. |

### 9.1 V-09 event sub-check order

Within V-09, the L1 verifier checks, in this order:

1. JSON parsing.
2. Canonical event-line equality.
3. Exact nine-field envelope.
4. Field formats.
5. Actor-to-public-key binding.
6. Sequence number equals the zero-based event index.
7. Genesis rule or `prev_hash` equality with the previous recomputed hash.
8. Recompute the SHA-256 hash from the five-field body and compare with stored `hash`.
9. Verify Ed25519 over the 32 recomputed hash bytes.

The verifier MUST continue the chain using the recomputed hash. It MUST NOT use a stored event hash as the next trusted link after a failed recomputation.

## 10. External anchoring

An external anchor is a commitment to the tuple:

`(ledger_id, seq, head_hash)`

- `ledger_id` is the recomputed genesis hash identifying the ledger.
- `seq` is the sequence number being checkpointed.
- `head_hash` is the recomputed hash of the event at that sequence.

The supplied `molt-anchor` implementation stores anchors as Git commits. Anchors link to prior anchors through `prev_anchor`; the implementation rejects backwards sequence movement and conflicting heads at the same sequence. It recomputes the ledger chain from genesis to the anchored sequence and compares the recomputed event hash with the anchor's `head_hash`. A verifier MUST NOT trust the anchor's stored `head_hash` or any stored event hash without recomputation.

The anchor store should be pushed to a Git remote that the ledger owner does not control. A local Git repository proves nothing: the ledger owner can rewrite the ledger and the local anchor history together. A remote push improves the evidence only to the extent that the remote is independently controlled and retains the published history.

**A real guarantee requires a second witness** outside the ledger owner's control—for example, an independently operated public repository plus a trusted timestamping service or another independent witness that records the checkpoint. Even a remote repository can be rewritten by whoever controls that remote. The verifier should check the remote actually contains the published anchor; merely having a configured remote is not evidence that a push occurred.

Anchoring and event signatures prove different things. Event signatures authenticate event hashes under keys; an anchor makes a ledger head externally observable at a checkpoint. The supplied `molt-anchor` README explicitly says its current implementation does not verify event signatures and that anchors themselves are unsigned. Those checks remain the responsibility of the MOLT-CORE verifier and the external witness design.

The anchor README also documents an earlier guessed event schema that does not match MOLT-CORE. Its guessed `seq/prev/payload/hash` hash formula MUST NOT be used. Any anchor implementation used with MOLT-CORE MUST use the nine-field event envelope and Camp 1 hash calculation in Section 6.

## 11. Security and interpretation limits

- A valid signature proves that the corresponding private key signed the 32-byte event hash; it does not prove the event's factual truth.
- An actor name is a manifest key-map identifier, not a verified civil identity.
- A package's internal manifest and files can be replaced together unless the package is anchored or otherwise distributed through a trusted channel.
- A hash chain detects alteration relative to a trusted starting point; it does not alone prevent an owner from creating a different valid ledger from genesis.
- A local anchor repository is not an independent witness.
- Key custody, key rotation, revocation, and recovery are not defined here.
- The gateway's approval-token gate is not part of this event-ledger protocol.

## 12. Out of scope and related specifications

This document specifies the event ledger and package verification profile only. It is not the whole MOLT system.

| Out-of-scope subject | Where it is specified or implemented |
|---|---|
| Gateway approval-token gate, including caller/target/event binding, single-use consumption, and fail-closed execution behavior | `gateway-approval-gate/REPORT.md` and the gateway implementation. The supplied report says production integration with Foundry's authoritative ledger and trusted caller resolver remains open; its local test issuer is explicitly `LOCAL_TEST_ONLY`, not a Foundry contract. |
| Per-caller permissions and execution authorization | The gateway's authorization and routing contract, not this ledger format. The supplied gateway report describes the approval gate but does not establish a complete general per-caller permission model. |
| Room frozen contract and multi-agent sandbox rules | The Room's separate frozen signed contract and implementation. No Room contract was included in this source bundle, so this specification does not restate its rules. |
| Key rotation, revocation, and key lifecycle | A separate key-management specification is required; no complete key-rotation contract was present in the supplied files. |
| Non-ASCII canonicalization choice | Open decision in Section 5.2; requires an explicit protocol ruling and cross-implementation test vectors. |

## Appendix A. Verified Camp 1 sample

The following excerpts are from `molt-verify-l1/samples/sample-good/`, the supplied L1 fixture. The complete fixture contains two events; the manifest anchor refers to sequence 1.

### A.1 Event excerpt

This is the first event, shown as a formatted JSON object for readability. In the package, `events.jsonl` stores the canonical one-line representation.

```json
{
  "actor": "foundry-control",
  "hash": "9e5ee6e3e42504b009d4efdc837ea1d4a0ba82ad9186faadd7ced3e88efacc81",
  "payload": {"sample": "good", "score": 1},
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "pub": "e783fcdf6697a0ed5e370bb9665ca3e8dc5f86c3355222624d2ea4b0e9d43db2",
  "seq": 0,
  "sig": "0540e6089018dd1c6c4e70dce7752255e9a6a56bb3e805e2564771a4c3e502e1ff52543307505aedb2377e23c6c3584907d2b0d345a66a65f9b35cee55569301",
  "ts": 1700000000,
  "type": "sample.event"
}
```

### A.2 Manifest excerpt

```json
{
  "artifacts": {
    "artifact.txt": "e5e8280c68f135da2186b29ced627bf7700ce8b855c07a1704f62070e579bf50"
  },
  "artifact_bytes": {
    "artifact.txt": 24
  },
  "agent_pubkeys": {
    "foundry-control": "e783fcdf6697a0ed5e370bb9665ca3e8dc5f86c3355222624d2ea4b0e9d43db2"
  },
  "ledger_bytes": 950,
  "anchor": {
    "seq": 1,
    "hash": "0c2d611f3177d7d971aa5df569e972d50964cb738899b3b360d1a8b52d036ca8"
  }
}
```

The supplied L1 README reports this package as `PASS all checks` with `anchor: verified`. The fixture is a deterministic test package, not a live private key or a production ledger.

## Appendix B. Implementation conformance notes

The supplied materials identify these implementation facts and gaps:

1. Foundry's `MoltLedger` computes the hash from `prev_hash` plus the canonical five-field body and signs the decoded 32-byte hash with Ed25519.
2. The L1 verifier implements the Camp 1 five-field/hash-bytes scheme and exposes V-01 through V-10.
3. `molt-event` and `molt-verify-ledger` in the supplied Camp 2 bundle still document/use the incompatible seven-field/body-string signature scheme. They MUST be corrected before they are treated as Camp 1-compatible tools.
4. The L1 verifier's README identifies `canonicalizeJsonText` as RFC 8785, while Foundry's own canonicalizer differs for non-ASCII strings and key ordering. This remains open as specified in Section 5.2.
5. The supplied anchor implementation's README says its event schema is a guess and does not match the real MOLT event format. Its hash calculation must be adapted before it can anchor real MOLT-CORE ledgers.
