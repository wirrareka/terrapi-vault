# Prompt for the memento agent — implement the vault-sync oplog client

> Copy everything below the line into the memento agent (it works in the `memento` repo,
> a sibling of `terrapi-vault`). It is self-contained but points at the published contract.

---

You are implementing the **client half** of personal multi-device sync for memento (and
later probe). The **server is already built and live** in the sibling repo `terrapi-vault`
(a path dependency: memento pins `terrapi-vault = { path = "../terrapi-vault" }`). Your job is
the `memento-core` side: capture local changes as encrypted ops, push/pull them to the
vault-sync server, and apply remote ops with per-row last-writer-wins.

## Read first (the contract — do not guess it)

- `../terrapi-vault/spec/sync-openapi.yaml` — the wire contract (endpoints, headers, schemas).
- `../terrapi-vault/docs/planning/02-vault-sync-oplog.md` — the full design + rationale.
- Your own `crates/memento-core/src/sync.rs` — the **existing** `SyncProvider` trait
  (`LocalOnly` no-op, `GitSync` real whole-file blob sync, `MementoCloud` stub).

## The key reality you must resolve first

memento-core's `SyncProvider` is **whole-file blob** today: `push/pull(&self, vault_path:
&Path)`. The oplog is **row-level** — it has no place in that signature. So your first design
decision: introduce an **oplog-capable sync path** (a new provider type and/or an extension of
the abstraction) WITHOUT breaking `LocalOnly` or `GitSync` or their tests. The hard part is
not the HTTP — it is wiring op-capture into memento's DB write path so every row mutation
emits an op, and applying remote ops back into the same SQLCipher store. Plan that integration
explicitly before coding; surface the options (e.g. a write-through op-log table in the vault
vs. a trigger-based capture) and pick one.

## What the server expects (summary; the spec is authoritative)

Base path `/v1/sync/{vault_id}`. `vault_id` is an opaque UUID you choose at account creation
(NOT derived from the passphrase — the server is blind).

- **Device identity:** each device generates an **ed25519** keypair on first run; store the
  private key in OS secure storage (Keychain / equivalent), never in the vault blob.
- **Request signing:** every `push`/`pull`/`status`/`tail` carries headers `X-Device-Id`,
  `X-Sync-Ts` (unix secs), `X-Sync-Nonce` (unique per request), `X-Sync-Sig` (base64 ed25519).
  Sign the canonical string **exactly**:
  `v1\n{METHOD}\n{path?query}\n{vault_id}\n{ts}\n{nonce}\n{sha256_hex(body)}`
  (for GETs the body is empty → hash of `""`). Reuse the SAME `{path?query}` you put on the
  request. The server allows ±300 s skew and rejects repeated nonces.
- **Enrolment (server-blind):** derive an **enrolment secret** = Argon2id over the vault
  passphrase with a **domain-separation label DISTINCT from the at-rest key derivation** and an
  **account-level salt** (NOT the vault's own salt). Flow:
  1. First device: `POST /account` with `enroll = { salt_b64, params, hash_b64 }` where
     `hash_b64 = base64(SHA-256(enroll_secret))`, plus its `device = { device_id, pubkey_b64 }`.
     Self-sign the request with the device key.
  2. New device: `GET /enroll-challenge` → `{ salt_b64, params }`; derive `enroll_secret`;
     `POST /enroll` with `proof_b64 = base64(enroll_secret)` + its device registration,
     self-signed. (The server checks `SHA-256(proof) == stored hash`, then discards it.)
  Use the SAME Argon2 params the server is told about; reuse `terrapi-vault`'s
  `derive_key`/`KdfParams` where convenient (it is Argon2id).
- **Ops:** `Op { op_id, device_id, hlc:{wall_ms,counter}, collection_id, encrypted_payload }`.
  - `op_id` = ULID or UUIDv7 (unique, ~monotonic). The server dedupes on it (push is retryable).
  - `hlc` = a hybrid logical clock you maintain on the client (advance on each local change;
    merge max-with-remote on pull). The wire type is `vault_transport::Hlc`.
  - `collection_id` = opaque grouping (per table/collection). Consider HMAC-ing it under a
    vault-derived key so it leaks no metadata.
  - `encrypted_payload` = base64 AEAD ciphertext of the change `(table, row_id, columns)` —
    or a tombstone for deletes. **The server never sees plaintext.**
- **push** → `{ accepted, duplicates, latest_seq }`. **pull?since={seq}&limit={n}** →
  `{ ops:[StoredOp{seq, ...}], latest_seq }` (seq-ordered). **status** → counts.
  **tail** (WebSocket) → each new `StoredOp` as a JSON text frame; on `{"resync":true}` do a
  full pull. The server-assigned `seq` is your **pull cursor** (persist the last applied seq).

## Payload crypto (client-only; keep the server blind)

- Derive a dedicated **sync-payload key** from the vault key via a KDF/HKDF with a distinct
  domain label (do NOT reuse the raw SQLCipher key directly).
- AEAD per op (XChaCha20-Poly1305 or AES-256-GCM) with a fresh random nonce per op; prepend
  the nonce to the ciphertext. AAD MAY include `op_id`/`collection_id` to bind them.
- Deletes are tombstone ops (still encrypted). Never send anything the server could read.

## Apply / conflict (per-row LWW)

- Maintain a persisted **last-applied seq** cursor; pull `since=cursor`, apply in seq order,
  advance the cursor. Idempotent (re-applying a seen `op_id` is a no-op).
- For each op, decrypt and apply with **per-row LWW keyed by HLC**: keep each row's
  last-applied HLC; an incoming op with a **lower** HLC for that row is ignored. Equal HLC →
  break ties by `device_id` (deterministic). Different rows merge freely (the whole point).
- CRDT text-merge for note bodies is **out of scope** (Phase 4) — LWW per row for v1.

## Hard constraints

- Do NOT break `LocalOnly` or `GitSync` or their tests; the oplog is an additional path.
- Sync logic lives in **memento-core**, NOT in the `terrapi-vault` lib (the lib stays
  dependency-neutral so memento/probe are never constrained). You MAY use the lib's public
  API (`derive_key`, `KdfParams`, `rusqlite` re-export).
- The server is the source of truth for the wire contract. If you need a contract change,
  propose it by editing `../terrapi-vault/spec/sync-openapi.yaml` and flag it — do not diverge
  silently.

## Suggested phasing

1. **Identity + enrolment**: device keypair + secure storage; `account`/`enroll-challenge`/
   `enroll`; the request-signing helper. Test against a locally-run `vault-sync` (`cargo run
   -p vault-sync`, bind loopback).
2. **Op capture + push**: HLC clock; emit ops on local writes; AEAD payloads; `push`.
3. **Pull + apply (LWW)**: cursor, decrypt, per-row LWW apply, idempotency.
4. **Live tail (WS)** + resync-on-lag; **status** UI.
Write integration tests that round-trip ops between two in-process clients through a real
`vault-sync` instance (two devices, concurrent edits to different rows → both converge).

## Deliverables

Working oplog sync in memento-core behind the existing settings UI (alongside LocalOnly/Git),
green `memento-core` tests, and a short design note in the memento repo describing the
op-capture integration you chose.
