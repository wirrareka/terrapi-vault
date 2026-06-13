# vesta-sync — row-level oplog (Svet B) — design v1

Owner decision (2026-05-29): vesta-sync v1 is a **row-level oplog**, not whole-file blob
sync. Server-blind, device-keypair auth, per-row LWW by HLC. CRDT text-merge is Phase 4.
See planning §5 of `01-vault-as-service.md` and the memory `vesta-sync-oplog-decision`.

## 0. Reality this must fit

- `memento`/`probe` embed the **at-rest lib** (`terrapi-vesta`) to encrypt a local
  SQLCipher file (+ plaintext `<vault>.meta.json` KDF sidecar, no secrets).
- `memento-core` ships a `SyncProvider` trait that is **whole-file blob** today
  (`async push/pull(vault_path)`, `status()`; `LocalOnly` no-op, `GitSync` real,
  `MementoCloud` stub). **The oplog needs a NEW client provider** in memento-core — out of
  scope for this repo; built/coordinated separately. **This repo delivers the server + the
  published wire contract.**
- vesta-sync carries **none** of Svet A: no OpenSearch, no tenants, no residency air-gap, no
  B3-to-OpenSearch. (Dependency firewall — see `core-lib-neutrality-principle`.)

## 1. Roles

- **Server (vesta-sync):** a dumb, signed, append-only **op store**, partitioned by
  `vault_id`, payloads opaque. Assigns a per-vault monotonic `seq`. Never holds the vault
  key or plaintext. Runs on a mac mini / small VPS.
- **Client (memento-core, future):** captures each local DB row change as an op, encrypts
  the payload with a key derived from the vault key, pushes ops, pulls remote ops, applies
  them with per-row LWW keyed by HLC. Owns all conflict logic.

## 2. Identity & auth (server-blind)

- `vault_id`: opaque public UUID for a vault's sync account. **Not** derived from the
  passphrase (keeps the server blind); chosen at account creation.
- **Enrolment secret:** derived client-side from the **vault passphrase** via Argon2id with a
  domain-separation label distinct from the at-rest key derivation (so a leaked enrolment
  verifier never helps derive the vault key). The server stores only an Argon2id **verifier**
  (salt + params + hash) — it can check a new device's proof without learning the secret.
  - Tradeoff (documented): an attacker with the server DB can offline-guess a *weak*
    passphrase against the verifier. Acceptable for personal use with a strong passphrase +
    strong Argon2 params; domain separation contains the blast radius to enrolment only.
- **Device keypair:** each device generates an **ed25519** keypair on first run. After
  proving the enrolment secret it registers `{device_id, pubkey}`. The server stores pubkeys.
- **Request auth:** every `push`/`pull`/`status` carries a detached **ed25519 signature** by
  the calling device over a canonical string `v1\n{method}\n{path}\n{vault_id}\n{ts}\n{nonce}\n{sha256(body)}`.
  The server verifies against a registered device pubkey, rejects a stale `ts` (±300 s skew)
  and replays. Headers: `X-Device-Id`, `X-Sync-Ts`, `X-Sync-Nonce`, `X-Sync-Sig` (base64).

## 3. Op model

```
Op {
  op_id:            String,   // client ULID/UUIDv7, globally unique, monotonic-ish
  device_id:        String,   // origin device
  hlc:              { wall_ms: u64, counter: u32 },  // vault_transport::Hlc — client order + LWW key
  collection_id:    String,   // opaque grouping (client may HMAC it; low-entropy metadata)
  encrypted_payload: String,  // base64 AEAD ciphertext: (table, row_id, column values). Server-opaque.
}
```

- The server adds a per-vault **`seq: u64`** on accept — the transport pull cursor (robust
  "give me everything after seq N", independent of clock quality). HLC is for *client*
  ordering/LWW; `seq` is for *transport* completeness.
- **Idempotent:** an `op_id` already stored for this `vault_id` is a no-op (dedupe). Push is
  safely retryable.

## 4. Endpoints (`spec/sync-openapi.yaml`)

- `POST /v1/sync/{vault_id}/account` — first device creates the account: enrolment verifier
  `{salt, params, hash}` + first `{device_id, pubkey}`. `201` / `409 account_exists`.
- `POST /v1/sync/{vault_id}/enroll` — new device: `{enroll_proof, device_id, pubkey}`.
  `200` / `401 bad_proof`. (Signed by the *new* device key; proof gates it.)
- `POST /v1/sync/{vault_id}/push` — device-signed. Body `{ ops: [Op…] }`. →
  `{ accepted, duplicates, latest_seq }`.
- `GET /v1/sync/{vault_id}/pull?since={seq}&limit={n}` — device-signed. →
  `{ ops: [Op + seq …], latest_seq }` (seq-ordered, `seq > since`, capped by `limit`).
- `GET /v1/sync/{vault_id}/status` — device-signed. → `{ latest_seq, op_count, device_count }`.
- `GET /healthz` — liveness.
- **Deferred:** `WS /v1/sync/{vault_id}/tail` — live op push to connected devices.

## 5. Storage (SQLite via the lib's `rusqlite`)

Payloads are already E2E-encrypted, so the server DB is plain SQLite (SQLCipher-at-rest is a
later defense-in-depth option, not required for confidentiality).

```
accounts(vault_id TEXT PK, enroll_salt BLOB, enroll_params TEXT, enroll_hash BLOB, created_at INT)
devices (vault_id TEXT, device_id TEXT, pubkey BLOB, enrolled_at INT, PRIMARY KEY(vault_id, device_id))
ops     (vault_id TEXT, seq INTEGER, op_id TEXT, device_id TEXT,
         hlc_wall INT, hlc_counter INT, collection_id TEXT, payload BLOB, created_at INT,
         PRIMARY KEY(vault_id, seq), UNIQUE(vault_id, op_id))
-- index (vault_id, seq) is the PK; pull is a range scan on it.
```

`seq` is allocated as `COALESCE(MAX(seq),0)+1` per `vault_id` inside the push transaction.

## 6. Crate layout (`services/vesta-sync`)

Binary crate (like vesta-broker). Planned modules:
- `dto.rs` — wire types (Op, requests/responses), serde.
- `store.rs` — SQLite schema + accounts/devices/ops queries (rusqlite).
- `auth.rs` — ed25519 request-signature verification + enrolment Argon2 verifier + replay guard.
- `http.rs` — axum router + handlers (account/enroll/push/pull/status/healthz).
- `config.rs` — bind addr, db path, dev knobs.
- `main.rs` — wire-up + `axum::serve`.

Deps (services workspace): `axum`, `tokio`, `serde`, `serde_json`, `base64`, `time`,
`thiserror`, `terrapi-vesta` (rusqlite re-export + Argon2 KDF), `vesta-transport` (`Hlc`), an
ed25519 verifier (`ed25519-dalek` or reuse `ssh-key`). **No** reqwest/OpenSearch/residency.

## 7. Phasing (server)

1. **Data model + store** — schema, accounts/devices/ops, seq allocation, dedupe; unit-tested.
2. **Auth** — enrolment Argon2 verifier; ed25519 request signatures + replay window; tested.
3. **HTTP** — account/enroll/push/pull/status; `oneshot` tests (signed happy paths + 401/409).
4. **Spec** — publish `spec/sync-openapi.yaml`; bootstrap/runbook doc.
5. **Deferred:** WS tail; SQLCipher-at-rest for the server DB; client provider in memento-core
   (separate, coordinated); CRDT text-merge (Phase 4).

## 8. Server-blind guarantees (invariants)

- The server stores: `vault_id`, an Argon2 verifier, device pubkeys, opaque ops. It **never**
  receives the vault passphrase, the vault key, or plaintext note content.
- `encrypted_payload` is opaque bytes. `collection_id` is the only low-entropy metadata; the
  client MAY HMAC it under a vault-derived key to blind it further (recommended, documented).
- No platform deps; no residency; not multi-tenant. If vesta-sync ever serves *tenant* data
  it must adopt the per-group air-gap (flagged scope boundary, planning §5).

## 9. Implementation status (2026-05-29)

**Server — Phases 1–4 DONE.** `services/vesta-sync` is now a real axum server (was a
print-only skeleton):
- `store.rs` — SQLite op store via the lib's `rusqlite` (plain sqlite; payloads already E2E).
  Accounts / devices / ops; per-vault `seq` allocation in the push transaction; idempotent
  dedupe by `(vault_id, op_id)`; per-vault isolation. Unit-tested.
- `auth.rs` — ed25519 request-signature verify (`verify_strict`), the versioned canonical
  string, the enrolment Argon2-verifier check (constant-time SHA-256), and an in-memory
  `ReplayGuard` (±300 s skew window). Unit-tested.
- `http.rs` — axum router + handlers: `account` / `enroll-challenge` / `enroll` / `push` /
  `pull` / `status` / `healthz`. Device-signed (registered) + self-signed (account/enroll)
  auth; `DefaultBodyLimit`. Full end-to-end `oneshot` tests (two-device create→enroll→push→
  pull→status, plus unsigned-401 and replay-401).
- `config.rs` — env (`VESTA_SYNC_BIND` default `127.0.0.1:8300`, `VESTA_SYNC_DB`,
  `VESTA_SYNC_MAX_BODY_BYTES`, `VESTA_SYNC_MAX_PULL`).
- New dep: `ed25519-dalek` (workspace) for raw device-signature verification.
- Contract published: `spec/sync-openapi.yaml` (v1.0.0). 12 tests pass; clippy `-D warnings`
  + `cargo fmt --check` clean.

**WS live-tail — DONE 2026-05-29.** `GET /v1/sync/{vault_id}/tail` (axum `ws`). The upgrade
is device-signed exactly like a GET; after it verifies, the socket streams each newly-pushed
`StoredOp` as a JSON text frame off a per-vault `tokio::broadcast` channel (capacity 256). A
subscriber that lags is sent `{"resync":true}` and should do a full `pull`. `push` fans the
freshly-stored ops out via `AppState::publish`. Covered by `http::tests::
push_notifies_tail_subscribers`. Added `axum`+`ws` / `tokio`+`sync` features.

**Deploy — DONE 2026-05-29 (lightweight).** `deploy/vesta-sync.env.sample` +
`docs/sync-bootstrap.md` runbook: trust model, TLS-in-front guidance (WG/Tailscale `/32` or a
Caddy/nginx reverse proxy — the binary speaks plain HTTP), launchd/systemd notes, endpoint
table, backups. No FreeBSD bastille module (personal, not the broker's platform deploy).

**Deferred / next:**
- **memento-core client provider** — the new `SyncProvider` that captures DB row changes as
  ops, encrypts payloads (AEAD under a vault-derived key, domain-separated), pushes/pulls, and
  applies incoming ops with per-row LWW by HLC. Cross-repo (memento), coordinated separately.
- ~~SQLCipher-at-rest for the server DB~~ — **DONE 2026-05-30** (opt-in `VESTA_SYNC_DB_KEY[_FILE]`,
  keys DB+WAL via `PRAGMA key`). CRDT text-merge remains Phase 4.

## Threat model — what the server learns (metadata exposure)

vesta-sync is **content** server-blind: the vault key never reaches the server and
`encrypted_payload` is never decrypted (the server stores it as an opaque blob). But a
server-blind oplog is **not** metadata-blind. An honest-but-curious or compromised server, or
anyone who can read its DB, observes:

| Observable | Where | Leak |
|---|---|---|
| op count / rate, push timing | `ops` rows, `created_at` | activity pattern: when/how much you edit |
| device count + per-op `device_id` | `devices`, `ops.device_id` | how many devices, which authored what |
| `hlc.wall_ms` | `ops` | client wall-clock at edit time (timezone/skew hints) |
| op payload **size** | `ops.payload` length | coarse size of each change (no content) |
| `collection_id` (cleartext) | `ops.collection_id` | which table/collection changed, unless the client HMACs it (a **MAY** today, not enforced) |
| `vault_id` ↔ device pubkeys | `accounts`/`devices` | links a vault to its device key set |

**Not** observable: note/field plaintext, the vault passphrase or key, the enrolment secret
(only `SHA-256` of it is stored), row contents.

Accepted for the personal/single-user scope (the server is the owner's own host, TLS-fronted,
not multi-tenant, not under the residency air-gap). If vesta-sync ever serves others' data,
revisit:
- **`collection_id`** — make HMAC-blinding **mandatory** (keyed by a vault-derived key) so the
  server can't see which collections change. Today it is a client `MAY`.
- **Size** — pad `encrypted_payload` to fixed-size buckets to blunt size fingerprinting.
- **Timing** — op `created_at` + `hlc.wall_ms` reveal activity; batching/jitter on the client
  reduces it. No server change needed (server only timestamps receipt).
- **At-rest** — ✅ **DONE (2026-05-30)**: the server DB is SQLCipher-encryptable at rest. Set
  `VESTA_SYNC_DB_KEY` / `VESTA_SYNC_DB_KEY_FILE` and every connection (DB **and** WAL) is keyed
  via `PRAGMA key`, so a stolen disk/backup yields neither content nor the metadata above. Opt-in
  for back-compat; recommended for any persistent deploy. (`store.rs` `apply_key`, `config.rs`.)

(Source: review finding S9, `docs/review/security.md`.)
