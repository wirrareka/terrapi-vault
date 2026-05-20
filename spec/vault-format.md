<!--
SPDX-License-Identifier: CC-BY-4.0
This specification is licensed under the Creative Commons Attribution 4.0
International License (CC-BY-4.0). https://creativecommons.org/licenses/by/4.0/
You may share and adapt it, including for commercial purposes, provided you
give appropriate credit to the Terrapi terrapi-vault project.
-->

# Memento Vault On-Disk Format — v1 (doc rev 1.1)

This document specifies the on-disk format produced by `terrapi-vault`
precisely enough that an independent implementation can write a compatible
reader/writer. It describes **exactly what the code produces**; if the code
and this document disagree, that is a bug to be reconciled.

> **Document revision:** 1.1 (2026-05-21). The sidecar integer `version`
> field (§2) stays at **1** — this revision only documents additional
> application-level tables introduced in M5 (see §8) and changes nothing
> about the cryptographic envelope, the sidecar JSON schema, or the keying
> procedure. A v1 reader written against doc rev 1.0 continues to open
> vaults produced by doc rev 1.1 with no changes.

> **Single-note export:** the encrypted `.memento-note` single-file
> container (produced by `export_note` / read by `import_note`) reuses
> this exact crypto path and is specified separately in
> [`note-export-format.md`](./note-export-format.md).

A vault is **two files** that travel together:

| File | Required | Contents |
|------|----------|----------|
| `<name>` (the vault path, e.g. `notes.memento`) | yes | SQLCipher-encrypted SQLite database |
| `<name>.meta.json` | yes | Plaintext JSON sidecar: salt + KDF parameters |

The vault path is user-chosen and has no mandated extension (Memento uses
`.memento`). Losing the sidecar makes the vault **unrecoverable** — the
salt is gone — but the sidecar contains **no secret material**.

## 1. Key derivation

The SQLCipher database key is the raw 32-byte (256-bit) output of
**Argon2id** (Argon2 version 0x13 / 19, i.e. v1.3, per RFC 9106).

| Parameter | Value |
|-----------|-------|
| Algorithm | Argon2id |
| Argon2 version | 0x13 (19) |
| Output length | 32 bytes |
| Salt length | 16 bytes (128-bit), cryptographically random per vault |
| Password input | UTF-8 bytes of the user passphrase, no normalization |
| Associated data / secret | none |

### Default cost parameters (v1)

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `m_cost_kib` | `65536` | Memory cost in KiB (= 64 MiB) |
| `t_cost` | `2` | Iterations / passes |
| `p_cost` | `1` | Parallelism lanes (single-threaded) |

These defaults target ~500 ms derivation on an Apple M-series Mac. The
**actual** parameters used by a given vault are stored in its sidecar
(`kdf_params`) and MUST be read from there when opening — never assume the
defaults. A compatible reader must support arbitrary `(m_cost_kib, t_cost,
p_cost)` triples within Argon2's valid ranges.

The 32-byte Argon2id output is used **directly** as the SQLCipher raw key
(see §3); SQLCipher's own internal PBKDF2 key-derivation is **bypassed**.

## 2. Sidecar file (`<name>.meta.json`)

UTF-8 JSON, pretty-printed, written atomically (temp file + rename). Schema:

```json
{
  "version": 1,
  "kdf": "argon2id",
  "kdf_params": {
    "m_cost_kib": 65536,
    "t_cost": 2,
    "p_cost": 1
  },
  "salt_hex": "0123456789abcdef0123456789abcdef",
  "created_at": "2026-05-18T21:00:00Z"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `version` | unsigned integer | Format version. This document is version `1`. A reader MUST reject `version` greater than the maximum it supports. |
| `kdf` | string | KDF identifier. MUST be `"argon2id"` in v1; readers reject anything else. |
| `kdf_params.m_cost_kib` | u32 | Argon2id memory cost, KiB. |
| `kdf_params.t_cost` | u32 | Argon2id iterations. |
| `kdf_params.p_cost` | u32 | Argon2id parallelism. |
| `salt_hex` | string | Lowercase hex of the 16-byte salt; exactly 32 hex characters. Readers MUST reject non-hex or a length other than 32. |
| `created_at` | string | RFC 3339 / ISO 8601 UTC timestamp, informational only. Not security-relevant; readers MUST NOT depend on it. |

The sidecar path is the vault path with the literal suffix `.meta.json`
appended to the **full filename** (not replacing the extension): a vault at
`notes.memento` has the sidecar `notes.memento.meta.json`.

Unknown additional JSON fields SHOULD be ignored by readers for forward
compatibility. Writers of v1 emit exactly the fields above.

## 3. Encrypted database

The vault file is a standard **SQLCipher 4** database. `terrapi-vault`
links SQLCipher statically via `rusqlite`'s `bundled-sqlcipher` feature and
uses the **SQLCipher 4 defaults**, which are:

| Setting | SQLCipher 4 default (used as-is) |
|---------|----------------------------------|
| Cipher | AES-256 in CBC mode |
| HMAC | HMAC-SHA512 |
| Page size | 4096 bytes |
| KDF iterations (SQLCipher internal) | 256000 (PBKDF2-HMAC-SHA512) |
| HMAC KDF iterations | 2 |
| Plaintext header bytes | 0 |

> The SQLCipher-internal PBKDF2 is **not** the security boundary here: the
> key is supplied as a raw 32-byte blob (see below), so SQLCipher applies
> only its fast HMAC-key split, not the 256k-iteration password PBKDF2.
> The password-stretching work is done entirely by Argon2id (§1).

### Keying

On **every** connection open, before any read or write of the database
file, the implementation issues:

```
PRAGMA key = "x'<64 lowercase hex chars>'";
```

where the 64 hex characters are the 32-byte Argon2id output. The
`x'...'` blob-literal form instructs SQLCipher to use the bytes
**directly** as the raw key (no inner PBKDF2 over a passphrase).

Additional pragmas set on each open (hardening / behavior; not part of the
cryptographic envelope but documented for faithful reproduction):

```
PRAGMA cipher_memory_security = ON;
PRAGMA busy_timeout = 5000;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
```

Because `journal_mode = WAL`, a live/abruptly-closed vault may also have
`-wal` and `-shm` sidecar files; these are standard SQLite WAL artifacts,
not part of this format, and are checkpointed/removed on clean close.

### Key rotation

Rotation derives a new key over a **fresh random 16-byte salt** (same KDF
params) and issues:

```
PRAGMA rekey = "x'<new 64 hex chars>'";
```

SQLCipher re-encrypts every page in place. The sidecar is then rewritten
atomically with the new `salt_hex` (and a new `created_at`). After
rotation the old passphrase no longer derives a working key.

## 4. Schema version table

Immediately after creating the encrypted database, `terrapi-vault`
initializes a bookkeeping table:

```sql
CREATE TABLE IF NOT EXISTS vault_schema (
    id      INTEGER PRIMARY KEY CHECK (id = 0),
    version INTEGER NOT NULL
);
INSERT OR IGNORE INTO vault_schema (id, version) VALUES (0, 1);
```

Row `id = 0` holds the **vault format** schema version (currently `1`).
This is distinct from any application-level migration versioning
(downstream code is expected to use SQLite's own `PRAGMA user_version`
via a migration framework). A reader can detect a Memento vault by the
presence of this table and the `id = 0` row after decryption.

## 5. Open / verify procedure (reference)

1. Locate `<name>.meta.json`; if absent, fail (vault unrecoverable).
2. Parse and validate the sidecar (§2). Reject unknown `version`/`kdf`.
3. Decode `salt_hex` to 16 bytes.
4. Run Argon2id over the UTF-8 passphrase + salt with `kdf_params` → 32-byte key.
5. Open the SQLite file; issue `PRAGMA key = "x'<hex>'"` first.
6. Perform a cheap read, e.g. `SELECT count(*) FROM sqlite_master`.
   - SQLCipher returns `SQLITE_NOTADB` ("file is not a database") when the
     key is wrong — map this to a distinct "wrong passphrase" outcome.
   - Success → the vault is open.

## 6. Versioning of this format

The sidecar `version` field governs format evolution. A v1 reader MUST:

- accept `version == 1`;
- reject `version > 1`;
- treat unknown extra sidecar JSON fields leniently (ignore).

Future versions may change KDF defaults or add fields; the salt/params
stored per-vault always take precedence over any defaults.

## 8. Blobs and attachments (application-level, M5)

> This section documents tables created by downstream application
> migrations (Memento's M5). They are **not** part of the cryptographic
> envelope — they live inside the SQLCipher-encrypted database alongside
> every other application table. A third-party reader that has the
> passphrase can extract every blob with stock `sqlite3`:
>
> ```
> sqlite3 my.memento "SELECT writefile('out.png', bytes) FROM blobs WHERE id = 1;"
> ```
>
> (after first issuing `PRAGMA key = "x'<hex>'"` — see §3.)

Memento stores image attachments **inline as SQLCipher BLOBs**, not as
external files. This keeps the vault self-contained: a single encrypted
file holds every byte of user content, including embedded images.
SQLCipher encrypts at the page level, so blob bytes are subject to the
same AES-256-CBC + HMAC-SHA512 envelope as the rest of the database —
there is no second crypto layer. The in-memory blob bytes never escape
unencrypted to disk: no temp files, no debug logs, no swap-friendly
unencrypted SQLite mirror.

### Schema (M5)

```sql
CREATE TABLE blobs (
    id           INTEGER PRIMARY KEY,
    sha256       TEXT NOT NULL UNIQUE,    -- lowercase hex SHA-256 of `bytes`
    mime         TEXT NOT NULL,           -- "image/png", "image/jpeg", …
    bytes        BLOB NOT NULL,           -- raw payload, content-addressed
    byte_len     INTEGER NOT NULL,        -- denormalised len(bytes)
    created_at   TEXT NOT NULL            -- RFC 3339 / ISO 8601 UTC
);
CREATE INDEX idx_blobs_sha ON blobs(sha256);

CREATE TABLE attachments (
    id           INTEGER PRIMARY KEY,
    note_id      INTEGER NOT NULL REFERENCES notes(id)  ON DELETE CASCADE,
    blob_id      INTEGER NOT NULL REFERENCES blobs(id),
    -- NB: blobs are content-addressed; the blob row is NOT cascade-deleted
    -- when its last attachment is removed. A separate "vacuum orphan blobs"
    -- maintenance op handles that — see "Orphan-blob policy" below.
    position     INTEGER NOT NULL,        -- in-note order (currently unused
                                          -- by render, reserved for future
                                          -- gallery / re-ordering UI)
    alt_text     TEXT,                    -- per-attachment, NOT per-blob
    created_at   TEXT NOT NULL            -- RFC 3339 / ISO 8601 UTC
);
CREATE INDEX idx_attachments_note ON attachments(note_id);
CREATE INDEX idx_attachments_blob ON attachments(blob_id);
```

### Content addressing

`blobs.sha256` is `UNIQUE`. Insertion is upsert-by-hash: if the user pastes
the same image into two notes, **one** row exists in `blobs` and **two**
rows exist in `attachments` pointing at it. This matters for vault size
(a duplicated image costs one blob row, not two) and for a future "find
notes containing this image" query.

`alt_text` lives on `attachments`, not on `blobs`, because the same image
can carry different alt text in different notes ("logo" vs "company
mark" vs ""). The blob is a byte payload; alt is a per-reference label.

`byte_len` is denormalised so `SELECT SUM(byte_len) FROM blobs` is a
single index read — vault-size readouts in the UI status bar do not have
to load any blob bytes.

### Orphan-blob policy

When the last `attachments` row referencing a `blobs.id` is deleted, the
`blobs` row stays. This is deliberate: deleting a note then immediately
undoing the deletion must restore its images, which cannot work if the
delete cascaded into the blob row. A separate maintenance entry point
(`BlobRepo::delete_orphans`) sweeps unreferenced blobs and is invoked
explicitly by the application (e.g. a "Vacuum vault" menu item or a
scheduled compaction). The cost of an orphan is its `byte_len` — surface
this to the user via the same `SUM(byte_len)` readout.

### Markdown reference syntax

In `notes.body_markdown`, an attachment is referenced with **standard
CommonMark image syntax** plus a custom URL scheme:

```
![alt text here](attachment:42)
```

where `42` is `attachments.id` (NOT `blobs.id` — alt text varies per
attachment). A reader that does not understand `attachment:` URLs renders
the line as a plain CommonMark image with a broken link, which is the
correct fallback (no crash, no data loss). A third-party Memento-format
reader extracts the bytes by joining: `attachments.id → attachments.blob_id
→ blobs.bytes`.

### M5 forward-compat

M5 only **adds** the two tables and three indexes; it touches no
pre-existing table, column, trigger, or FTS index. The FTS5
external-content table `notes_fts` indexes `notes(title, body_markdown)`
only and is unaffected. A vault produced by an app version pre-dating M5
migrates forward by a single application-level `PRAGMA user_version`
bump (M5 = previous + 1); no SQLCipher-level re-encryption occurs.

## 7. Raw-key open (alternative unlock)

`Vault::open_with_key(path, key)` opens the database with a caller-supplied
raw 32-byte key, skipping Argon2id. It is the *same* key material a
passphrase would derive (the SQLCipher key); the sidecar is still read so
the salt/params survive for a later `rotate_key`. A wrong key is reported
as a wrong passphrase (`SQLITE_NOTADB`, §5). The on-disk format is
unchanged: no key is ever written to disk by this crate. This API exists
so an application can implement an opt-in OS-keystore / biometric unlock
that stashes the derived key out-of-band; the threat model for that is the
application's responsibility (see the app's `SECURITY.md`). Because
`rotate_key` derives a new key over a fresh salt, any previously stashed
key stops working after rotation — the crypto enforces re-enrollment.

## Changelog

- **doc rev 1.1 (2026-05-21)** — Image attachments (M5). New §8 "Blobs
  and attachments" documenting the `blobs` and `attachments` tables,
  content addressing, the `attachment:<id>` markdown URL scheme, and the
  orphan-blob policy. Forward-compat addition: existing vaults migrate
  forward by a single `PRAGMA user_version` bump; no sidecar/version
  bump and no cryptographic changes. A v1 reader at doc rev 1.0 still
  opens vaults at doc rev 1.1; tables it does not know about are simply
  ignored by SQLite.
- **doc rev 1.0** — initial specification of the vault format v1.
