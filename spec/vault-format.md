<!--
SPDX-License-Identifier: CC-BY-4.0
This specification is licensed under the Creative Commons Attribution 4.0
International License (CC-BY-4.0). https://creativecommons.org/licenses/by/4.0/
You may share and adapt it, including for commercial purposes, provided you
give appropriate credit to the Terrapi memento-vault project.
-->

# Memento Vault On-Disk Format — v1

This document specifies the on-disk format produced by `memento-vault`
precisely enough that an independent implementation can write a compatible
reader/writer. It describes **exactly what the code produces**; if the code
and this document disagree, that is a bug to be reconciled.

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

The vault file is a standard **SQLCipher 4** database. `memento-vault`
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

Immediately after creating the encrypted database, `memento-vault`
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
