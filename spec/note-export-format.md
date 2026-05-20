<!--
SPDX-License-Identifier: CC-BY-4.0
This specification is licensed under the Creative Commons Attribution 4.0
International License (CC-BY-4.0). https://creativecommons.org/licenses/by/4.0/
You may share and adapt it, including for commercial purposes, provided you
give appropriate credit to the Terrapi terrapi-vault project.
-->

# Memento `.memento-note` Single-Note Export Format — v1

Companion to [`vault-format.md`](./vault-format.md). This document
specifies the on-disk format produced by `terrapi_vault::export_note` and
consumed by `terrapi_vault::import_note`, precisely enough that an
independent implementation can write a compatible reader/writer. It
describes **exactly what the code produces**; if the code and this
document disagree, that is a bug to be reconciled.

## 1. Design: reuse, not new crypto

A `.memento-note` file introduces **no new cryptographic primitive or
dependency**. The note is stored inside an ordinary Memento vault — the
exact `Vault::create` / `Vault::open` path: Argon2id (RFC 9106) over a
fresh random 16-byte salt deriving a 32-byte raw key, fed to SQLCipher
via `PRAGMA key = "x'<hex>'"`, with the salt + KDF parameters recorded in
a plaintext JSON sidecar (see `vault-format.md` §2). The only thing this
format adds is an **outer framing** that packs that vault's two on-disk
artifacts (the SQLCipher database file and its `.meta.json` sidecar) into
one portable file. Consequently the confidentiality/authentication
properties are identical to the audited vault format and are not
re-specified here — see `vault-format.md`.

## 2. Container layout

The file is a fixed header followed by two length-delimited payloads. All
integers are little-endian. Total minimum size = 21 header bytes.

| Offset | Size | Field           | Value                                            |
|--------|------|-----------------|--------------------------------------------------|
| 0      | 8    | `magic`         | ASCII `MNOTE\0\0\0` (`4D 4E 4F 54 45 00 00 00`)  |
| 8      | 1    | `container_ver` | `u8`, MUST be `1`                                |
| 9      | 4    | `meta_len`      | `u32` LE — byte length of `meta_json`            |
| 13     | 8    | `db_len`        | `u64` LE — byte length of `db_bytes`             |
| 21     | `meta_len` | `meta_json` | the vault sidecar JSON, verbatim (`vault-format.md` §2) |
| 21+`meta_len` | `db_len` | `db_bytes` | the SQLCipher database file, verbatim         |

`magic`, `container_ver`, and `meta_json` are **plaintext by design**.
`meta_json` is the same public salt + KDF-params sidecar the vault always
writes in the clear; it contains **no key and no note content**.
`db_bytes` is a complete SQLCipher database; note content exists only as
ciphertext within it and never appears in the clear anywhere in the file.

## 3. Database schema (inside `db_bytes`)

A single table holding exactly one row (`id = 0`):

```sql
CREATE TABLE exported_note (
    id            INTEGER PRIMARY KEY CHECK (id = 0),
    title         TEXT NOT NULL,
    body_markdown TEXT NOT NULL,
    view_mode     TEXT NOT NULL,   -- "live" | "raw"
    created_at    TEXT NOT NULL,   -- RFC 3339
    updated_at    TEXT NOT NULL    -- RFC 3339
);
```

(The vault's own `vault_schema` bookkeeping table from `vault-format.md`
is also present, unchanged.)

## 3a. Attachments (M5) — currently NOT bundled (v1 limitation)

> **Known v1 gap, tracked for the next container_ver bump.**

When the source vault carries M5 image attachments (see
[`vault-format.md`](./vault-format.md) §8), the body of a `.memento-note`
file may contain `![alt](attachment:<id>)` markdown references. The v1
container as specified above bundles **only** the single `exported_note`
row; it does NOT carry the referenced `blobs.bytes` or `attachments`
rows. On import to a vault that does not have those blob ids, the
references become broken-image placeholders and the prose content
remains intact (no panic, no data loss).

The next container version (`container_ver == 2`) is reserved to bundle
the embedded blob bytes inside the same encrypted envelope (one extra
`exported_blobs (sha256, mime, bytes, alt_text)` table inside `db_bytes`)
so the importer can re-resolve attachment ids by SHA-256 content lookup
in the target vault (insert-if-new, reuse-if-existing). This is a
backward-compatible *extension* — a v1 reader sees the magic + version
mismatch and refuses to open, exactly as documented in §7. The framing
itself does not change.

Until then, users sharing notes that contain images SHOULD share the
source `.memento` vault (or a duplicate restricted to the relevant
folder) rather than a single-note file. The UI surfaces this limitation
at export time when the selected note has attachments.

## 4. Scope: secrets are NOT exported

A `.memento-note` carries note *content only*: `title`, `body_markdown`,
`view_mode`, `created_at`, `updated_at`. A note's `Secret` rows are
**deliberately excluded**. Secrets are vault-scoped; bundling them into a
shareable single-note file would widen the blast radius of a leaked
`.memento-note` beyond a user's reasonable expectation of "export this
note". Sharing credentials remains a separate, deliberate action. An
importer MUST NOT expect or require secret data.

## 5. Writing

1. Build a one-note vault via the standard `Vault::create` path with the
   caller's passphrase and Argon2id params.
2. Create the schema in §3 and insert the single row.
3. `Vault::lock` (flushes the WAL into the main DB file; zeroizes the key).
4. Read the sidecar JSON and the SQLCipher DB file.
5. Emit the header (§2) then the two payloads; write atomically
   (temp file + rename).

## 6. Reading

1. Read and verify the 21-byte header: `magic`, `container_ver == 1`.
2. Split out `meta_json` (`meta_len`) and `db_bytes` (`db_len`).
   Truncation or a bad magic/version is a hard "not a valid
   `.memento-note`" error (distinct from a wrong passphrase).
3. Materialize the sidecar + DB and open via the standard `Vault::open`
   path with the supplied passphrase.
4. A wrong passphrase **or any tampering of `db_bytes`** fails the keyed
   read; both surface as the vault's wrong-passphrase outcome (SQLCipher
   cannot distinguish them). Implementations MUST NOT panic.
5. `SELECT … FROM exported_note WHERE id = 0` → the note.

## 7. Versioning

`container_ver` governs framing evolution independently of the inner
vault `version`. A v1 reader MUST accept `container_ver == 1` and reject
anything else. The inner sidecar/DB evolve per `vault-format.md` §6.
