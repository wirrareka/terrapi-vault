<!--
SPDX-License-Identifier: CC-BY-4.0
This specification is licensed under the Creative Commons Attribution 4.0
International License (CC-BY-4.0). https://creativecommons.org/licenses/by/4.0/
You may share and adapt it, including for commercial purposes, provided you
give appropriate credit to the Terrapi terrapi-vault project.
-->

# Memento Vault On-Disk Format — v1 + v2 (doc rev 1.7)

This document specifies the on-disk format produced by `terrapi-vault`
precisely enough that an independent implementation can write a compatible
reader/writer. It describes **exactly what the code produces**; if the code
and this document disagree, that is a bug to be reconciled.

> **Document revision:** 1.7 (2026-06-06) — **introduces sidecar format
> `version: 2`**, the **DEK key-slot** model that backs recovery codes. The
> database is now keyed by a random data-encryption key (DEK) wrapped under
> one or more credential slots (passphrase + optional recovery code) instead
> of the passphrase deriving the key directly. v1 vaults are **lazily migrated
> to v2 on the next passphrase unlock**. v1 (§1–§3) remains specified for
> reading legacy/in-flight vaults; the v2 envelope, slots, recovery code, and
> migration are specified in **§13**. The passphrase-change procedure changes
> meaning under v2 (re-wrap a slot, not rekey the DB) — see §13.6.
>
> **Earlier:** Document revision 1.6 (2026-05-24). The sidecar integer `version`
> field (§2) stays at **1**. This revision adds the **M9 `succession_plans`
> table** (§12) — a single additive, new-table application-level migration
> (`user_version` 8 → 9), following the §6b checklist; the table stores only
> a recipient label, a folder id, a timestamp, and optional notes — never a
> passphrase, key, or PII. Doc rev 1.5 added the M8 `secrets.updated_at`
> column (§11); doc rev 1.4 added the M7 `audit_log` table (§10); doc rev 1.3
> added the §6a/§6b migration-safety contract (no schema change); doc rev 1.2
> added the M6 tables (§9); doc rev 1.1 added M5 (§8); none changed the
> cryptographic envelope, the sidecar JSON schema, or the keying procedure. A
> v1 reader written against doc rev 1.0 continues to open vaults produced by
> doc rev 1.6 with no changes — additional tables and columns it does not
> know about (including `audit_log`, `secrets.updated_at`, and
> `succession_plans`) are simply ignored.

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
p_cost)` triples within Argon2's valid ranges, but **MUST reject params above
the sane upper bounds before deriving** — the sidecar is unauthenticated, so an
unbounded `m_cost_kib` would otherwise let a tampered sidecar pin a multi-TiB
allocation on open. This reader rejects `m_cost_kib > 4 GiB`, `t_cost > 16`,
`p_cost > 16` (`Error::MetaInvalid`). The sidecar JSON is parsed with
**unknown fields rejected** (a security sidecar must never silently drop a
field it doesn't understand). Opening also **fails closed** (`Error::Encryption
Unavailable`) if the linked SQLite is not SQLCipher, so a degraded build can
never store the database in the clear.

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

## 6a. Migration safety and recovery (application-level)

This section documents how the **application layer** (Memento) evolves the
app-level schema tracked by `PRAGMA user_version` (§4) — distinct from the
format-level `vault_schema` row 0. Third-party readers are unaffected: all
application migrations are additive (§8/§9 precedent).

### Open-time guards

On every open, before and after applying pending migrations, Memento
enforces two guards and refuses to open on either:

- **Future format.** If `vault_schema` row 0 (the format-level version) is
  **greater** than the value the running binary understands
  (`SUPPORTED_FORMAT_VERSION`, currently `1`), the open is refused. This is
  the application-side enforcement of the §6 reader rule: never read a
  format from the future.
- **Newer app schema.** If `PRAGMA user_version` is **greater** than the
  highest migration the binary knows (`current_version`), a newer Memento
  already upgraded this vault. The open is refused rather than silently
  proceeding, since an older binary cannot reason about newer schema.

### Backup-before-migrate

Before applying **any** pending migration (i.e. when
`user_version < current_version`), Memento copies the database file **and
its `.meta.json` sidecar** to recovery backups next to the vault:

```
<name>.pre-migrate-v{from}-to-v{to}.bak
<name>.meta.json.pre-migrate-v{from}-to-v{to}.bak
```

where `{from}` is the pre-migration `user_version` and `{to}` is
`current_version`. Properties:

- **Skipped when nothing is pending** — the common open path performs no
  filesystem writes (zero cost).
- **Skipped for a freshly created vault** (`from == 0`): a brand-new vault
  has no pre-existing user data to protect.
- The `.bak` files are **left in place** after a successful migration as a
  recovery artifact. Pruning stale backups is future work; a recovery
  artifact is never deleted automatically.

### Rollback stance — forward-only

Production is **forward-only**. Migrations are applied with `to_latest` and
the application **never auto-downgrades user data** with a programmatic
`to_version`. `down` scripts exist in the codebase **for tests only** (to
construct an older schema and assert the forward migration) and are not
wired into any open path.

If a migration must be undone on real data, the supported recovery path is
to **restore the pre-migration `.bak`** described above — not a
programmatic downgrade.

## 6b. Spec-doc process for a new application migration (Mn)

Every new application-level migration `Mn` MUST update this spec in
lockstep. Checklist (codifies the M5/M6 precedent):

1. **Additive only.** No destructive change to v1 reader compatibility — a
   reader unaware of the new table/column ignores it (SQLite skips unknown
   tables; new columns are nullable or carry a default).
2. **Bump `user_version` by exactly 1** (append one entry to the migration
   registry; advance `current_version` by 1).
3. **Sidecar `version` stays `1`.** It changes **only** if the cryptographic
   envelope or sidecar JSON schema changes — which is a true format v2, a
   separate and much heavier process (and would bump
   `SUPPORTED_FORMAT_VERSION`).
4. **Add a spec section §N** documenting the new table/column, its
   semantics, and a forward-compat note.
5. **Add a "legacy open → migrate → assert" test** mirroring the existing
   migration tests: build a vault at the previous schema, run the full
   migration, assert `user_version` advanced and the new schema works.
6. **Note third-party-reader impact** (normally: none — additive table the
   reader ignores).

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

## 9. Per-note version history (application-level, M6)

Migration **M6** introduces a single additional table that stores
historical snapshots of note text. The cryptographic envelope, the
sidecar, the keying procedure, and the FTS5 full-text index are
unaffected: M6 is a purely-additive schema change, exactly like M5.

### Schema (M6)

```sql
CREATE TABLE note_versions (
    id            INTEGER PRIMARY KEY,
    note_id       INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
    version       INTEGER NOT NULL,
    title         TEXT    NOT NULL,
    body_markdown TEXT    NOT NULL,
    icon          TEXT,
    folder_id     INTEGER,
    created_at    TEXT    NOT NULL
);
CREATE INDEX idx_note_versions_note ON note_versions(note_id, created_at DESC);
```

Each row is a snapshot of `(title, body_markdown, icon, folder_id,
version)` *as it stood immediately before* a successful
`NoteRepo::update` overwrote the live `notes` row. The current `notes`
row therefore always carries the latest content + the latest `version`;
`note_versions` rows are monotonically-older versions of the same note.

### Write-hook contract

The writer (Memento's `NoteRepo::update`) MUST, inside a single SQL
transaction:

1. Read the current `(title, body_markdown, icon, folder_id, version)`
   from `notes` for the target id.
2. If the new content is **byte-identical** to the current
   `(title, body_markdown, icon, folder_id)`, return the unchanged
   version without inserting a snapshot and without bumping `version`.
   This prevents stray autosaves-with-no-edits from polluting history.
3. Otherwise INSERT one row into `note_versions` capturing the OLD
   state, then DELETE the oldest rows beyond the per-note cap
   (`v1` = **20** rows), then run the existing
   `UPDATE notes … version = version + 1 … RETURNING version`.
4. COMMIT.

A failing UPDATE rolls the snapshot back too — history can never grow
ahead of, or behind, the live row.

### Cap policy

v1 hardcodes a per-note cap of **20** versions. After each insert the
writer prunes rows for that `note_id` beyond the most recent 20 (by
`created_at DESC, id DESC`). The cap is intentionally configurable
later but not for v1.

### Cascade + folder semantics

`note_versions.note_id` is `ON DELETE CASCADE`: deleting a note also
drops its version rows. (Restoring a deleted note is out of scope for
v1; it would require a separate tombstone table.)

`note_versions.folder_id` is **deliberately not** a foreign key: the
folder may itself be deleted later, and the recorded id stays as an
informational breadcrumb. A reader rendering a snapshot whose
`folder_id` no longer resolves SHOULD fall back to a sentinel label
(Memento renders "(deleted folder)").

### Text-only history (v1 limitation)

v1 stores the snapshot of the note's TEXT (title + body markdown) plus
the `icon` and `folder_id`. It deliberately does **not** snapshot:

* **`note_tags`** — tag attachments change independently of note
  content; capturing them on every text edit would be noise.
* **`attachments`** (M5) — image references are tracked in a separate
  table. Restoring an old version shows the old text against the
  CURRENT attachment set. Memento's UI surfaces this as "text-only
  history" so the user is not surprised by stale image references.

### Restore is reversible

A restore is implemented as `NoteRepo::update` with the snapshot's
content. Because the write hook itself snapshots the live state first,
the just-overwritten "live" content becomes the newest history entry,
and the restore is undoable by restoring that entry in turn.

### Open format — third-party readers

Because the table lives in the same SQLCipher container as the rest of
the vault, **any** stock SQLite tool with the correct key can extract a
note's history:

```bash
sqlite3 my.vault \
  "SELECT version, body_markdown FROM note_versions \
   WHERE note_id = ? ORDER BY created_at DESC"
```

This is the open-format promise: history is data, not a proprietary
sidecar. A reader unaware of `note_versions` simply ignores the table.

### M6 forward-compat

M6 only **adds** one table and one index; it touches no pre-existing
table, column, trigger, or FTS index. `notes_fts` indexes
`notes(title, body_markdown)` only — snapshot rows are NOT full-text
indexed (search results always reflect the live note, not its history),
which is the intended behaviour. A vault produced by an app version
pre-dating M6 migrates forward by a single application-level
`PRAGMA user_version` bump (M6 = previous + 1); no SQLCipher-level
re-encryption occurs.

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

## 10. Audit log (application-level, M7)

An **append-only** record of *what happened and when* across the vault.
Distinct from the per-note **version history** (§9, `note_versions`):
version history answers "restore this note to how it was" (restorable
content snapshots, capped at 20/note); the audit log answers "what
happened and when" (one short row per mutating action, every entity type,
never restored). Diff text for a `note.edit` is **derived on demand** from
`note_versions` via the optional `version_id` link — it is never stored
in the audit log.

### Schema (M7)

```sql
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    ts          TEXT    NOT NULL,           -- RFC3339 UTC
    actor       TEXT    NOT NULL DEFAULT 'local',  -- 'local' | 'sync'
    action      TEXT    NOT NULL,           -- e.g. note.create / secret.update
    entity_type TEXT    NOT NULL,           -- 'note' | 'folder' | 'secret' | 'tag' | …
    entity_id   INTEGER,                    -- affected row; NOT a foreign key
    summary     TEXT    NOT NULL,           -- human string; NO secret values
    version_id  INTEGER                     -- optional link to note_versions.id
);
CREATE INDEX idx_audit_ts ON audit_log(ts DESC);
```

### Action verbs

`note.create` / `note.edit` / `note.delete`;
`folder.create` / `folder.rename` / `folder.move` / `folder.delete`;
`secret.create` / `secret.update` / `secret.delete`;
`tag.create` / `tag.delete`; and (reserved for later callers)
`key.rotate`, `sync.pull` / `sync.push`, `export.plaintext`.

### Write contract

Each row is written by the repository layer **inside the same SQL
transaction** as the mutation it records, so a failed mutation rolls the
audit row back too — the log can never contain an action that did not
commit, nor miss one that did. `note.edit` rows carry the `version_id` of
the `note_versions` snapshot captured by the §9 write-hook, so the UI can
derive a line diff between that snapshot and the next.

### No secret values — hard rule

For `secret.*` actions, `summary` records the **key name and the action
only** (e.g. `secret AWS_KEY updated`), **never the value**. The audit
table is inside the SQLCipher-encrypted container, but it is the most
likely artifact a user screenshots or exports, so values must never reach
it. The application enforces this at every `secret.*` call site (the value
is bound only to the mutation's own parameter, never interpolated into the
summary) and covers it with a test asserting the value string is absent.

### Retention

The log is bounded: after each insert the application keeps at most
**N = 10 000** rows and prunes any row older than **365 days** (mirrors
the §9 cap-trim). v1 hardcodes these; an enable/disable toggle and a
user-tunable cap are deferred to application configuration.

### `entity_id` / `version_id` are not foreign keys

Like `note_versions.folder_id` (§9), neither column is a foreign key: the
referenced row may already be deleted (the recorded action may itself be a
delete), and the audit row must outlive it. `version_id` additionally
points at a `note_versions` row that cascades away with its note, while
the audit entry persists.

### M7 forward-compat

M7 only **adds** one table and one index; it touches no pre-existing
table, column, trigger, or FTS index (`notes_fts` indexes
`notes(title, body_markdown)` only — audit rows are not full-text
indexed). A vault produced by an app version pre-dating M7 migrates
forward by a single application-level `PRAGMA user_version` bump
(M7 = previous + 1); the sidecar `version` stays `1` and no
SQLCipher-level re-encryption occurs. A third-party reader unaware of
`audit_log` simply ignores the table.

## 11. Secret last-modified timestamp (application-level, M8)

M8 adds a single nullable column to the existing `secrets` table:

```sql
ALTER TABLE secrets ADD COLUMN updated_at TEXT;  -- RFC3339 UTC, nullable
```

`secrets.updated_at` records the RFC3339-UTC time a secret row was last
created or updated, surfaced unobtrusively in the secrets panel
("Edited 2m ago").

### Nullable, no default — why

SQLite `ALTER TABLE … ADD COLUMN` cannot add a `NOT NULL` column without a
**constant** default and cannot use a **non-constant** default (a clock
expression). The column is therefore added **NULLABLE**:

- **Pre-M8 rows keep `NULL`**, meaning "last-modified time unknown". The app
  renders `NULL` as *nothing* — never a literal "unknown" or a fabricated
  time.
- **Every new write sets it.** Memento's `SecretRepo::create` and
  `SecretRepo::update` write `Utc::now().to_rfc3339()`, the same convention
  `notes.created_at` / `notes.updated_at` use.

### M8 forward-compat

M8 only **adds** one nullable column to `secrets`; it touches no other
table, no trigger, and no FTS index (`notes_fts` indexes
`notes(title, body_markdown)` only — secrets are never full-text indexed).
A vault produced by an app version pre-dating M8 migrates forward by a
single application-level `PRAGMA user_version` bump (M8 = previous + 1, i.e.
`user_version` 7 → 8); the sidecar `version` stays `1` and no SQLCipher-level
re-encryption occurs. A third-party reader unaware of `updated_at` simply
ignores the column (or reads it as an optional text field) — `SELECT *` and
named-column reads both remain valid.

## 12. Succession-plan bookkeeping (application-level, M9)

M9 adds one table recording **which folder subtrees have had succession
bundles produced, for which recipient labels, and when** — the deferred
§4c of the succession feature (see `docs/proposals/G-major-features.md` §4).
It lets the owner-side UI show "Last exported to <recipient> on <date>"
instead of relying on memory.

```sql
CREATE TABLE succession_plans (
    id            INTEGER PRIMARY KEY,
    folder_id     INTEGER,              -- subtree root, NOT a foreign key
    recipient     TEXT NOT NULL,        -- owner-chosen LABEL only, no PII
    last_exported TEXT,                 -- RFC3339 UTC, when last produced
    notes         TEXT                  -- optional owner freeform text
);
CREATE INDEX        idx_succession_plans_folder           ON succession_plans(folder_id);
CREATE UNIQUE INDEX idx_succession_plans_folder_recipient ON succession_plans(folder_id, recipient);
```

### Critical security rule — no secrets, no keys, no PII

This table stores **NO** generated bundle passphrases, **NO** key material,
and **NO** recipient contact PII. The only recipient-derived datum is the
freeform `recipient` LABEL the owner types ("Lawyer", "Alice"). The generated
bundle passphrase is returned to the owner **once** in memory
(`GeneratedBundle`, zeroizing) and is never written to any vault. `notes` is
optional owner-facing freeform text and must likewise never carry a secret
value. This mirrors the audit-log rule (§10): the most likely artifact a user
screenshots or exports must never contain a secret.

### Keying and the upsert contract

A plan is keyed on `(folder_id, recipient)` (enforced by the UNIQUE index).
Producing a bundle for the same folder and the same recipient label again
**updates** the existing row's `last_exported` rather than inserting a
duplicate. The write is performed by `SuccessionPlanRepo::upsert` in the same
master-vault flow that records the `succession.export` audit row, so a
recorded plan always corresponds to a produced bundle.

`folder_id` is intentionally **NOT a foreign key**: the subtree root may be
moved or deleted after a bundle was produced; the recorded id is
informational (same rationale as `note_versions.folder_id`, §9, and
`audit_log.entity_id`, §10). It is left `NULL`able for the same reason.

### M9 forward-compat

M9 only **adds** one table and two indexes; it touches no existing table, no
trigger, and no FTS index (`notes_fts` indexes `notes(title, body_markdown)`
only). A vault produced by an app version pre-dating M9 migrates forward by a
single application-level `PRAGMA user_version` bump (M9 = previous + 1, i.e.
`user_version` 8 → 9); the sidecar `version` stays `1` and no SQLCipher-level
re-encryption occurs. A third-party reader unaware of `succession_plans`
simply ignores the table — `SELECT *` and named-column reads on other tables
remain valid.

## 13. Recovery codes & the v2 DEK key-slot format

Sidecar `version: 2` replaces the v1 "passphrase derives the database key
directly" model with a **data-encryption key (DEK) envelope**. This is what
makes a vault recoverable from a forgotten passphrase via a separate,
high-entropy **recovery code**, without weakening the zero-knowledge property:
there is still no master backdoor; recovery requires a secret the user holds.

### 13.1 Model

- A **DEK** is 32 random bytes generated at vault creation (or at v1→v2
  migration). It is the actual SQLCipher key (`PRAGMA key = x'<dek hex>'`,
  raw-key path, no inner KDF — identical to §3 keying, just with a random key
  instead of a passphrase-derived one). The DEK is **stable for the life of
  the vault**.
- Each **credential** (the passphrase, and optionally a recovery code) has a
  **key slot** that wraps the *same* DEK. Unlocking = derive the slot key from
  the credential → AEAD-open the slot → recover the DEK → open the database
  with it. Changing one credential re-wraps only its slot; the DEK and every
  other slot are untouched (this is why a recovery code survives a passphrase
  change).

### 13.2 Sidecar schema (v2)

```jsonc
{
  "version": 2,
  "kdf": "argon2id",
  "created_at": "2026-06-06T12:00:00Z",
  "slots": {
    "password": {
      "kdf_params": { "m_cost_kib": 65536, "t_cost": 2, "p_cost": 1 },
      "salt_hex": "<32 hex chars = 16-byte Argon2id salt>",
      "wrap": {
        "alg": "xchacha20poly1305",
        "nonce_hex": "<48 hex chars = 24-byte XChaCha20 nonce>",
        "ct_hex": "<96 hex chars = 32-byte DEK + 16-byte Poly1305 tag, sealed>"
      }
    },
    "recovery": { /* same shape; present iff a recovery code is enrolled */ }
  }
}
```

`deny_unknown_fields` applies to every object (a stray key is a hard error).
The reader **dispatches on the integer `version`** first: `1` parses the v1
schema (§2), `2` parses this schema, anything higher is rejected
(`UnsupportedFormat`). The sidecar still contains **no secret material** — the
DEK is only present as authenticated ciphertext inside each `wrap`.

### 13.3 Slot key derivation and DEK wrap

- **Slot key** = `Argon2id(credential_bytes, slot.salt, slot.kdf_params)` →
  32 bytes (the same `derive_key` used in §1; the passphrase slot feeds UTF-8
  bytes, the recovery slot feeds the code's raw 20 bytes).
- **Wrap** = `XChaCha20-Poly1305` seal of the 32-byte DEK under the slot key,
  with a fresh random 24-byte nonce per seal. **AAD =
  `"terrapi-vault/dek-slot/v2/" + slot_name`** (`slot_name` ∈ {`password`,
  `recovery`}). Binding the slot name into the AAD means a blob lifted from
  one slot fails authentication in another — a wrong-slot ciphertext cannot be
  replayed.
- A wrong credential is an AEAD **authentication failure**, surfaced as
  `WrongPassphrase` / `WrongRecoveryCode`. A structurally malformed slot
  (unknown `alg`, bad hex, wrong nonce/DEK length) is `KeySlotCorrupt` and is
  distinct from a wrong credential.

### 13.4 Recovery code format

- **160 bits** (20 bytes) of CSPRNG entropy.
- Display form: **Crockford Base32** (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`,
  no I/L/O/U), 32 payload characters shown as eight 4-character groups, plus a
  trailing 4-character **checksum** group:
  `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-CCCC`.
- The checksum is **CRC-16/CCITT-FALSE** of the 20 payload bytes, Base32-encoded.
  It is a **typo guard only** (lets the UI reject a mistyped code before
  ~1 s of Argon2id); the real integrity check is the slot's Poly1305 tag.
- Parsing is case-insensitive, ignores dashes/whitespace, and folds Crockford
  look-alikes (`O→0`, `I/L→1`). The raw 20 bytes (not the formatted string)
  are fed to the slot KDF, so display formatting is never load-bearing.

### 13.5 Unlock procedure (v2)

1. Read + dispatch the sidecar; for `version: 2` take `slots.password`.
2. `slot_key = Argon2id(passphrase, password.salt, password.kdf_params)`.
3. AEAD-open `password.wrap` (AAD = `…/password`). Failure → `WrongPassphrase`.
4. `PRAGMA key = x'<dek hex>'`; verify with a cheap read (§5).

Recovery unlock is identical with `slots.recovery` and AAD `…/recovery`
(absent slot → `NoRecoverySlot`; auth failure → `WrongRecoveryCode`).

### 13.6 Passphrase change, reset, and recovery enrollment

- **Passphrase change** (knowing the old one): verify by unwrapping the DEK
  from the current `password` slot, then re-seal the *same* DEK under a new
  `password` slot (fresh salt). The sidecar is rewritten atomically
  (temp-then-rename). **No `PRAGMA rekey`** — the database is untouched, so it
  is openable throughout and a crash before the rename simply leaves the old
  passphrase working. **Any enrolled `recovery` slot is preserved.**
- **Reset via recovery** (forgot passphrase): unwrap the DEK with the recovery
  code, then set a new `password` slot with no old-passphrase check
  (authorization came from the recovery code).
- **Enroll / remove recovery**: derive a recovery slot key from a freshly
  generated code, seal the DEK, add the `recovery` slot (atomic write);
  removal drops the slot. Enrolling runs Argon2id and is split into a cheap
  snapshot → off-thread derivation → cheap commit, like rotation.

### 13.7 Lazy v1 → v2 migration

A v1 vault migrates on its **next passphrase unlock**:

1. Open the database with the v1 salt-derived key (§1).
2. Generate a random DEK; build a v2 `password` slot wrapping it (preserving
   the vault's Argon2id cost params).
3. **Stage** the v2 sidecar at `<name>.meta.json.rekeying`.
4. `PRAGMA rekey` the database from the v1 key to the DEK.
5. Atomically rename the staged sidecar over the v1 one.

Crash-safety reuses the §169 staged-sidecar protocol: a crash after the rekey
but before the rename leaves the database keyed by the DEK with a committed v1
sidecar (whose key no longer opens it) plus the staged v2 sidecar. The next
unlock detects this — the v1 key fails, the staged v2 slot unwraps the DEK and
opens the database — and finalizes the rename. Raw-key (`open_with_key`,
biometric §7) opens do **not** migrate (no passphrase is available to build the
password slot); such a vault migrates on its next passphrase unlock.

### 13.8 Security notes (for the audit)

- **DEK stability is a deliberate trade-off.** Because a passphrase change only
  re-wraps the `password` slot, it does **not** invalidate the DEK — so a
  recovery code (and any raw key stashed for biometric unlock, §7) keeps
  working across a passphrase change. The v1 guarantee that "rotating the
  passphrase invalidates the old derived key" no longer holds. Re-gating
  biometric unlock on a passphrase change is therefore an **application UI
  policy** (Memento clears the stashed key on change), not a cryptographic
  consequence.
- Each slot has an **independent salt** and a **fresh random nonce per seal**;
  the DEK is held in zeroizing memory and never logged or persisted in the
  clear. The recovery code is zeroized after the slot key is derived.
- Losing the sidecar is still fatal (the only copies of the DEK live in its
  slots). The recovery code is a *credential*, not a sidecar backup: it cannot
  reconstruct a lost sidecar.

## Changelog

- **doc rev 1.7 (2026-06-06)** — Recovery codes & the v2 DEK key-slot format.
  New §13 specifying sidecar `version: 2`: the database is keyed by a random,
  life-stable **DEK** wrapped under per-credential **key slots** (passphrase +
  optional recovery code) via Argon2id slot keys + XChaCha20-Poly1305 with
  slot-name-bound AAD; the 160-bit Crockford-Base32 recovery code format with a
  CRC-16 typo-guard checksum; the v2 unlock / passphrase-change (slot re-wrap,
  no DB rekey) / reset-via-recovery / enroll procedures; and the **crash-safe
  lazy v1→v2 migration on next passphrase unlock**. Documents the deliberate
  DEK-stability trade-off (a passphrase change no longer invalidates the DEK;
  biometric re-gating is a UI policy). v1 (§1–§3) remains specified for legacy
  and in-flight vaults. A v1 reader cannot open a v2 sidecar (version
  dispatch); v2 is the format this build writes for new and migrated vaults.

- **doc rev 1.6 (2026-05-24)** — Succession-plan bookkeeping (M9). New §12
  documenting the `succession_plans` table (which folder subtrees had bundles
  produced, for which recipient labels, and when), the `(folder_id,
  recipient)` upsert keying, and the **hard rule that the table stores no
  passphrases, no keys, and no PII — only a label, a folder id, an RFC3339
  timestamp, and optional owner notes**. `folder_id` is deliberately not a
  foreign key. Application-level `PRAGMA user_version` bump 8 → 9 following
  the §6b checklist; the sidecar `version` stays `1` and no cryptographic
  changes. A reader at any earlier doc rev still opens vaults at doc rev 1.6
  unchanged — the new table is ignored.

- **doc rev 1.5 (2026-05-24)** — Secret last-modified (M8). New §11
  documenting the additive, **nullable** `secrets.updated_at` column
  (RFC3339 UTC), why it is nullable (SQLite `ADD COLUMN` cannot take a
  non-constant default), the NULL = "unknown" semantics for pre-M8 rows, and
  that every `create`/`update` stamps it. Application-level `PRAGMA
  user_version` bump 7 → 8 following the §6b checklist; the sidecar
  `version` stays `1` and no cryptographic changes. A reader at any earlier
  doc rev still opens vaults at doc rev 1.5 unchanged — the new column is
  ignored or read as an optional field.

- **doc rev 1.4 (2026-05-23)** — Audit log (M7). New §10 "Audit log"
  documenting the `audit_log` table (append-only record of mutating
  actions across every entity type), the action-verb set, the
  same-transaction write contract, the `version_id` link to
  `note_versions` for on-demand `note.edit` diffs, the retention bound
  (≤ 10 000 rows / ≤ 365 days), and the **hard rule that `summary` never
  contains a secret value** (only the key name + action). `entity_id`
  and `version_id` are deliberately not foreign keys. Forward-compat
  addition: existing vaults migrate forward by a single application-level
  `PRAGMA user_version` bump (M7 = previous + 1); the sidecar `version`
  stays 1 and no cryptographic changes occur. A reader at any earlier doc
  rev still opens vaults at doc rev 1.4 unchanged — the `audit_log` table
  it does not know about is simply ignored.
- **doc rev 1.3 (2026-05-23)** — Migration-framework hardening. No schema
  change. New §6a "Migration safety and recovery" (open-time guards
  rejecting a future format-level version or a newer app-level
  `user_version`; backup-before-migrate writing
  `<name>.pre-migrate-v{from}-to-v{to}.bak` plus the sidecar `.bak` before
  any pending migration, skipped when nothing is pending and for a
  freshly created vault; forward-only rollback stance — recovery is
  restore-from-`.bak`, never an auto-downgrade, `down` scripts are
  test-only). New §6b "Spec-doc process for a new application migration"
  codifying the additive-only / single-`user_version`-bump / sidecar-stays-1
  / add-spec-§N / add-legacy-open-migrate-assert-test / note-reader-impact
  checklist. A reader at any earlier doc rev still opens vaults at doc rev
  1.3 unchanged.
- **doc rev 1.2 (2026-05-21)** — Per-note version history (M6). New §9
  "Per-note version history" documenting the `note_versions` table, the
  write-hook contract (read-old → insert-snapshot → prune-to-cap →
  update-current, all in one transaction; no-op skip on byte-identical
  edits), the 20-version-per-note cap, the cascade rule, and the
  "text-only history" v1 limitation (tags and attachments are
  intentionally not snapshotted). Forward-compat addition: existing
  vaults migrate forward by a single `PRAGMA user_version` bump; no
  sidecar/version bump and no cryptographic changes. A reader at any
  earlier doc rev still opens vaults at doc rev 1.2 unchanged — the
  table it does not know about is simply ignored.
- **doc rev 1.1 (2026-05-21)** — Image attachments (M5). New §8 "Blobs
  and attachments" documenting the `blobs` and `attachments` tables,
  content addressing, the `attachment:<id>` markdown URL scheme, and the
  orphan-blob policy. Forward-compat addition: existing vaults migrate
  forward by a single `PRAGMA user_version` bump; no sidecar/version
  bump and no cryptographic changes. A v1 reader at doc rev 1.0 still
  opens vaults at doc rev 1.1; tables it does not know about are simply
  ignored by SQLite.
- **doc rev 1.0** — initial specification of the vault format v1.
