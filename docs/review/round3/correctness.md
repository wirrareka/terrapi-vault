# terrapi-vault root library — correctness & edge-case review (round 3)

Scope: `src/` only (lib crate pinned by memento/probe). MSRV 1.83,
dependency-neutral. Files: error.rs, kdf.rs, lib.rs, meta.rs, vault.rs,
note_export.rs, tests/lifecycle.rs.

Overall the crate is in good shape: no `unsafe`, no `unwrap`/`expect`/`panic`
in non-test paths, all slice indexing into the note-export header is on a
fixed-size `[u8; HEADER_LEN]` buffer (bounds-checked by `read_exact`), and the
two attacker-controlled length fields are both range-checked before use. The
findings below are real but mostly availability/robustness, not memory-safety.

---

## High

### H1 — `import_note` allocates attacker-declared lengths before reading: memory-exhaustion DoS
`note_export.rs:246` and `:249`.

`read_container` reads `meta_len` (u32) and `db_len` (u64, narrowed to usize)
straight from the plaintext header and then does:

```rust
let mut meta_json = vec![0u8; meta_len];   // up to ~4 GiB
let mut db_bytes  = vec![0u8; db_len];     // up to usize::MAX
```

A 21-byte hostile `.memento-note` whose header declares `db_len = 0xFFFF_FFFF_FFFF`
forces a multi-terabyte allocation (abort / OOM-kill) **before** a single body
byte is read. `read_exact` would ultimately fail on the short file, but the
allocation happens first. The header validates the *magic* and *version* but not
that the declared lengths are consistent with the actual file size.

This is the one input-driven crash on a malicious file. memento/probe import
`.memento-note` files received from other users, so it is reachable.

Fix: cap the declared sizes and/or compare against the real file length before
allocating. Stat the file once, then reject any header whose
`HEADER_LEN + meta_len + db_len > file_len` (and impose an absolute ceiling,
e.g. a few hundred MiB, so a *correctly-sized* 100 GiB junk file is still
rejected up front). Prefer reading with a bounded reader or
`read_to_end`-into-`Vec::with_capacity(min(declared, cap))` over pre-sizing to
the declared length. Add a unit test with a forged oversized `db_len`.

---

## Medium

### M1 — `rotate_key` is not crash-consistent: rekey succeeds, sidecar write fails → bricked vault
`vault.rs:194-200`.

Order is: `PRAGMA rekey` (mutates the DB key in place), **then**
`VaultMeta::new(&new_salt,…).write()`. If the process dies, or the meta write
fails, *after* rekey but *before* the new sidecar lands, the on-disk DB is now
encrypted under `new_key` while the sidecar still holds the **old** salt. Result:
`open` derives the old key → `WrongPassphrase`; the new passphrase also fails
because the stored salt no longer matches. The vault is unrecoverable with
either passphrase.

`VaultMeta::write` is itself atomic (temp+rename, meta.rs:117-119), so the
window is "rekey done, rename not yet done" — small but real, and a returned
`Io`/`Json` error from `write()` leaves `self.key` un-updated (vault.rs:200
never runs) so even the live in-memory handle is now wrong.

Fix options, best first:
1. Write the *new* sidecar to a temp name **before** rekey; rekey; then atomic-
   rename temp→meta. On open, if the primary salt fails, try a `*.meta.json.new`
   recovery sidecar. (A documented recovery path is the only true fix for the
   power-cut case.)
2. At minimum, reorder so the in-memory `self.key = new_key` update and a clear
   doc comment acknowledge the window, and on a `write()` failure attempt to
   rekey *back* to the old key before returning, so a failed rotation is a no-op
   rather than a brick.

This is the same class of bug as create (H/M below) but worse because there is
existing data to lose.

### M2 — `create` is not crash-consistent: orphan DB after a crash auto-deletes the next vault attempt's data silently
`vault.rs:71-74`, `:354-369`.

`create` writes the DB (`open_keyed` + `init_schema`) then the sidecar. A crash
between them leaves an orphan DB with no sidecar. `prepare_paths_for_create`
"recovers" by **silently `remove_file`** the orphan on the next `create`
(vault.rs:359-366). For `create` of a brand-new vault that is correct, but the
recovery branch cannot distinguish "leftover from a half-finished create" from
"a real DB whose sidecar the user accidentally deleted/lost" — in the latter
case it deletes recoverable-by-backup ciphertext without warning. Acceptable for
the create contract, but worth a doc note and ideally a dedicated
`recover`/`repair` entry point rather than a side effect of `create`.

Also: `prepare_paths_for_create` uses `Path::exists()` (vault.rs:355-356), which
follows symlinks and races TOCTOU against the subsequent `Connection::open`.
Low severity (local single-user file), but `remove_file` on a symlink target is
a footgun; consider `symlink_metadata`.

### M3 — WAL/SHM sidecar files are ignored by create/lock/note-export
`vault.rs:292` sets `journal_mode=WAL`, producing `-wal` and `-shm` companions.

- `prepare_paths_for_create` only checks/removes `vault_path` and `meta_path`,
  never `vault_path-wal` / `-shm` (vault.rs:354). A stale `-wal` from a previous
  vault that shared the path can be replayed into the freshly-created DB.
- `export_note` reads only `db_path` after `vault.lock()` (note_export.rs:144-147).
  `lock()` calls `conn.close()` which checkpoints the WAL back into the main
  file, so in the happy path the WAL is empty — but `lock()` **ignores the close
  error** (vault.rs:268 `let _ = self.conn.close()`). If close/checkpoint fails,
  `export_note` silently frames a main DB file that is missing the WAL's
  contents → a container that imports as an empty/partial note with no error.

Fix: in `prepare_paths_for_create`, also clear `-wal`/`-shm`. In `export_note`,
either propagate the `close()` result or explicitly
`PRAGMA wal_checkpoint(TRUNCATE)` and check it before reading the bytes. At
minimum stop discarding the `lock()` close error on the export path.

### M4 — `lock()` swallows `Connection::close` errors everywhere
`vault.rs:265-270`.

`lock(self)` returns `()` and discards the close result. A failed WAL checkpoint
on close means un-checkpointed committed data sits only in the `-wal` file; for a
normal vault that is fine (next open replays it), but combined with M3 it is a
silent data-loss path for export. Consider a `try_lock(self) -> Result<()>` (or
have `lock` log) so callers that need durability (export, pre-backup) can detect
a failed flush.

### M5 — `import_note` cannot surface meta-version / corruption distinctly
`note_export.rs:177` → `Vault::open` → `VaultMeta::read`.

A `.memento-note` carrying a future `version` in its embedded sidecar surfaces as
`UnsupportedFormat` (good), but a *corrupt* embedded sidecar (valid framing,
garbage JSON) surfaces as `Error::Json`, while the doc comment
(note_export.rs:161-167) only advertises `WrongPassphrase` / `MetaInvalid` / `Io`
/ `Db` / `Json`. That is technically covered by "Json", but the framing layer
claims to validate "the framing is a valid `.memento-note`" via `MetaInvalid` and
then leaks the inner `Json`/`UnsupportedFormat` variants. Not a bug, but the
error contract for importers is under-specified; document that import can return
`UnsupportedFormat` and `Json` from the embedded sidecar.

---

## Low

### L1 — `now_rfc3339` clamps a pre-epoch clock to 1970 silently
meta.rs:154-156. `duration_since(UNIX_EPOCH).unwrap_or_default()` turns a clock
set before 1970 into `0` → `created_at = "1970-01-01T00:00:00Z"`. Informational
field only; harmless, but note it.

### L2 — `meta_path_for` is purely string-suffix based
meta.rs:126-130. `vault.memento` → `vault.memento.meta.json`. Correct, but a
vault path ending in a trailing separator or with unusual OsString bytes yields a
surprising sidecar path. Fine for the documented usage; document that callers
pass a normal file path.

### L3 — `write_container` temp file uses a fixed `.tmp` suffix, not unique
note_export.rs:212. Two concurrent `export_note` calls to the **same** output
path race on `<path>.memento-note.tmp`. The `TempDir` work dir is per-call unique
(note_export.rs:281-307, well done), but the *final* temp is not. Concurrent
export to one destination is an odd thing to do, but the rename could observe a
half-written temp. Use a unique temp suffix (reuse the TEMPDIR_SEQ/nonce scheme).

### L4 — `open_with_key` ignores the sidecar it reads
vault.rs:141 reads `_meta` solely for the MetaMissing error shape, then discards
it. If the sidecar is present but its `kdf`/`version`/salt is invalid,
`VaultMeta::read` still runs `validate()` so that is caught — good. But the salt
is then unused on this path, so a sidecar with a *valid-shape but wrong* salt
opens fine by raw key while a later `rotate_key` would derive against that wrong
salt. Edge-only; document that `open_with_key` trusts the caller's key over the
sidecar.

### L5 — `Error::MetaInvalid` is reused for both sidecar and container-framing errors
note_export.rs:201/227/230/234/244. Overloading one variant for "bad JSON salt"
and "bad container magic" makes it impossible for a caller to tell a corrupt
sidecar from a non-`.memento-note` file. Consider a dedicated `ContainerInvalid`
variant (the enum is `#[non_exhaustive]`, so adding one is non-breaking).

---

## Things that are correct (verified, no action)

- No panic on the note-export parse path for *malformed*/truncated/empty/version-
  mismatch input (covered by tests) — except the H1 oversize-length allocation.
- Header slicing `header[0..8]`, `[9..13]`, `[13..21]` is all into a fixed
  `[u8; 21]` array, never attacker-sized — no OOB.
- `meta.salt()` length-checks before `copy_from_slice` (meta.rs:59-67) — no panic
  on a short/long hex salt.
- `hex_decode` handles odd length and non-hex via `Option` (meta.rs:141-149) — no
  unwrap.
- `constant_time_eq` is a correct fixed-length XOR-accumulate (vault.rs:327-333);
  rotate_key's old-key check is genuinely constant-time.
- `map_cipher_err` correctly distinguishes `NotADatabase` → `WrongPassphrase`
  from real `Db` errors (vault.rs:315-323).
- `#[non_exhaustive]` on `Error`; `#[from]` impls (Io/Json/Db) are correct and
  every `?` maps to the right variant.
- Use-after-lock is statically impossible: `lock(self)` consumes the vault, so
  double-lock / use-after-lock won't compile. Key zeroizes via `DerivedKey`'s
  `#[zeroize(drop)]`. No runtime "locked" state to mismanage. Good design.
- The `u64 as i64` cast in `now_rfc3339` and `db_bytes.len() as u64` in
  write_container are benign (documented / always-widening).

---

## Top 5 (fix in this order)

1. **H1** — bound/validate `meta_len`+`db_len` against real file size before
   allocating in `read_container` (the only malicious-input DoS).
2. **M1** — make `rotate_key` crash-safe (write new sidecar before rekey + a
   recovery path, or rekey-back on write failure) so a failed rotation can't
   brick a vault with data.
3. **M3 / M4** — handle `-wal`/`-shm` in create-recovery, and stop discarding the
   `close()` error on the `export_note` path (silent partial-note export).
4. **M2** — make `create`'s orphan-deletion explicit (doc + ideally a separate
   `repair` API) and switch `exists()` → `symlink_metadata` to dodge TOCTOU.
5. **L5 / M5** — split `MetaInvalid` (container vs sidecar) and document that
   `import_note` can also return `UnsupportedFormat` / `Json`.

## Most valuable missing tests

1. `import_note` with a **forged oversized `db_len`/`meta_len`** header → must
   return `MetaInvalid`, not OOM (regression test for H1).
2. `rotate_key` where the **sidecar write fails** (read-only dir / injected
   error) → assert the vault still opens with the *old* passphrase (no brick).
3. **Crash-between-DB-and-sidecar** simulation for `create` and `rotate_key`
   (write DB, skip/corrupt sidecar) → assert the documented recoverable outcome.
4. `import_note` with a **corrupt embedded sidecar JSON** and with a **future
   `version`** → assert `Json` / `UnsupportedFormat` (locks the error contract).
5. **Concurrent `export_note` to the same destination path** → no half-written
   container observed (L3).
6. `open` on a **truncated / corrupt DB body** (valid sidecar) → assert a clean
   `Db`/`WrongPassphrase`, never a panic.
7. `create` when a stale **`-wal`** companion is present → fresh vault must not
   replay the stale WAL (M3).
8. `schema_version` / meta `version` **mismatch** open path (currently only the
   unit `rejects_future_version` covers validate, not the full `open`).
