# terrapi-vault — Round 3 roadmap: root lib (`src/`) deep-dive (2026-05-31)

Third review round, refocused from the services (rounds 1–2) onto the **root SQLCipher at-rest
library** — the crate memento/probe pin via `../terrapi-vault`, the highest-blast-radius code and
the least-reviewed until now. Three agents (crypto-security, correctness, API/versioning). Reports:
[`security.md`](security.md) · [`correctness.md`](correctness.md) · [`architecture.md`](architecture.md).

**Framing:** the crypto core is sound (Argon2id, raw-key SQLCipher, PRAGMA ordering, zeroization,
constant-time rotate, `#![forbid(unsafe_code)]`, minimal neutral API). **No Critical.** But the
review found real **malicious-input** and **at-rest-guarantee** gaps — and these matter precisely
because the lib is shipped inside memento/probe. All headline findings were verified against the code.

## Convergent findings (≥2 agents)
| Theme | Agents | Where |
|---|---|---|
| **`import_note` allocates from an attacker-controlled header before reading** (OOM DoS) | security M3, correctness **H1** | `note_export.rs:238-246` |
| **`rotate_key` is not crash-atomic** (rekey then sidecar → mid-crash brick) | security M1, correctness M | `vault.rs:194-200` |

## R3-P0 — Malicious-input + at-rest guarantee — ✅ DONE 2026-05-31
- **R3-1. ✅ `KdfParams` bounded**: `KdfParams::validate()` rejects `m_cost_kib > 4 GiB` / `t_cost`
  / `p_cost > 16`; called from `VaultMeta::validate()` (so every sidecar read is checked) — and
  thus on the `import_note` path. A tampered sidecar / hostile `.memento-note` can no longer pin a
  multi-TiB Argon2 allocation. `kdf.rs`, `meta.rs` (+ test `validate_rejects_out_of_range_kdf_params`).
- **R3-2. ✅ Declared lengths bounded before allocation**: `read_container` now caps `meta_len`
  (64 KiB) and rejects `meta_len + db_len > file_size` **before** the `vec![0u8; …]` — a hostile
  21-byte header declaring a 2 GiB body fails fast instead of OOMing. `note_export.rs` (+ test
  `import_rejects_oversized_declared_length_no_oom`).
- **R3-3. ✅ Fail-closed encryption assertion**: `open_keyed` checks `PRAGMA cipher_version` is a
  non-empty SQLCipher build string; if the linked SQLite isn't SQLCipher it returns the new
  `Error::EncryptionUnavailable` rather than silently writing plaintext. `vault.rs`, `error.rs`.
  _(Switching to `bundled-sqlcipher-vendored-openssl` remains a separate dep decision — deferred.)_
- **R3-4. ✅ `#[serde(deny_unknown_fields)]`** on `VaultMeta` + `KdfParams`: an unrecognised sidecar
  field is now a hard parse error, never silently dropped. `meta.rs`, `kdf.rs` (+ test
  `deserialize_rejects_unknown_field`).

_Verified: root lib 42 tests (35+5+2, 3 new), clippy -D warnings + fmt clean; services still green
(39+23+21) — the encryption assertion + validations are transparent to the broker/sync vault usage.
`spec/vault-format.md` documents the new limits._

## R3-P1 — Robustness / correctness — ✅ DONE 2026-05-31
- **R3-5. ✅ `rotate_key` crash-safe + recoverable**: the new sidecar is staged at `<meta>.rekeying`
  BEFORE `PRAGMA rekey`, then atomically renamed after. If a crash lands between rekey and the
  rename, `open` detects the staged sidecar (whose salt matches the rekeyed DB) and finalizes it —
  the vault is never bricked. A successful normal open cleans a stale pre-rekey staging file. Also
  fixed a latent bug surfaced here: `open` now catches `WrongPassphrase` from `open_keyed` (not
  only `verify_key`), so recovery actually runs. `vault.rs` (+ test
  `open_recovers_from_interrupted_rotate_no_brick`).
- **R3-6. ✅** a *newer* `.memento-note` container version is now `Error::UnsupportedFormat`
  (upgrade) vs. `MetaInvalid` (corrupt). `note_export.rs` (+ updated test).
- **R3-7. ✅** `random_salt` uses explicit `OsRng`; `pragma_literal` returns a `Zeroizing<String>`
  so the key-hex is scrubbed from the heap. `kdf.rs`, `vault.rs`. _(The tempdir nonce stays
  `thread_rng` — it is uniqueness-only, not security material.)_
- **R3-8. ✅ `Vault::files()`** returns `(db, meta)` with the atomic-unit invariant documented on
  the type — a backup/sync author can no longer miss that the sidecar must travel with the DB.
  `vault.rs`.

_Verified: root lib 43 tests (incl. the crash-recovery sim), clippy -D warnings + fmt clean;
services still green (39+23+21) — all changes transparent downstream._

## R3-P2 — Polish + tests — ✅ DONE 2026-05-31
- **R3-9. ✅** MSRV aligned to the deliberate floor: `Cargo.toml rust-version = "1.83"` (was 1.79)
  to match `rust-toolchain.toml` + the services workspace; README "MSRV policy: 1.79+" → 1.83 (the
  only tested version). `Cargo.toml`, `README.md`.
- **R3-10. ✅** `note_export` is behind a default-on `note-export` feature: memento is unaffected; a
  neutral consumer (`probe`) drops it with `default-features = false`. Verified the lib builds both
  with and without it. `Cargo.toml`, `lib.rs`.
- **R3-11. ✅** `prepare_paths_for_create` strips a symlink (via non-following `symlink_metadata`)
  before writing — closing the dangling-symlink write-through (`exists()` doesn't see a dangling
  link); orphan-DB removal now also drops stale `-wal`/`-shm`; `DerivedKey: Clone` documented as
  the keystore-handoff-only path. `vault.rs`, `kdf.rs`. _(Path-scrubbing from error variants left
  as-is — the paths are useful local debug context and removing them is a net-negative for a
  personal vault; S3-L3 noted, not actioned.)_
- **R3-12. ✅ Tests added** across P0/P1/P2: container-length OOM guard, unknown-field rejection,
  KDF-bound rejection, crash-recovery sim (`open_recovers_from_interrupted_rotate_no_brick`),
  symlink-strip, `Vault::files()`, container future-version contract.

_Verified: root lib 45 tests; builds with AND without `note-export`; clippy -D warnings + fmt clean;
services still green (39+23+21)._

## Suggested order
R3-1 → R3-2 → R3-4 (small, high-value, malicious-input + forward-compat) → R3-3 (encryption
assertion) → R3-5 (rotate atomicity) → the rest. R3-1/R3-2/R3-4 are a tight, high-value first pass
on the format-parsing surface; each pairs with a test from R3-12.
