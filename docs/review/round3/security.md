# terrapi-vault — Round 3 crypto/at-rest security review (root lib `src/`)

_The crypto core is sound and well-engineered: Argon2id params, raw-key SQLCipher keying,
PRAGMA-key ordering, zeroization, the constant-time rotate check, and the note_export framing all
hold up. **No Critical.** The findings are hardening/robustness on the edges — but several matter
because this lib is pinned by memento/probe (high blast radius)._

## High

**S3-H1. `kdf_params` in the meta sidecar are never bounds-checked** — `meta.rs:76-91` (`validate()`),
consumed at `vault.rs:100` / `vault.rs:186`, and worst via `import_note` (`note_export.rs:177`).
`validate()` checks `version`, `kdf == "argon2id"`, salt length — but **not** `kdf_params`. The
sidecar is plaintext + unauthenticated. An attacker editing it (or crafting a malicious
`.memento-note`, whose container-supplied sidecar `import_note` feeds straight into `Vault::open`)
can pin attacker-chosen `m_cost_kib`/`t_cost`/`p_cost`. A huge `m_cost_kib` → `derive_key` attempts
a multi-TiB allocation on open/import = **DoS**. **Fix:** range-check `KdfParams` in `validate()`
(RFC 9106 floor `m_cost_kib >= 19_456`, and a ceiling e.g. `<= 4_194_304` / 4 GiB, `t_cost`/`p_cost
<= 16`), and call it explicitly in `import_note` before opening.

**S3-H2. No runtime confirmation that SQLCipher encryption is actually active** — `Cargo.toml:16`
(`bundled-sqlcipher`), `vault.rs:286-288`. The code keeps cipher defaults but never asserts the
linked lib is SQLCipher; `bundled-sqlcipher` links against a *system* crypto provider, and on a
host where that degrades, `PRAGMA key` can be silently accepted as a no-op by plain SQLite →
**plaintext DB that still "works."** No positive confirmation. **Fix:** after keying, assert
`PRAGMA cipher_version` is non-empty (or that a fresh DB's first 16 bytes are not `SQLite format
3\0`) and fail closed with a distinct error; consider `bundled-sqlcipher-vendored-openssl` for a
deterministic provider.

## Medium

**S3-M1. `rotate_key` is not crash-atomic** — `vault.rs:194-200`. `PRAGMA rekey` re-encrypts in
place (new salt), *then* the sidecar is written. A crash between the two leaves the DB keyed with
the new salt while the sidecar holds the old salt → **neither passphrase re-derives the key
(brick)**; `derived_key()` (in-memory) is the only recovery. The meta write is itself atomic
(temp+rename) but the cross-file ordering isn't. **Fix:** stage the new sidecar before/around
`rekey` and rename immediately after; or a recovery marker; at minimum document + recommend
snapshotting `derived_key()` before rotating. _(Convergent with correctness review.)_

**S3-M3. `import_note` allocates from an attacker-controlled header before reading the body** —
`note_export.rs:243-251`. `db_len`/`meta_len` are validated only against `usize::MAX`; a 21-byte
hostile container declaring `db_len = 0x7FFF_FFFF` forces `vec![0u8; db_len]` (≈2 GiB) before
`read_exact` fails. **Fix:** cap `meta_len` (a sidecar is < 4 KiB; reject > 64 KiB) and validate
`db_len` against the actual file size before allocating. _(Convergent — correctness review rated
this **High**.)_

**S3-M2. Salt/nonce use `thread_rng()` not explicit `OsRng`** — `kdf.rs:77`, `note_export.rs:294`.
`thread_rng()` (rand 0.8) is a CSPRNG today, so currently secure — but the guarantee is implicit; a
future `rand`/`getrandom` change could weaken it with no compile error. **Fix:** use explicit
`OsRng.fill_bytes(...)` so the property is pinned in the type. (Salt length 16 B is fine.)

## Low
- **S3-L1.** `pragma_literal` builds the raw key as a non-zeroized `String` (`kdf.rs:121-130`,
  `vault.rs:194/281`) — transient key bytes linger in freed heap. Use `Zeroizing<String>`.
- **S3-L2.** `DerivedKey: Clone` (`kdf.rs:87`) copies raw key bytes — bounded (each clone zeroizes)
  but a footgun; document/gate it.
- **S3-L3.** Error variants embed full filesystem paths (`error.rs:25-26,33`; Kdf string echoes
  params) — leaks vault locations if logged. No key material. Scrub in user-facing surfaces.
- **S3-L4.** `prepare_paths_for_create` (`vault.rs:354-369`) `remove_file`s an orphan without a
  symlink/type check — local TOCTOU footgun. Add `symlink_metadata` check / `O_NOFOLLOW`.

## Verified correct
Argon2id key derivation; raw-key SQLCipher keying with correct PRAGMA-key ordering;
`DerivedKey`/`SecretBox` zeroization + no-leak `Debug`; constant-time `rotate_key` compare;
`map_cipher_err` → `WrongPassphrase` with no extra timing/message leak; note_export framing.

## Top 5
1. **S3-H1** — bound `kdf_params` in `validate()` + `import_note` (unauthenticated cost-injection DoS).
2. **S3-H2** — fail-closed assertion that encryption is actually on (don't silently store plaintext).
3. **S3-M3** — bound `meta_len`/`db_len` vs file size before allocating (import OOM).
4. **S3-M1** — make `rotate_key` crash-safe (no brick on mid-rotation crash).
5. **S3-M2 + S3-L1** — explicit `OsRng` for salt/nonce; zeroize the transient `pragma_literal` key.
