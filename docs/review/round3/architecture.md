# terrapi-vault — Round 3 Architecture Review (root library crate, `src/` only)

Scope: API stability, versioning/compat, dependency neutrality, cohesion,
maintainability for an external (memento/probe) consumer. Services excluded.

Overall: this is a small, disciplined, dependency-neutral crate. The on-disk
format is genuinely documented (`spec/vault-format.md`,
`spec/note-export-format.md`), `unsafe` is forbidden, the key never touches
disk, and the three version surfaces are handled more carefully than most
real-world libraries. Most findings below are hardening / consistency, not
correctness bugs. The single most valuable section is versioning, first.

---

## 1. Versioning & forward/backward compatibility (HIGHEST VALUE)

There are **four** version surfaces. Their behavior on an old↔new mismatch:

| Surface | Where | Newer lib / older file | Older lib / newer file |
|---|---|---|---|
| `FORMAT_VERSION` (sidecar) | `meta.rs:15`, `VaultMeta::validate` `meta.rs:75-92` | OK (reads v1) | **Clean error** `UnsupportedFormat` (`version > FORMAT_VERSION`) |
| `CONTAINER_VERSION` (.memento-note) | `note_export.rs:67`, `read_container` `note_export.rs:233` | OK | **Clean error** `MetaInvalid("unsupported … container version")` |
| `vault_schema` row 0 (= 1) | `vault.rs:241`, `init_schema` `vault.rs:335-342` | see Low-3 | see Low-3 |
| SQLCipher cipher version | implicit (bundled) | — | — |

### Verdict: the forward-compat story is GOOD but asymmetric and under-typed.

**HIGH-1 — `.memento-note` future-version rejection is mistyped as
`MetaInvalid`, not `UnsupportedFormat`.**
`read_container` (`note_export.rs:233-236`) rejects a *newer* container version
with `Error::MetaInvalid` ("invalid"), while the sidecar path correctly uses the
dedicated `Error::UnsupportedFormat { found, supported }` (`meta.rs:79`). These
are the *same situation* (a future file a current build can't read) reported as
two different error kinds. A memento UI that wants to say "this note was made by
a newer app version — upgrade" cannot distinguish it from genuine corruption.
**Change:** make the container check emit `Error::UnsupportedFormat { found:
u32::from(container_ver), supported: u32::from(CONTAINER_VERSION) }`. (Note: this
unifies the two version surfaces' downstream handling — the single most useful
change in the crate.)

**HIGH-2 — `KdfParams` and `VaultMeta` have no `#[serde(deny_unknown_fields)]`,
so the "future version" gate is the *only* thing protecting forward-compat — and
it is bypassable.** A v1 sidecar that a future build *adds a field to* (e.g. a
`mac` or `kdf_variant`) will silently deserialize on the OLD lib, dropping the
new field, and—because `version` is still `1`—**pass `validate()`**. The old
lib then derives a key ignoring the new field. For a security sidecar this is a
real footgun: forward-incompatible changes MUST bump `FORMAT_VERSION`, but
nothing enforces that an additive field also bumps it. **Change:** add
`#[serde(deny_unknown_fields)]` to `VaultMeta` (`meta.rs:23`) and `KdfParams`
(`kdf.rs:38`). Then any unknown field in a v1 doc fails to parse on an old build
(loud), rather than being silently ignored (dangerous). Document in
`vault-format.md`: "additive sidecar fields require a `version` bump."

**MED-1 — `import_note` does not call `meta.validate()` on the *embedded*
sidecar before opening.** `read_container` checks the container framing version,
but the inner `meta_json` is written to a temp file (`note_export.rs:174`) and
handed to `Vault::open`, which *does* validate via `VaultMeta::read`. So it is in
fact covered transitively — but only by luck of the open path. Worth an explicit
assertion/comment so a future refactor of `import_note` doesn't drop the
validation. Low risk, flagged for the record.

**MED-2 — No upper bound on `meta_len`/`db_len` allocation in `read_container`
(`note_export.rs:245-251`).** A hostile/corrupt `.memento-note` declares a
`meta_len`/`db_len` and the reader does `vec![0u8; meta_len]` before reading.
`db_len` is bounded only by `usize::try_from`. `import_note` is a user action on
a user-chosen file, so the blast radius is small, but a 4 GiB `meta_len` is a
trivial OOM. **Change:** reject `meta_len` above a sane ceiling (e.g. 1 MiB — the
sidecar is ~200 bytes) and stream/cap `db_len` against the actual file size
(`f.metadata().len()`), failing with `MetaInvalid` before allocating.

**MED-3 — On-disk format spec versioning is documented but the *evolution
policy* is not.** `vault-format.md` exists and is thorough, but neither it nor
rustdoc states the **compatibility contract** memento needs: "v1 readers reject
v2 files; v2 readers must still read v1; additive fields bump the version; the
sidecar MUST be backed up with the DB." This is the contract an external
consumer actually depends on. **Change:** add a short "Compatibility &
evolution" section to `vault-format.md` and reference it from `lib.rs`.

---

## 2. Public API surface & stability

The surface is small and deliberate: `Vault`, `VaultMeta`, `KdfParams`,
`DerivedKey`, `export_note`/`import_note`+`ExportedNote`, the consts, and the
`rusqlite` re-export. `Error` is `#[non_exhaustive]` (`error.rs:12`) — good,
lets you add variants without a breaking change. `DerivedKey.0` is `pub(crate)`
(`kdf.rs:89`) — correct, not leaked.

**MED-4 — `with_connection` exposing raw `rusqlite::Connection` is the right
escape hatch, but the *re-export of `rusqlite`* (`lib.rs:72`) silently pins
memento/probe to this crate's exact rusqlite/SQLCipher version forever.** This is
intentional and documented (avoids the version-mismatch hazard when passing the
`Connection` through), and is the correct call. But it means **every rusqlite
bump in this crate is a semver-breaking change for downstream** even if your own
API is unchanged. **Change:** document this explicitly in the changelog policy —
"a `rusqlite` major bump is a breaking release of terrapi-vault" — and consider a
`pub use rusqlite` behind a `#[doc]` note so consumers know not to add their own
`rusqlite` dep. (No code change required; this is a stability-contract note.)

**LOW-1 — `open_with_key` + `derived_key` widen the surface for an unbuilt
feature (biometric keystore).** Both are well-documented, but they expose
raw-key open and key extraction purely for a feature that doesn't exist yet in
this crate. They're defensible (memento needs them) but every pub item is a
forever-commitment. Confirm memento actually consumes both before 1.0; if not,
gate behind a `keystore` feature.

**LOW-2 — `Cargo.toml` declares `version = "0.1.0"` with a `docs.rs`/`repository`
pointing at a public `github.com/terrapi` URL.** For a path-dependency-only crate
that is the secrets boundary of a private stack, publishing metadata
(`documentation = docs.rs`, public repo URL) is misleading until it's actually
published. Either publish, or trim the publish-oriented metadata to avoid
implying a stability guarantee that isn't backed by a release process.

---

## 3. Dependency neutrality (CLAUDE.md "core lib neutrality principle")

**Clean.** `Cargo.toml` deps: `rusqlite(bundled-sqlcipher)`, `argon2`, `rand`,
`zeroize`, `secrecy`, `thiserror`, `serde`, `serde_json`. **No tokio, no axum, no
async, no platform/UI types.** `#![forbid(unsafe_code)]` (`lib.rs:53`). The
author even hand-rolled the RFC-3339 timestamp (`meta.rs:155-180`) and a temp-dir
(`note_export.rs`) to avoid `chrono`/`tempfile` in non-dev deps. This is exactly
right for a crate pinned by memento/probe.

**MED-5 — `bundled-sqlcipher` is the only SQLCipher wiring; there is no
system-lib escape and it is not feature-gated.** `bundled-sqlcipher` compiles
SQLCipher (and a vendored OpenSSL/crypto) from source on every downstream build —
slow builds and a vendored crypto blob baked into memento/probe with no opt-out.
Most consumers want bundled, but a packager (Linux distro, security audit) may
require the system library. **Change:** expose `default = ["bundled-sqlcipher"]`
and an alternative `system-sqlcipher` feature forwarding to rusqlite's
`sqlcipher` feature, so downstream can choose. Document the choice's security
implication (you currently inherit whatever SQLCipher version the bundle ships;
pin it).

**LOW-3 — MSRV is declared in two places that disagree.** `Cargo.toml:5` says
`rust-version = "1.79"`; `README.md:94` and `rust-toolchain.toml` say `1.83`.
The task brief says 1.83. `cargo` enforces the `Cargo.toml` value, so the real
guarantee is 1.79 while CI tests 1.83 — meaning a 1.80–1.83 feature could slip in
undetected. **Change:** set `rust-version = "1.83"` in `Cargo.toml` to match the
toolchain and the documented floor (single source of truth).

---

## 4. Cohesion

**LOW-4 — `note_export` is a separable concern living in the core crate.** It is
a memento-specific format (`NOTE_MAGIC = b"MNOTE\0\0\0"`, `exported_note`
table with `title`/`body_markdown`/`view_mode` — pure memento domain) inside a
crate whose stated purpose is "shared encrypted-at-rest SQLCipher vault." `probe`
(API client) almost certainly never imports a note. This couples the neutral
vault primitive to one consumer's document shape, and bloats `probe`'s build with
note logic + the `TempDir` machinery. **Change:** gate it behind a default-off
`note-export` feature (cheap, non-breaking), or split it into a
`terrapi-note-export` crate that depends on `terrapi-vault`. Feature-gating is the
pragmatic move; it keeps the path dep intact while letting `probe` opt out.

**LOW-5 — `Vault` aggregates DB + key + meta + lifecycle.** This is acceptable —
it's the cohesive "open encrypted store" facade and the parts are genuinely
coupled (the key derives from the meta's salt to open the DB). Not a god-object;
no change needed. Noted only to confirm it was assessed.

The `Error` enum is well-designed: `#[non_exhaustive]`, `#[from]` for io/json/db,
a distinct `WrongPassphrase` cleanly separated from `Db` via `map_cipher_err`
(`vault.rs:316`), and a dedicated `UnsupportedFormat` discriminant. Good.

---

## 5. Docs / maintainability for an external consumer

Strong. `lib.rs` has a runnable quick-start, documents the migration story
(downstream runs its own migrations via `with_connection`), and states the
sidecar-is-not-secret-but-is-required invariant. `#![warn(missing_docs)]` is on.

**MED-6 — The single most security-critical operational invariant — "the
`.meta.json` sidecar MUST be backed up / synced *together with* the DB, atomically;
losing it bricks the vault" — is stated in prose in `lib.rs` and `meta.rs` but is
not surfaced where a backup/sync author will see it.** vault-sync and memento
both move these files around; a sync that copies the `.terrapi` DB but not the
`.meta.json` (or vice-versa, or non-atomically mid-`rotate_key`) silently bricks
or corrupts the vault. Note `rotate_key` (`vault.rs:178`) rewrites the sidecar
with a *fresh salt* — a backup taken between the `rekey` PRAGMA and the sidecar
write (or that captures only one of the two) is unrecoverable. **Change:** add a
`# Backup & sync invariant` doc section to `Vault` itself (not just module docs)
spelling out: (1) DB + sidecar are one atomic unit; (2) `rotate_key` mutates both
— don't snapshot mid-rotation; (3) point at `vault-format.md`. Consider a
`Vault::files(&self) -> [&Path; 2]` helper so a backup tool can't forget one.

**LOW-6 — `with_connection` contract under-specifies failure/poisoning.** Doc
says it propagates `rusqlite::Error`, but doesn't state what happens if the
closure leaves a transaction open or the connection in a bad state, nor that the
borrow is exclusive for `_mut`. Minor; a one-line note ("the connection is not
reset between calls; leave no open transaction") would help.

---

## Top 5 (priority order)

1. **HIGH-2 — Add `#[serde(deny_unknown_fields)]` to `VaultMeta` and
   `KdfParams`** (`meta.rs:23`, `kdf.rs:38`). Today an additive future field can
   be silently dropped by an old build *and still pass `validate()`* because
   `version` is unchanged — a forward-compat hole in the security sidecar.

2. **HIGH-1 — Make `.memento-note` future-version rejection use
   `Error::UnsupportedFormat`, not `MetaInvalid`** (`note_export.rs:233`). Unifies
   the two version surfaces so memento can tell "newer-app file, upgrade" from
   "corrupt file."

3. **MED-6 — Document the DB+sidecar atomic-backup invariant on `Vault` itself,
   and flag the `rotate_key` mid-rotation window** (`vault.rs:178`); add a
   `files()` helper. This is the invariant most likely to brick real user data
   via vault-sync.

4. **MED-5 — Feature-gate SQLCipher (`bundled` default + `system` opt-in)** in
   `Cargo.toml`, and **LOW-3 — fix the MSRV mismatch** (`Cargo.toml` 1.79 vs
   toolchain 1.83). Both remove "surprise" from downstream builds.

5. **MED-2 + LOW-4 — Bound `read_container` allocations against file size**
   (`note_export.rs:245`) and **feature-gate `note_export`** so the neutral vault
   primitive isn't coupled to memento's document format and `probe` can opt out.
