# terrapi-vault

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Encrypted-at-rest storage foundation for the **Memento** notes app, part of
the [Terrapi](https://github.com/terrapi) brand of developer tools.

`terrapi-vault` wraps a single [SQLCipher](https://www.zetetic.net/sqlcipher/)
database behind a small, safe lifecycle API:

- **Argon2id** (RFC 9106) key derivation from a user passphrase over a
  random per-vault salt — tuned for ~500 ms on Apple M-series hardware.
- The derived 256-bit key never touches disk; it lives in a
  [`secrecy::SecretBox`] and is zeroized on lock/drop.
- A small plaintext JSON **sidecar** (`<vault>.meta.json`) stores only the
  salt and KDF parameters — no secret material.
- In-place **key rotation** via SQLCipher `PRAGMA rekey`.
- Robust **partial-state recovery** on create (orphan DB / orphan sidecar).

It is fully self-contained: **no** dependency on any UI, GPUI, or
application types. The on-disk format is documented in
[`spec/vault-format.md`](spec/vault-format.md) precisely enough for an
independent compatible reader.

## Usage

```toml
[dependencies]
terrapi-vault = "0.1"
```

```rust
use terrapi_vault::{Vault, KdfParams};

# fn main() -> terrapi_vault::Result<()> {
// First run — create the vault.
let vault = Vault::create("notes.memento", "correct horse battery staple",
                          KdfParams::default())?;
vault.with_connection(|conn| {
    conn.execute_batch("CREATE TABLE note(id INTEGER PRIMARY KEY, body TEXT)")
})?;
vault.lock();

// Later run — unlock.
let vault = Vault::open("notes.memento", "correct horse battery staple")?;

// Rotate the passphrase.
let mut vault = vault;
vault.rotate_key("correct horse battery staple", "new passphrase")?;
# Ok(())
# }
```

### Running migrations

Downstream crates run migrations (e.g. with `rusqlite_migration`) and FTS5
setup through the guarded accessors — the encrypted connection is never
exposed unguarded:

```rust,no_run
# use terrapi_vault::Vault;
# fn f(vault: &Vault) -> terrapi_vault::Result<()> {
vault.with_connection(|conn| {
    conn.execute_batch("CREATE VIRTUAL TABLE note_fts USING fts5(title, body)")
})?;
# Ok(()) }
```

`terrapi_vault::rusqlite` re-exports the exact `rusqlite` build this crate
links, so downstream code shares one SQLCipher.

## KDF parameters

`KdfParams::default()` is Argon2id with `m_cost = 64 MiB`, `t_cost = 2`,
`p_cost = 1`. Verify the derivation time on your hardware:

```
cargo test print_default_kdf_timing -- --nocapture
```

## Security

- Master passphrase is **never persisted**.
- Derived key in `SecretBox`, zeroized on lock/drop.
- `PRAGMA key` is set as the first statement on every connection.
- Wrong passphrase maps to a distinct `Error::WrongPassphrase` (no panic).
- The vault file on disk is **not** a readable plaintext SQLite database.

See [`spec/vault-format.md`](spec/vault-format.md) for the full on-disk
format so the encryption is independently verifiable.

## Minimum supported Rust version

Pinned via `rust-toolchain.toml` (1.83.0). MSRV policy: 1.79+.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. The on-disk format specification
([`spec/vault-format.md`](spec/vault-format.md)) is licensed CC-BY-4.0.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms.
