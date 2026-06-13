# terrapi-vesta

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Encrypted-at-rest storage foundation for the **Memento** notes app, part of
the [Terrapi](https://github.com/terrapi) brand of developer tools.

`terrapi-vesta` wraps a single [SQLCipher](https://www.zetetic.net/sqlcipher/)
database behind a small, safe lifecycle API:

- **Argon2id** (RFC 9106) key derivation from a user passphrase over a
  random per-vesta salt — tuned for ~500 ms on Apple M-series hardware.
- The derived 256-bit key never touches disk; it lives in a
  [`secrecy::SecretBox`] and is zeroized on lock/drop.
- A small plaintext JSON **sidecar** (`<vesta>.meta.json`) stores only the
  salt and KDF parameters — no secret material.
- In-place **key rotation** via SQLCipher `PRAGMA rekey`.
- Robust **partial-state recovery** on create (orphan DB / orphan sidecar).
- **Recovery codes** — passphrase and a high-entropy recovery code are independent
  key-slots that each wrap a random data key, so a lost passphrase is recoverable and
  changing one slot never invalidates the other (see
  [`spec/vault-format.md`](spec/vault-format.md) §13).

It is fully self-contained: **no** dependency on any UI, GPUI, or
application types. The on-disk format is documented in
[`spec/vault-format.md`](spec/vault-format.md) precisely enough for an
independent compatible reader.

## Repository layout

This repo is the at-rest **library** (this crate, at the root — what `memento` and `probe`
consume as a path dependency) plus the network **services** it has grown into, under
[`services/`](services/):

- **`vesta-broker`** — the stack's network **secrets broker** (Path A): mTLS-over-WireGuard,
  one instance per residency group, port `8200`. SSH signed-cert CA, leased service-admin
  creds, KMS wrap/unwrap, object-store presigned URLs, and a read-only `observe` API.
  Contract: [`spec/broker-openapi.yaml`](spec/broker-openapi.yaml).
- **`vesta-sync`** — personal multi-device, **end-to-end / server-blind** sync for memento/probe
  (device-keypair auth, row-level oplog). Contract: [`spec/sync-openapi.yaml`](spec/sync-openapi.yaml).
- **`vesta-console`** — operator web/API console (read-only observability), one per group,
  port `8203`; aggregates the brokers' `observe` API. SPA in [`web/`](web/). Plan:
  [`docs/planning/02-vesta-console.md`](docs/planning/02-vesta-console.md).
- **`vesta-transport`** — shared transport/audit types for the services.

The library stays platform-neutral (no networking/UI deps) so memento/probe are never
constrained; the services are a separate workspace under `services/`.

## Usage

```toml
[dependencies]
terrapi-vesta = "0.1"
```

```rust
use terrapi_vault::{Vesta, KdfParams};

# fn main() -> terrapi_vault::Result<()> {
// First run — create the vault.
let vesta = Vesta::create("notes.memento", "correct horse battery staple",
                          KdfParams::default())?;
vault.with_connection(|conn| {
    conn.execute_batch("CREATE TABLE note(id INTEGER PRIMARY KEY, body TEXT)")
})?;
vault.lock();

// Later run — unlock.
let vesta = Vesta::open("notes.memento", "correct horse battery staple")?;

// Rotate the passphrase.
let mut vesta = vesta;
vault.rotate_key("correct horse battery staple", "new passphrase")?;
# Ok(())
# }
```

### Running migrations

Downstream crates run migrations (e.g. with `rusqlite_migration`) and FTS5
setup through the guarded accessors — the encrypted connection is never
exposed unguarded:

```rust,no_run
# use terrapi_vault::Vesta;
# fn f(vesta: &Vesta) -> terrapi_vault::Result<()> {
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
- The vesta file on disk is **not** a readable plaintext SQLite database.

See [`spec/vault-format.md`](spec/vault-format.md) for the full on-disk
format so the encryption is independently verifiable.

## Minimum supported Rust version

**1.83** — the deliberate MSRV floor, pinned via `rust-toolchain.toml` and declared in
`Cargo.toml` (`rust-version = "1.83"`). The lib is built and tested only on 1.83, so that is the
verified minimum; do not bump it without reason (memento consumes it as a path dependency).

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
