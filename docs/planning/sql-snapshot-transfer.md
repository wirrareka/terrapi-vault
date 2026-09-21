# Generic SQL snapshot transfer

Status: application-data snapshot/operation-codec foundation implemented, UNRELEASED.
Date: 2026-09-13. Source: `replication/fixed-pair/src/sql_snapshot.rs` and
`sql_snapshot/transport.rs`; tests: `replication/fixed-pair/tests/sql_snapshot.rs`.

## Implemented contract

1. Initialize the application's SQL schema, then `bind` a new empty database to
   `(format=1, cluster, tenant, epoch, schema name/version, catalog digest)`. Reopening
   requires exact equality. A populated unbound database cannot be adopted implicitly;
   an existing binding cannot change epoch, tenant or schema in place.
   All three metadata tables are created atomically on first bind. A partial table
   set or a missing binding row in an existing set is corruption, not permission
   to initialize again. Bind refuses to repair it; subsequent operations also fail
   closed on missing metadata.
2. `export` captures a consistent SQL read transaction. It freezes typed rows in
   application table order and primary-key order, hashes the actual SQL values and
   the adapter's canonical view, then releases the transaction. Catalog identity includes
   exact table/index DDL and adapter table order, not only a numeric schema version.
3. `begin` reserves one immutable incoming manifest. `receive` stores validated pages
   and counters transactionally in `snapshot_sql_*` tables. Application rows stay empty.
   Exact fully received page retries are accepted; gaps, overlap, changed rows, manifest
   swaps and schema drift are rejected. A Vesta-owned connection encrypts staging too.
4. `finish` verifies all staged positions, counts, bytes and the content hash; inserts
   into an empty application schema in one transaction; checks foreign keys, exact SQL
   value roundtrip and the application state hash; then commits data and completion
   together. A failure rolls back all application rows. Foreign keys can be deferred
   within this transaction, allowing children to arrive before parents.
5. Reopened receivers resume from durable counters. Repeating `begin`, an acknowledged
   page, or `finish` after completion revalidates current application data before reporting
   completion. An old completion flag cannot certify changed data.

Transport operations are `Begin`, `Page` and `Finish`, with strict unknown-field
rejection and bounded decoding before JSON allocation. Finish explicitly names the
manifest digest, so a stale operation cannot finish a different reserved transfer.
`dispatch` returns local progress; it does not authorize requests or assert two-copy ACKs.
The host must apply wire-size limits while reading the connection, before passing a
complete buffer to the decoder. The decoders cannot prevent an upstream unbounded read.

## Type preservation and limits

Values are explicitly tagged NULL, signed INTEGER, REAL IEEE bits, UTF-8 TEXT, or BLOB.
This preserves NULL versus an empty blob, integer extrema, fractional/infinite REALs,
and composite primary keys. NaN and invalid UTF-8 text are rejected. SQL identifiers
are derived from locally validated catalog metadata and quoted, never supplied as SQL
by the transfer. The receiver re-reads typed rows to catch SQL affinity conversions and
ordering differences independently of an incomplete application view.

| Limit, format 1 | Maximum |
| --- | --- |
| Application tables / columns per table | 128 / 256 |
| Rows / summed canonical row JSON | 100,000 / 256 MiB |
| Canonical row JSON | 256 KiB |
| Page rows / encoded page | 256 / 1 MiB |
| Encoded manifest / operation request | 4 KiB / 1 MiB + 128 bytes |

Outgoing `Export` is a bounded in-memory frozen image; `pages` returns an owned vector
and clones rows. This is not an outgoing disk-backed streaming publication. JSON byte
quotas are not an RSS or encrypted-file-size guarantee. Incoming pages persist across
restarts; there is one incoming slot and no reset/GC/automatic replacement API.

Supported: ordinary tables with explicit non-null primary keys, including WITHOUT ROWID,
composite keys and foreign keys contained within the application schema. Rejected:
virtual tables, generated/hidden columns, application-table triggers, and any temporary
tables/views/triggers on the connection (they could shadow main application or metadata tables),
cross-schema foreign keys, and AUTOINCREMENT (its sequence high-water mark is not exported).
Implicit rowids are not logical replicated state; adapters must not depend on them.
Exact DDL equality intentionally rejects even benign index/DDL differences. Adapter
implementations, collations and view semantics must remain stable for a schema identity;
the DDL hash cannot prove equivalence of application code.

## Security and compatibility boundary

`bind` selects `synchronous=FULL` on its exclusively owned connection, preserving a
pre-existing `EXTRA` profile. Every snapshot operation checks this profile. Reopening
the root Vesta library resets its general-purpose connection default to NORMAL, so
call `bind` again with the exact persisted scope before resuming a transfer. The root
library's defaults are not changed. Persistent databases require transactional disk
journaling (WAL/DELETE/TRUNCATE/PERSIST) and `temp_store=MEMORY`; volatile journals
are accepted only for explicitly in-memory databases, which provide no durability.
The module does not change `temp_store` or delete existing temporary objects to make
a connection pass validation. Disk durability still depends on storage honoring syncs.

The caller owns authentication, manifest provenance, authorization, fencing, exclusive
database access and read admission. Digests detect mismatch, not maliciously replaced
manifests or rollback of an entire database. `Schema` remains trusted code. No untrusted
SQL execution, permissive policy, plaintext listener, new service route or production
deployment was introduced. Holding a `Progress` value is not a recovery authorization.

Metadata-loss detection is not an external anti-rollback mechanism: deleting the
entire metadata set from an empty database is indistinguishable here from a new,
unbound application database. Host-level durable identity/fencing is still required;
the snapshot primitive does not replace Node's admission or recovery authority.

This primitive exports application data only: no operation receipts, commit journal,
membership seals, authority counters or recovery control decisions. Legacy Node,
materialized/publication formats and checkpoint format 1 remain intact. The later
[peer admission change](peer-schema-admission.md) upgrades the reference TLS protocol
from 11 to 12 independently of this snapshot primitive.
Generic two-copy requests, receipt-bearing snapshots and authenticated network dispatch
still need integration with the existing recovery coordinator. Do not treat this module
as a finished `Node<YourSchema>` or route custom schemas through legacy endpoints.

The changes are isolated to new modules plus crate-private schema validation reuse;
existing protocol checks were preserved, following the narrow-change approach. Root
Vesta API/format, Rust 1.83 and services are unchanged; this workspace remains Rust 1.89.

## Verification record

### Binding corruption continuation (2026-09-13)

- RED: the new regression reproduced successful rebinding after deleting the binding
  row from an empty database. Existing initialization also recreated missing tables.
- Fixed initialization to distinguish first creation from a damaged existing set;
  common operation admission verifies metadata completeness without repairing it.
- New tests cover missing binding row, each missing metadata table, refusal of both
  original and changed-tenant rebind, export/begin/receive/finish rejection, unchanged
  remaining table set and empty application data. An encrypted-file reopen separately
  verifies that a deleted binding row stays missing and cannot be reassigned.
- SQL snapshot 17 and SQL schema 10 passed in both default and all-feature profiles
  (54 selected test executions). All-feature workspace/all-target Clippy passed with
  warnings denied. This continuation does not rerun legacy Node/network recovery
  suites and does not complete generic Node integration.

### Earlier snapshot foundation

- Initial RED: new tests failed to compile before the snapshot module existed.
- New snapshot suite: 15 passed in each default/all-feature profile. Includes encrypted receiver reopen,
  resumable exact retries, scope/catalog mismatches, empty transfer, byte/page limits,
  invalid tables/rows, corrupted staging, hash-failure rollback, foreign-key ordering,
  operation codec/stale finish, changed-data completion checks, REAL/composite keys,
  unsupported AUTOINCREMENT, corrupted completion counters, TEMP shadowing, and
  durability profile enforcement/re-establishment after reopen.
- A RED/GREEN test reproduced export of a shadowing TEMP table; the catalog now
  rejects temporary tables/views/triggers before using the connection.
- Existing SQL adapter suite: 8 passed.
- Compatibility run: library 27, legacy materialized 5, legacy recovery 7 and staged
  snapshot 5 passed; two recovery subprocess helpers were invoked by parent tests.
  That run's new snapshot target failed on a malformed AUTOINCREMENT test fixture;
  its SQL syntax was corrected and the full new suite rerun separately. This was a
  test-fixture error, not a passing aggregate run.
- A clean targeted all-feature rerun subsequently passed library 27 + materialized 5 +
  recovery 7 + staged snapshot 5 + SQL adapter 8 + then-current SQL snapshot 14 = 66
  parent tests. The later durability-only addition was checked in the final 15-test
  snapshot suite separately; it does not modify the legacy protocol paths.
- Both final Clippy profiles passed with `--workspace --all-targets -- -D warnings`, with
  `--all-features` on the full profile. Formatting, CI YAML and local documentation
  links are checked. Root runtime sources/manifests/services remain unchanged.

No complete network suite, full-workspace pass, measured coverage, power-loss test,
real FreeBSD/Linux run, independent audit, performance acceptance or remote CI execution
is claimed for this continuation. Existing network timing limits were not changed.
