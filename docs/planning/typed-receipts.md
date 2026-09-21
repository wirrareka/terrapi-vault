# Typed receipts and shared storage

Status: implemented helper/storage integration, UNRELEASED, 2026-09-13.
Source: `replication/fixed-pair/src/receipts.rs`; tests:
`replication/fixed-pair/src/envelope_tests.rs` plus existing receipt/protocol suites.

## Implemented

`OperationReceipt::from_applied(adapter, entry)` derives receipt contents from a
typed `Entry` using the adapter's request fingerprint and nonzero fingerprint version.
It requires Applied state, valid nonempty operation ID, a positive SQLite-range
sequence and a valid envelope checksum. Result encoding remains version 1.

`matches_request(adapter, batch)` verifies supported result/fingerprint versions,
result-key validity, operation ID and the ordered business-request fingerprint.
It does not infer that equal resulting SQL state means equal requests.

Internal `get_for`, `insert_for` and `validate_entry_for` share the existing
`operation_receipts` table implementation across adapters. Legacy wrappers select
Proximi and fingerprint version 1. The now-unused private `from_entry` wrapper was
removed; no public legacy API was removed. Legacy fingerprint bytes, receipt JSON,
receipt-format marker and TLS format remain unchanged.

Insert participates in the caller's transaction. Exact retry must equal the stored
receipt; another result under the same operation ID is rejected. Lookup verifies SQL
sequence/operation keys against receipt metadata and the expected fingerprint version.
Journal validation compares the stored receipt with the expected Applied receipt;
Prepared/Decided entries must not have one. Existing legacy migration still backfills
only its supported reference format and preserves its corruption checks.

## Authority and scope boundary

Receipt construction is a pure data operation, not proof that SQL was applied or
that either replica durably committed it. An envelope checksum excludes state and
does not authorize a state transition. Identity/tenant/epoch/schema admission,
immutable schema-contract verification and full history validation remain the
owning protocol's responsibility. Request matching intentionally excludes transport
scope from its business-content fingerprint.

The SQL helpers remain crate-private and do not initialize a generic receipt format,
set durability pragmas, authorize writes or commit a transaction. Reference Node uses
them inside its existing entity/journal/receipt transaction and existing two-copy
protocol. A default Node cannot read the independent adapter's V2 receipts as V1.
This is not yet a generic Node, generic receipt-bearing snapshot or peer protocol.

## Independent-schema verification

An inventory adapter with fingerprint version 2 initializes its own SQL table and
persisted schema contract inside a real encrypted Vesta database. A real SQLite
changeset is captured and a Prepared typed journal entry stored. The test composes
the existing replay, journal and receipt helpers in one caller-owned transaction.

An injected receipt-insert failure is followed by transaction rollback: inventory
rows remain empty, journal state remains Prepared, and no receipt exists. Successful
retry commits application data, Applied journal and receipt together. Exact receipt
insert retry succeeds; conflicting sequence, premature receipt state and corrupt SQL
receipt metadata are rejected. Reopening the encrypted file validates the same
contract, application rows, typed entry and V2 receipt. This is a local transaction
composition test, not a new replication engine or generic two-copy recovery proof.

Other tests cover invalid envelope state/checksum, invalid keys, wrong versions,
request conflict and a literal legacy receipt JSON with an independently computed
SHA-256 digest.

## Verification record

Verified locally with Rust 1.89.0 on 2026-09-13:

- All-feature library and selected integration suites: 79 passed. Suites include
  receipts, protocol, recovery_foundation, materialized, published_restore and
  snapshot_staging; two child-process helper tests remain intentionally ignored.
- Default-feature library: 31 passed; production_features: one passed and one
  child-process helper intentionally ignored.
- Workspace/all-target Clippy with warnings denied passed with both default and
  all features; workspace formatting check passed.
- `git diff --check` passed for tracked changes. Root Cargo.toml, Cargo.lock,
  src and services have no tracked changes.

These are targeted regression runs, not a fresh full-network or membership suite,
coverage measurement, physical power-loss test or production deployment. Generic
Node lifecycle and receipt-bearing generic recovery remain unfinished. Subsequent
[reference peer admission](peer-schema-admission.md) and
[typed checkpoint/history restoration](typed-checkpoints-history.md) have their own
implementation and verification records.
