# Typed checkpoints and shared history restoration

Status: implemented, targeted regressions verified with a recorded parallel-test
instability, UNRELEASED,
2026-09-13. This is a continuation of the SQL adapter and typed receipt integration,
not completion of a generic replication Node.

## Shared implementation

`Checkpoint<I = u32>` supports typed schema identities without changing the default
JSON fields or checkpoint format 1. Internal checkpoint calculation, current-data
verification, base decoding and receipt-prefix hashing now accept the schema adapter
and typed identity. The reference Node delegates to those same functions.

Receipt prefixes use the adapter's nonzero fingerprint version and retain checks on
sequence continuity, SQL/JSON operation keys, result version and prefix completeness.
Both active and published receipt tables use the same implementation. SQLite-range
bounds are checked before querying the prefix. The reference adapter still requires
V1 receipts; it does not silently accept the inventory adapter's V2 receipts.

Checkpoint calculation retains scope validation, per-entry checksums, receipt/history
agreement, ordering, pending-tail rules, base validation, prefix bounds and orphan
receipt checks. Current-state verification additionally compares the actual application
view with the checkpoint. The historical `proximiio-journal-chain-v1` and
`proximiio-journal-link-v1` hash labels remain format-1 encoding constants; typed scope
is included in the seed. No persisted digest is rewritten or migrated.

`journal::replay_history_in` is a shared caller-transaction operation. Reference
`Node::install` uses it after its existing role, scope, snapshot digest, recovery,
empty-target and publication checks. Every entry must belong to the expected scope,
be Applied, fit the existing entry limit, continue sequence one onward and match the
current application state. SQL changes, journal entry and receipt are written within
the same transaction. The caller must roll back/drop that transaction on error, run
final snapshot checks and commit only on success. Node's existing final view/receipt
checks and read-admission invalidation remain in place.

## Trust and scope limits

These helpers remain crate-private. The owning protocol must validate the immutable
schema contract, supply a trusted initial-state digest, own the connection/transaction
and enforce durability, authority and lifecycle. A checksum or typed checkpoint does
not authorize restoring a database or applying a remote decision.

The replay helper consumes an in-memory complete history. It is not a new bounded
network snapshot protocol, a generic materialized/publication format or an arbitrary
schema migration API. The test's manually installed base and removed journal rows are
fixtures for checkpoint verification, not a public journal-GC operation. No new
runtime DDL, root-library format, TLS protocol change or service boundary is introduced.

The narrow shared-code extraction follows the Karpathy guidelines: no parallel
replication engine and no bypass of reference admission checks. Generic `Node<S>`,
receipt-bearing bounded snapshots and end-to-end recovery-controller integration
remain unfinished.

## Verification

Independent inventory tests use real SQL changesets and fingerprint version 2:

- Restore two operations into encrypted Vesta; a failure on the second receipt rolls
  back application rows, journal and all receipts. Successful retry commits them.
- Checkpoint receipt hash equals the independently serialized receipt list; the
  journal chain is recomputed independently. Published receipt hashing agrees.
- Encrypted reopen preserves the typed history/checkpoint. Typed base anchoring works;
  wrong scope, prefixes below the base and changed application data are rejected.
- Changed scope, sequence, state, before/after hashes, duplicate operation IDs and
  invalid changesets cannot leave a partial committed restoration.
- Missing/mismatched/orphan receipts, impossible prefixes and pending-tail ordering
  are rejected. Prepared/Decided tails are excluded from the applied checkpoint and
  cannot satisfy quiescent or complete-prefix checks.
- A literal reference checkpoint JSON confirms the default serialization remains exact.

### Local run record (Rust 1.89.0)

- Final all-feature library, serial run: **47 passed**, no filtered/ignored cases.
- Final default-profile envelope/history tests: 11 passed, including all three new
  inventory history/checkpoint cases and the reference checkpoint JSON fixture.
- All-feature base activation 6, bootstrap 6, materialized 5, paging 6, protocol 12,
  published restore 5, receipts 3, recovery foundation 7 and snapshot staging 5 passed.
  Two recovery subprocess helpers were intentionally ignored as direct entries.
  This run preceded the final test-only additions and removal of an unused private
  wrapper; the final serial library run covers those final edits.
- Targeted real TLS snapshot bootstrap and decided-operation recovery each passed.
- Default and all-feature workspace/all-target Clippy passed with warnings denied;
  formatting, tracked diff checks and seven local documentation links passed.
  Root Cargo files, src and services have no tracked changes.

Retained failures: the first Clippy run found a private receipt-prefix wrapper left
unused by this extraction. It was removed and both lint profiles passed afterward.
A four-thread final library run passed 46 tests but failed
`network::tests::lost_stage_or_apply_ack_is_reconciled_without_duplicate`: its first
retry after restarting the peer returned 503/NotAccepted at network/tests.rs:314.
The unchanged test passed in isolation, then the entire unchanged 47-test library
passed serially. No timeout was increased and no test was removed or skipped.
This is unresolved parallel-run instability, not proof that the cause is scheduling
and not a claim of a fully green parallel suite.

No fresh full network/membership or consumer run, coverage percentage, native platform
or physical power-loss acceptance, independent security sign-off, release or deployment
is claimed for this extraction. Earlier full-workspace results belong to the preceding
peer-admission change and do not substitute for this record.
