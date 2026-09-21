# SQL schema adapter foundation

Status: implemented low-level boundary; end-to-end generic Node remains IN PROGRESS.
Date: 2026-09-13. Direction: custom application SQL schemas, as recommended before
the user's request to continue. No existing root library/service API is changed.

## Implemented

- `replication/fixed-pair/src/schema.rs`: `Schema` has typed `Change` and canonical `View`,
  an explicit immutable name/version, table allowlist, DDL, mutation and projection methods.
- `initialize` validates the descriptor before DDL and checks table existence, explicit
  non-null primary keys, foreign-key enforcement and integrity inside one transaction.
  Empty/duplicate/invalid/reserved names, views and virtual tables are rejected.
- `capture` executes in a transaction, captures SQLite changesets and rolls back. A
  failed request leaves no partial application writes. State hashes and schema identity
  accompany the resulting envelope.
- `replay` checks the schema identity, exact before-state, allowed tables, foreign keys
  and exact after-state before committing. An undeclared table makes the entire replay
  fail, even if the SQLite filter could otherwise skip it silently. Failed replay rolls back.
- `reference.rs` owns legacy Proximi entities, SQL mutations and ordered projection.
  Existing root type names are re-exported for compatibility. `Node::prepare`, staged
  validation, commit application and replay snapshot installation use the shared helpers.
  Existing protocol-level before-state checks remain in place in addition to adapter checks.
- Replay borrows the existing changeset; it does not clone the payload for the adapter.
- `RequestSchema` now separates the application's versioned request fingerprint
  from SQL state projection. It returns a fixed 32-byte digest with no permissive
  default encoding. `reference::Proximi` owns the unchanged legacy canonical
  encoding; existing Node receipts call this adapter. A compile-time assertion
  prevents accidentally changing its version while legacy receipts still require V1.
  The independent inventory adapter demonstrates that distinct ordered requests
  remain distinct even when they produce the same final SQL state.
- Journal envelopes are now `Identity<S = u32>`, `Batch<C = Change, S = u32>`
  and `Entry<C = Change, S = u32>`. Existing Node/transport callers continue using
  exactly the default reference specialization. Independent applications can
  represent typed changes with `SchemaId` without adding serialized wrapper fields.
  Content checksum and exact scope comparison use the same implementation in both
  specializations; the existing state-transition rules are not replaced.
- `journal/store.rs` is the shared internal typed journal codec used by Node's
  save, full entry listing, point lookups and tail lookup. It uses the unchanged
  `replication_log` table and JSON encoding, and checks stored sequence/operation
  keys against the decoded envelope plus its content digest. Writes reject invalid
  keys, invalid digests and a sequence already assigned to another operation.
  Generic inventory tests use this actual store, including encrypted reopen.

## Trust and transaction contract

Adapters are trusted application code, not an untrusted SQL execution facility. They
must not commit or change pragmas/DDL during mutation, write outside the table allowlist,
or perform external side effects. SQLite sessions do not capture arbitrary schema changes
or writes to tables without usable keys. The adapter owns complete deterministic state
serialization, including ordering and lossless representation of its SQL values. A view
omitting data cannot protect those omitted values. These are implementer obligations,
not properties the trait system proves.

The public helpers own their transactions and reject nesting instead of committing a
caller's transaction. Protocol-internal replay runs in its existing entity/journal/receipt
transaction. `Captured` is not authenticated authority or a durable decision: a standalone
caller must bind its schema, tenant, generation and commit decision, impose request/transfer
quotas, and manage receipts. Calling `replay` on one database is not a two-copy ACK.
The helpers do not persist/adopt a schema identity or perform migrations on the caller's behalf.

The internal journal store owns no transaction, DDL or durability configuration.
It executes its write as one SQL statement on the caller's connection, including
inside an existing transaction. The legacy `save` wrapper still inserts Applied
receipts in the same application transaction. The store does not validate chain
continuity, expected tenant/schema, membership or state transitions; those remain
protocol responsibilities. It does not introduce a public bypass for committing
raw application changes. Paging retains its existing size and revision checks.

## Compatibility and remaining work

The reference Node now enforces a [persisted schema contract](node-schema-contract.md)
covering adapter identity, request-fingerprint version and physical catalog, with an
explicit checked upgrade for pre-contract files. Its descriptor helper is generic;
the arbitrary-schema Node and peer/snapshot integration remain unfinished.

Continuation: [generic SQL snapshot transfer](sql-snapshot-transfer.md) now provides
typed rows, persisted schema/scope binding and resumable staged installation. It is
a separate application-data primitive, not yet a replacement for the legacy Node's
receipt-bearing recovery pipeline. The verification below records the earlier adapter
extraction; the snapshot continuation has its own evidence record.

The current Node, receipts and snapshot/materialized/publication/transport types
still use the reference specialization of the generic envelopes. This extraction is deliberately not advertised
as `Node<YourSchema>`. The independent SQL test validates capture/replay, not the entire
distributed recovery lifecycle for arbitrary tables. No legacy wire/checkpoint/journal
format was silently repurposed. Root Vesta remains Rust 1.83; this workspace remains 1.89.

Next integration must make application request/state/row encodings generic, persist and
bind the immutable schema descriptor to each database and every transport/snapshot scope,
preserve a legacy Proximi adapter, and run the independent schema through two-copy commit,
receipts, restart, materialized publication/restore and controlled member replacement.
Schema migration negotiation and arbitrary client SQL remain out of scope until designed.

The [typed receipt continuation](typed-receipts.md) now provides generic receipt
contents and shared internal SQL storage, also used by the reference Node. These
helpers do not constitute `Node<S>` or its complete recovery pipeline.
Existing receipt format, admission checks and checkpoint hashes stay unchanged.
The later [peer admission](peer-schema-admission.md) step requires TLS protocol 12.
Arbitrary adapters must still be connected to that same commit/recovery
pipeline before end-to-end support can be claimed. Their fingerprint versions and
schema identities still need binding across that entire lifecycle; the trait alone
does not enforce this. Local reference-Node binding is now implemented as linked above.

[Typed checkpoints and shared history restoration](typed-checkpoints-history.md)
now integrate adapter-specific receipt prefixes and complete-history replay with
the same reference implementation. These are shared local building blocks, not
an independently completed generic two-copy Node or bounded recovery pipeline.

## Verification

### Typed journal store continuation (2026-09-13)

- Shared storage is now exercised by existing Node flows, not just a standalone
  serialization fixture. Added tests cover all lookup paths, absent rows, conflicting
  sequence/operation keys, rollback of both insertion and update, malformed JSON,
  content corruption, mismatched SQL/envelope keys and rejected writes without mutation.
  Encrypted reopen now uses the actual journal store and table layout.
- All-feature core runs: library 33, paging 5, protocol 12, receipts 3 and recovery
  foundation 7 passed (60 total; two recovery subprocess helpers ignored).
- All-feature recovery/SQL runs: activation delivery 9, base activation 6, bootstrap 6,
  materialized 5, process crash 5, publication 7, published restore 5, snapshot staging 5,
  SQL schema 10 and SQL snapshot 15 passed (73 total).
- Default configuration: library 22 and production feature isolation 1 passed
  (23 total; one isolation subprocess helper ignored). Combined selected runs: 156.
- Final review additionally tightened decoding to reject an empty operation ID even
  when SQL keys and the digest agree. Six envelope/store tests were rerun in both
  configurations after this addition; the 156-test runs above predate this final guard.
- Default and all-feature workspace/all-target Clippy passed with warnings denied;
  all-feature Clippy was rerun after the final guard. Formatting and tracked diff
  whitespace checks passed. Root Cargo files, runtime and services have no changes.
- One initial default test command misspelled the package name and ran no tests;
  it was corrected before the successful default run.
- Still not a generic Node or schema-binding protocol. No full network, membership
  model, consumer, measured coverage, real power-loss or cross-platform validation
  was run in this continuation; no release or deployment is claimed.

### Typed journal envelope continuation (2026-09-13)

- Default configuration: library 19, protocol 12, receipts 3, recovery foundation 7,
  SQL schema 10 and SQL snapshot 15 passed (66 total; one recovery helper ignored).
- All features: library 30, protocol 12, receipts 3, recovery foundation 7, SQL schema
  10 and SQL snapshot 15 passed (77 total; two recovery helpers ignored).
- Three new envelope tests check literal legacy JSON and an independently computed
  SHA-256 digest, typed round-trip and legacy rejection, each scope component and
  content-field tampering, and encrypted storage reopen. The stored byte payload
  is a codec fixture, not an actual changeset or a generic recovery proof.
- The checksum still deliberately excludes Prepared/Decided/Applied state; legal
  transitions remain the responsibility of the existing durable protocol. A matching
  checksum alone does not authenticate a peer, authorize writes or validate SQL.
- All-feature workspace/all-target Clippy and formatting pass. A needless `Ok(...?)`
  in the new test was corrected without lint suppressions. An initial compile check
  preceded creation of the referenced test module and failed on that missing file.
- Root Cargo files, runtime source and services remain unchanged. No full network,
  consumer, power-loss or cross-platform suite was rerun; no release/deployment.

### Request identity continuation (2026-09-13)

- Default configuration: library 16, protocol 12, receipts 3, recovery foundation 7
  and SQL schema 10 passed (48 total; one recovery subprocess helper ignored).
- All features: library 27, protocol 12, receipts 3, recovery foundation 7 and SQL
  schema 10 passed (59 total; two recovery subprocess helpers ignored).
- New tests cover independently computed legacy SHA-256 vectors for an empty
  request and all mutation tags with UTF-8, embedded NUL and empty strings, plus
  distinct inventory requests yielding identical state and order sensitivity.
  The existing receipt golden vector and migration/corruption tests also passed.
- All-feature workspace/all-target Clippy with warnings denied and formatting passed.
  Root Cargo files, runtime and services have no tracked diff. Graph index refreshed.
- An initial test invocation used the nonexistent target `recovery`; it ran no
  tests and was corrected to `recovery_foundation` for both successful runs above.
- This continuation did not rerun the full network or workspace suites, measure
  coverage, deploy, or establish generic Node recovery support.

### Earlier SQL adapter extraction

- RED: the new SQL tests initially failed to compile because `schema` did not exist.
- GREEN: eight SQL tests pass, covering independent insert/update/delete replay, rollback,
  wrong schema/version/state, malformed/foreign-table changesets, disabled foreign keys,
  outer transaction safety, descriptor/key rejection, legacy JSON encoding and cascades,
  composite keys with NULL/empty/binary values, and two encrypted Vesta files reopened
  with distinct passphrases. Incorrect passphrase access is rejected.
- A second RED/GREEN cycle caught missing `checkpoint_` and `receipt_` reservations:
  the test reproduced acceptance of `checkpoint_format`; the fixed descriptor rejects
  both internal namespaces. Final eight-test run passed after this fix.
- Existing all-feature library/protocol/receipt/recovery regression: 27 + 12 + 3 + 7 passed;
  two recovery subprocess helper entries are ignored and invoked by parent tests.
- Other existing all-feature regressions: 158 passed — activation delivery 9, API 1,
  base activation 6, bootstrap 6, materialized 5, membership model 102, paging 5,
  process crash 5, publication 7, published restore 5, secondary 2, snapshot staging 5.
  Eight membership subprocess helpers are ignored as direct entry points and invoked
  by parent tests. That run also passed the then-six SQL tests; the final eight-test
  suite was rerun separately after its additional cases and namespace fix.
- Default crash-hook isolation: 1 passed, 1 subprocess helper ignored. Default SQL
  suite: 8 passed. Proximi consumer recovery integration: 7 passed, 2 helpers ignored.
- Default and all-feature Clippy: passed with warnings denied. Formatting, CI YAML
  syntax and touched-document local links: passed. Root Cargo manifests/lockfile,
  runtime source and services remain unchanged.

These are split local runs, not a new full-workspace/network pass. The complete 15-case
network integration suite was not rerun after this extraction; its prior passing result
is only pre-extraction evidence. No timeouts or assertions were weakened. Existing
protocol hash checks were retained alongside the new adapter checks. No measured
coverage, performance acceptance, real power-loss/FreeBSD/Linux validation, release,
deployment, or remote CI execution is claimed.
