# Persisted Node schema contract

Status: implemented reference-Node integration, UNRELEASED, 2026-09-13.
Sources: `replication/fixed-pair/src/schema_contract.rs`, `src/lib.rs`,
`src/node_identity_tests.rs` and `tests/sql_schema.rs` within that crate.

## Contract and admission

`schema_contract::Contract` records format 1, application `SchemaId`, the adapter's
nonzero request-fingerprint version and an exact catalog digest. The digest includes
declared table order and SQLite's stored table/index/trigger DDL, not application rows
or protocol tables. `describe` reads an actual catalog; `expected` independently
initializes the trusted adapter in an isolated in-memory database. TEMP objects and
disabled foreign keys are rejected. Custom setup required by an adapter must also
work in that isolated connection; no application-specific connection fallback exists.

Node compares the actual catalog and persisted contract against the local expected
contract **before** application initialization can conceal missing tables. New Node
files install exactly one `node_schema_contract` row. Installation uses one transaction
for table and row creation; an existing empty/corrupt table is never repaired.

Ordinary open of an existing file with no contract is rejected. Exact DDL equality
also rejects an additional application index, including a benign one. Schema changes
need a separately designed migration; this API does not negotiate them automatically.
The reference identity encoding, request digests and receipts stay unchanged. This
local binding step initially left TLS unchanged; the subsequent
[peer admission integration](peer-schema-admission.md) requires TLS protocol 12.

`Node::schema_contract()` returns a locally verified contract and fails on metadata
or catalog drift. Peer admission now carries this verified descriptor in journal
summaries and TLS envelopes; the descriptor itself is not authenticated authority.

## Explicit local pre-contract upgrade

`Node::upgrade_legacy_schema_contract(path, role, identity, passphrase)` is a local
library operation, not an HTTP/TLS route or a deployed migration command. The caller
must intentionally authorize upgrading that specific legacy file and ensure normal
exclusive ownership/fencing. No user or production database was upgraded by this task.

It requires an existing Node file, exact persisted identity/role, canonical application
DDL, valid foreign keys, a readable checkpoint/history/receipt chain and a valid primary
base before normal initialization runs. It targets the supported immediately pre-binding
Node format, not arbitrary older formats with missing history tables. A missing database,
unowned Vesta file, corrupt history or schema drift is rejected. If the contract table
already exists, it must match exactly; retry is verification, never replacement.

After the existing initialization/validation path succeeds, the contract table and row
are installed atomically. This is not an atomic rewrite of all historical initializer
migrations. An interruption before contract installation leaves the file requiring the
same explicit upgrade. Application data, receipts and checkpoint remain unchanged in
the successful migration test. The returned Node must still satisfy normal pair recovery
and write admission; migration is not an acknowledgement from the second replica.

Deletion of the entire contract table is indistinguishable from a pre-contract file to
this explicit operator API. Normal open rejects both. The operator migration must not
be used as an automatic retry or generic repair path.

## Boundaries and remaining work

Adapter semantics, fingerprint implementation, custom functions and collations are
trusted code: version and DDL hashes cannot prove those implementations equivalent.
Filesystem ownership and existing recovery authority remain required. This is not an
external anti-rollback mechanism, peer version negotiation or a rolling-upgrade guarantee;
an older binary does not enforce the new contract. Deployment/version fencing remains
outside this local metadata change.

The descriptor helper supports independent SQL adapters, but Node itself still uses
the Proximi reference specialization. Custom typed Node operations, generic receipts,
receipt-bearing snapshots still need end-to-end integration. Reference peer contract
admission is implemented separately; generic peer admission remains unfinished. This
does not finish `Node<YourSchema>` or change the root Vesta Rust 1.83 library/services.
The subsequent [typed receipt helpers](typed-receipts.md) are now shared with the
reference Node; their use throughout a generic Node lifecycle remains unfinished.

## Verification

Tests exercise explicit upgrade preserving data/receipts/checkpoint, exact reopen and
retry, missing/corrupt contract, wrong fingerprint/schema identity, physical DDL drift,
missing/corrupt history without metadata recreation, and rejection of absent/unowned files.
Independent inventory tests distinguish fingerprint versions, reject version zero,
detect added DDL while ignoring application row changes, and reject TEMP shadowing or
disabled foreign-key checks.

Verification runs (local, split suites):

- Final default library 29 and all-feature library 40 passed. Seven identity/contract
  tests were also rerun in both profiles after adding the pre-initialization history gate.
- SQL adapter 12 passed in default and all-feature profiles; SQL snapshot 17 passed
  with all features. Existing all-feature bootstrap 6, base activation 6, protocol 12,
  receipts 3 and recovery foundation 7 passed (two subprocess helpers ignored as direct
  entry points). These wider runs preceded the final history preflight/introspection
  additions; the later library reruns cover those additions.
- All-feature materialized 5, process crash 5, published restore 5 and snapshot staging
  5 passed with the history preflight in place.
- The migration test was finally extended to a real pair of local encrypted Nodes:
  two-copy commit before upgrade, explicit upgrades of primary and secondary, original
  idempotent retry and a second two-copy commit afterwards. That enhanced test passed
  separately in both profiles after the library runs above.
- Workspace/all-target Clippy passed with warnings denied in both profiles; formatting
  and tracked diff whitespace checks passed. Root Cargo files, runtime and services
  have no tracked changes. No full network/membership-model or consumer run, measured
  coverage, real FreeBSD/Linux or physical power-loss verification, release, deployment
  or user-database migration is claimed.
