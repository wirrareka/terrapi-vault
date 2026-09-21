# Node identity admission

Status: implemented hardening of the reference Node; UNRELEASED, 2026-09-13.
Source: `replication/fixed-pair/src/lib.rs`; regression tests:
`replication/fixed-pair/src/node_identity_tests.rs`.

## Contract

`Node::open` distinguishes creation of a missing database path from opening an
existing encrypted file, after acquiring the existing exclusive node lock.

- Existing files must contain exactly one `node_identity` row whose serialized
  identity and role equal the requested configuration. Missing tables/rows,
  duplicate rows (including identical duplicates), malformed identity and mismatched
  cluster, tenant, epoch, schema or role are rejected.
- This check runs before application schema initialization or replication metadata
  migrations. The existing later identity check is retained and now also requires
  exactly one row. No fallback inserts identity into an existing file.
- New paths retain the existing initialization sequence and serialized identity.
  Root Vesta API, SQLCipher format, replica wire protocol and receipt formats do not
  change. This identity check itself needs no identity migration. The subsequent
  [schema-contract integration](node-schema-contract.md) additionally requires an
  explicit upgrade for pre-contract Node files.
- Controlled recovery still updates the persisted role together with its activation
  record in its existing transaction. Reopening uses that persisted role; this patch
  neither grants a new role nor bypasses recovery admission.

## Compatibility and operational boundary

An encrypted Vesta file created independently is no longer implicitly adopted as a
Node. An interrupted first Node initialization that left a file without identity
now fails closed. Inspect and recover such a file explicitly; this implementation
does not delete it, reset it, invent an identity, or provide an automatic repair tool.

The root Vesta library still opens the encrypted file and establishes its normal
connection profile before Node admission. The guarantee is no Node application DDL
or protocol initialization on rejected identity, not byte-for-byte immutable file
access: underlying SQLite/WAL handling may occur during opening.

The filesystem, passphrase and exclusive ownership remain trusted. This is not
external anti-rollback protection: deletion/replacement of the entire file or a
deliberately rewritten valid identity needs independent authority/fencing controls.
It also does not yet bind an arbitrary adapter's catalog and fingerprint version
to a generic `Node<S>`; that larger integration remains unfinished.

## Verification

The initial regression run reproduced two problems: missing identity was recreated,
and an existing non-Node encrypted file was adopted. A valid exact-identity reopen
already passed. The corrected implementation rejects both cases, missing identity
tables, duplicate and malformed identities, wrong scope and wrong role.

The rejection test removes an application table as a sentinel and verifies it is
not recreated. The non-Node test checks its complete SQL catalog and user data are
unchanged. Its first version incorrectly assumed Vesta had no internal table; the
fixture was corrected to compare the before/after catalog instead of a fixed count.

Final clean runs:

- Default library: 25 passed. The three new identity tests also passed in a separate
  targeted run after correcting the catalog fixture.
- All-feature library 36, base activation 6, bootstrap 6, protocol 12, receipts 3,
  recovery foundation 7: 70 passed. Two recovery subprocess helpers are ignored as
  direct entry points and run through parent tests.
- All-feature materialized snapshots 5, process crash 5, published restore 5 and
  snapshot staging 5: 20 passed. Selected default/all-feature total: 115.
- Workspace/all-target Clippy passed with warnings denied in both profiles;
  formatting and tracked diff whitespace checks passed. Root Cargo files, runtime
  source and services remain unchanged. The replication graph index was refreshed.

The initial incorrect catalog-count assertion also failed in an all-feature run;
that run is not counted as passing. All counts above refer to the clean reruns.
No full network or membership-model suite, consumer run, deployment, production file
repair, release, coverage measurement, real FreeBSD/Linux run or physical power-loss
test is claimed for this change.
