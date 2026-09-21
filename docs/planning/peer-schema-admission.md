# Replication peer schema admission

Status: implemented and regression-verified, UNRELEASED, 2026-09-13.

The reference Node now exports its verified application schema contract in every
journal summary. Recovery compares the primary and secondary contracts before
journal paging, checkpoint confirmation, abort, stage or apply. Missing contract
fields are deserialization errors, not a request to assume the legacy contract.

TLS protocol **12** requires the contract in both request and reply envelopes.
The secondary validates the request against its persisted, locally verified
contract before dispatch. The client compares the reply with the contract derived
from its trusted reference adapter. Matching TLS certificates alone cannot make
a mismatched contract acceptable. Protocol 11 is rejected; update both members
of an experimental pair together. No rolling mixed-version mode or downgrade is
implemented. Existing databases with valid local schema contracts need no new
database migration for this wire change.

The equality covers contract format, schema name/version, fingerprint version and
exact application catalog digest. It is not proof of adapter code equivalence,
writer authority, physical fencing, independent durability or absence of a malicious
authenticated peer. Scope, membership, TLS pins and existing commit/recovery checks
remain mandatory and unchanged.

This closes peer contract admission for the **reference runtime**, not generic
`Node<S>`. Typed journal/receipt helpers and generic SQL snapshots remain foundations
whose complete lifecycle integration is still unfinished. Root Vesta, broker, sync,
services and deployed coordination contracts are not changed.

## Tests

- Five contract-field mismatches reject recovery before any journal page or state
  change; restoring the matching contract recovers a pending decision and equal receipts.
- Invalid/missing contracts and protocol 11 cannot reach a network abort mutation.
- Contract metadata damaged after open fails summary and network admission.
- Even an authenticated TLS peer cannot acknowledge a request with a mismatched,
  missing or old-version reply envelope.

## Verification record

Local Rust 1.89.0 runs, 2026-09-13:

- All-feature library 43, paging 6 and protocol 12 passed; the subsequently added
  authenticated-reply negative test passed separately (one test). Runtime code was
  unchanged by that final test addition.
- Default library 31, production feature isolation 1, SQL adapter 12 and SQL
  snapshot 17 passed. One subprocess helper is intentionally ignored as a direct entry.
- Proximi consumer paging 5, protocol 12 and recovery foundation 7 passed; two
  recovery subprocess helpers are intentionally ignored as direct entries.
- Default and all-feature workspace/all-target Clippy passed with warnings denied.
  Formatting and tracked diff checks passed; root Cargo files, src and services
  have no tracked changes. Seventeen local documentation links were checked.
- The full all-feature workspace run completed successfully (exit 0), including
  all 102 membership/recovery tests and all 15 network cases without filtering or
  retry. The network suite completed in 796.74 seconds. Eight membership and two
  recovery subprocess helpers remain intentionally ignored as direct test entries.
  Publication crash/retry, published restore, receipt, secondary, snapshot staging,
  SQL adapter/snapshot suites and doctest targets also passed. This full run compiled
  before the final test-only authenticated-reply addition; that additional test passed
  separately, as recorded above. No runtime implementation changed after compilation.

No coverage percentage, native FreeBSD/Linux acceptance, physical power-loss result,
independent security sign-off, release or production deployment is claimed.
