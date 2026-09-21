# Typed maintenance operations

2026-09-14. Unreleased local operator API. **Not a production deployment or a remotely
coordinated maintenance service.** Caller authentication/authorization is integration-owned.

## Implemented scope

`typed::Node::plan_compaction` inspects a consistent read transaction. It includes the
checkpoint, history head/base, role, schema contract, membership, recovery anchor,
covered journal entry count/JSON bytes, receipt count and optional frozen publication.
A valid unresolved tail is reported; corruption is an error. JSON bytes are not a
promise of reclaimed filesystem space. The plan grants no permission to write/prune.

`enable_maintenance()` is an explicit atomic opt-in. It changes node runtime 1→3 or
2→4, preserving the recovery-history meaning of the original format. Older runtimes
reject these files. Maintenance format 1 adds durable publication pins; the first
compaction atomically installs maintenance format 2, compaction state, history and a
history root. Old pin-only builds reject maintenance format 2.

Do not downgrade by editing either marker or deleting metadata. Lost or inconsistent
format/history metadata fails closed. This is not a migration for arbitrary application
schema changes. No encryption key or root Vesta file format is changed by the opt-in.

## Snapshot ownership

After publishing, use `pin_snapshot(&manifest, transfer_id)` before handing a snapshot
to a consumer. Pins persist over restart and block rotation and compaction. A transfer
ID must be unique for its owner/lifetime; do not reuse it for unrelated transfers.
Pin IDs are bounded to 128 ASCII alphanumeric/hyphen/underscore characters, and the
publication has a 1,024-pin quota. No implicit expiry or wall-clock TTL exists.

`release_snapshot_pin(&manifest, transfer_id)` is an exact-digest conditional release;
an already absent pin is an idempotent no-op. A mismatched existing pin is an error.
Release is metadata-only and can be needed after a survivor has been sealed; it does
not grant export, read, write or recovery authority. The owner must know the transfer
is finished or cancelled before release. No automatic remote transfer registry exists.

## Destination staging lifecycle

`cancel_snapshot(&manifest)` atomically discards only the exact unfinished bootstrap
on an otherwise initial secondary. Installed bases, receipts, journal entries or live
application changes prevent cancellation. A failed transaction preserves resumability;
an already empty destination is an idempotent no-op. Stop the sender first: cancellation
is not a persistent tombstone and a future authenticated begin may restart the transfer.

After successful installation, `cleanup_snapshot_staging(&manifest)` removes transfer
pages and staged SQL rows. It verifies the exact completion manifest, installed base,
live checkpoint and completed SQL progress. It preserves application data, receipts,
completion metadata and retry behavior. Repeated cleanup is safe. This API is not an
arbitrary database cleaner or authority to delete another owner's transfer.

## Receipt-preserving compaction of the original local pair

Supported: both original fixed-pair members, exclusively owned local `Node` handles,
resolved identical checkpoints, same schema/scope, maintenance enabled, no publication
pins, and a current frozen publication on each node. Already recovered memberships
are explicitly rejected. The operator API does not open a network endpoint.

Call sequence (Rust API names, not shell commands):

1. Stop concurrent application use and resolve the pair using normal reconciliation.
2. Enable maintenance on both handles. Publish a fresh snapshot, or explicitly rotate
   the existing publication only after its owners have released all pins.
3. Obtain `maintenance::compaction::plan_pair(&primary, &secondary)`. Review its cut,
   unchanged receipt count, storage accounting and expected old bases.
4. Persist the full returned plan in the operator's job record. Call
   `compact_pair(&mut primary, &mut secondary, &plan)` with that exact plan.
5. After success, inspect both checkpoints and completion state. The coordinator runs
   normal reconciliation to restore secondary read admission before returning success.

The coordinator validates all frozen page bindings, SQL content hashes and receipt
prefix hashes before closing either unprepared member. Each activation rechecks the
local cut and publication. It installs a new base and prunes only covered journal
entries in one local transaction; it never removes receipts or changes sequence IDs.

Durable phases are Prepared on both, Decided on both, Applied secondary then primary,
and Complete secondary then primary. No normal local admission while its state is
incomplete. A fresh journal revision invalidates old history cursors; membership and
its admission generation are not changed by compaction. Stored secondary readiness is
cleared and later restored through ordinary reconciliation.

## Interrupted maintenance

Open the original files with the same scope/role and supported binary. Read
`compaction_progress()` on both handles and resume the **same** persisted plan. The
coordinator handles lost replies and partial installation idempotently. Never delete
the state/history or issue a different plan to bypass an incomplete operation.

If both handles are available, retries complete the recorded phases. If a member or
required snapshot is permanently unavailable, this API does not implement abort,
replacement or cross-generation recovery of the maintenance decision. Keep writes
closed and preserve all evidence/backups. This unresolved availability case prevents
claiming the complete production lifecycle is finished.

History records are anchored to the original local base, linked across successive
cuts, checksummed and checked against the installed base/current phase. Missing prefix,
head or complete history is rejected. This is corruption detection, not an external
anti-rollback witness or permission to restore stale disks into a live deployment.

## Backup, rollout and certificates

- Back up only through a consistent Vesta/SQLite-aware process with associated metadata;
  an arbitrary copy of a live database without its WAL is not a validated backup here.
  Rehearse restore into separate files with exact tenant/schema binding before rollout.
- Keep the old binary and pre-upgrade verified backup until acceptance, but never roll
  a live pair back to older files after it accepted new writes. That requires a separate
  data-reconciliation/cutover decision, not just a binary rollback.
- Upgrade both stopped members to a compatible build before enabling maintenance.
  The local tests prove atomic marker upgrade and refusal of damaged/downgraded metadata;
  mixed-version production operation is not supported by this feature.
- Existing mTLS identity/pin configuration remains authoritative. Do not disable pin
  checks to rotate certificates. A coordinated offline certificate/configuration change
  and revalidation is required; an automated in-place certificate rotation controller
  is not implemented by this change.
- Route 53 health routing is not writer authorization. Do not direct clients to a
  maintenance-incomplete member merely because its process is healthy.

These are operating constraints, not evidence of tested deployment on FreeBSD/Linux,
certificate issuance or an implemented production backup orchestration service.

## Capacity and remaining product boundaries

The existing format caps 100,000 application rows/receipts and 256 MiB encoded content
per category. Retaining receipts preserves exact retry semantics but leaves the lifetime
receipt limit in place. Reaching it still refuses new operations, including updates and
deletes. Compaction does not solve this and must not be marketed as unbounded storage.

Still open: recovery-compatible compaction, permanently lost-member handling during
maintenance, network operator transport, bounded receipt
retention or a larger versioned capacity contract, automated schema/certificate upgrades,
and external durability/security/deployment validation. No receipt TTL has been chosen.

The attempted local-metadata shortcut for recovery anchor continuity was rejected by
tool safety review. It was not applied; existing recovery checkpoint/base validation
remains. A reviewed redesign is required before enabling compaction on recovered pairs.
