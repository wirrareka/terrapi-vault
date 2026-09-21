# Typed replication integration

Unreleased implementation, 2026-09-14. Supersedes the generic-integration frontier
in earlier planning notes; those notes retain their historical test evidence.

## Delivered interfaces

- `typed::Node<A>` owns the encrypted file and exclusive node lock. `A` implements
  `schema::RequestSchema`; its change type is serializable, deserializable, cloneable
  and comparable, and its view is serializable, deserializable, cloneable and comparable.
- `Identity<SchemaId>`, typed batches, entries, journal pages and checkpoints bind the
  complete cluster/tenant/epoch/schema scope. Open rejects an existing database with a
  different owner, role, initial-state digest, catalog or fingerprint contract. It does
  not adopt a reference Node file or repair missing ownership/snapshot metadata.
- `commit`, `recover` and `coordinator::Coordinator` are shared generic algorithms;
  the legacy root exports retain their defaults. `typed::Coordinator<A,R>` is the
  application-facing type alias. Schema capture/replay, receipt and checkpoint helpers
  are shared too; legacy publication/HTTP formats remain their own compatibility profile.
- `publish_snapshot`, `snapshot_page`, `begin_snapshot`, `receive_snapshot` and
  `finish_snapshot` transfer a frozen SQL state plus the complete operation-receipt prefix.
  Final SQL installation, receipt validation, base checkpoint and generation change commit
  atomically. An incomplete restore cannot stage, apply, confirm or serve a verified view.
  `begin` and `finish` support exact retries after a lost completion ACK. Reusing an
  operation ID with different content or rewriting a received page fails closed.
- `network::typed::TlsReplica<A>` implements the same Replica trait. `serve` and
  `serve_with_observer` serialize secondary mutations over TLS 1.3, certificate pins,
  absolute deadlines and bounded frames. Scope and contract are checked before dispatch
  and on replies. An observer must invalidate/publish caches before returning; its failure
  prevents ACK. `install_snapshot_from` resumes an interrupted frozen bootstrap.

## Normal application integration

Define a deterministic trusted SQL adapter and request fingerprint. Create/reopen a
primary and secondary with the same typed identity, contract and separately managed
passphrases. Use `typed::Coordinator` for application writes, not individual lifecycle
methods. A success means the operation is applied on both copies. On `WriteFailure`,
preserve `operation_id`; `Unknown` is not a rejected operation and must not be retried
under a newly allocated ID. Capabilities are recent observations, never a write lease.
The adapter initializes empty application tables; insert seed rows through replicated
writes. Initialization/execution must follow the trusted, side-effect-free schema contract.

`Node::view` is local inspection and can inspect an incomplete restoration; it is **not**
read admission. Use `verified_view` on a secondary and the Coordinator's validated view
on a primary. The typed network View command requires persisted read admission. After
bootstrap, run shared `recover` to verify the common prefix, catch up the tail and confirm
the secondary checkpoint before exposing reads. A snapshot is not membership authority.

## Controlled replacement

Member IDs in this bridge are SHA-256 leaf-certificate fingerprints. Under externally
authenticated maintenance and actual old-writer fencing:

1. Derive a plan from the verified survivor checkpoint and generation; seal the survivor.
   `publish_recovery_snapshot` accepts only that sealed, inactive survivor and rejects
   an older frozen publication whose checkpoint differs from the plan.
2. Restore into a new restricted Secondary candidate. Obtain `inspect_recovery` evidence
   from both actual installations and create the neutral authority decision using a
   trusted Policy and signed grant. No default or caller-supplied authorization boolean
   exists in the product integration.
3. Deliver the opaque `CommittedDecision` to both nodes with `record_recovery_decision`.
   The delivery binds the actual checkpoint and generation and is immutable.
4. `typed::recovery::activate_pair` fetches/revalidates the authority decision and activates
   survivor before candidate. A partially activated pair cannot accept data writes.
5. `complete_pair` checks both actual active installations, persists both authority ACKs,
   completes the authority journal and installs immutable local completion receipts.
   An interruption resumes with the same request/completion ID. Only then can the
   completed pair reconcile/write. Persisted membership and both TLS pins must agree.

Activation/completion require `experimental-recovery`. A build without it rejects
recovered data admission. The neutral authority validates grants and external policy;
this bridge adds no election, no DNS promotion, no unseal, and no single-copy write mode.
Route 53 can move traffic but cannot satisfy quorum, fencing or authority continuity.

### Subsequent primary replacement and explicit publication rotation

The typed bridge supports successive **primary replacements with the same survivor**.
After a completed recovery, construct the next baseline from `summary().membership`,
the previous plan's revision/candidate, and the survivor's current verified checkpoint
and generation. The candidate must have a fresh incarnation/certificate fingerprint.
`seal_recovery_source` checks this continuation, archives the previous active/delivery/
completion evidence, and installs the next seal in one transaction. It refuses incomplete
completion, stale baselines, reused recovery IDs and previously retired primary IDs.
An exact retry of the newly sealed plan is safe after a process exit.

The first rollover advances the survivor's `node_runtime` format from 1 to 2. Older typed
binaries reject that file; the root encryption format and wire checkpoint format do not
change. The local `recovery_cycles` hash chain is validated on open/admission and retains
old evidence. Missing prefixes/tails or damaged records fail closed. This local history is
**not** protection against restoring an entire old encrypted disk image: external authority
continuity and fencing remain required. There is no downgrade or history GC operation.

Each cycle still needs a newly scoped authority journal, signed grant, verified candidate
installation, both ACKs and completion. Do not delete/reuse an old authority journal or
discard an unfinished decision. The product adds no production authority backend.

`published_snapshot()` inspects the stored manifest without creating a publication or
granting page export. Use it to recover the expected manifest after a restart, including
when a newly sealed cycle makes the old checkpoint unexportable.

`rotate_snapshot(expected_manifest)` is a local maintenance compare-and-swap. It replaces
the current frozen publication and all pages atomically, including on a newly sealed
survivor. Quota/SQL failures retain the old publication. A changed publication rejects old
cursors and stale rotation requests. With unchanged content the manifest may be identical;
it identifies data, not a recovery generation. If a rotation reply is lost, read the current
publication and verify its checkpoint instead of blindly retrying an old expected manifest.
Finish existing transfers before rotation, or bootstrap into fresh destination files after
rotation. Exact unfinished-bootstrap cancellation and completed staging cleanup are now
available locally; see the maintenance operations contract. Rotation never grants read/write authority
and does not compact journal history or rotate an installed base in place.

After sealing the next cycle, an old publication at a different checkpoint remains
unexportable until explicitly rotated. The new candidate is restored into a fresh file;
do not reuse a prior candidate's occupied bootstrap slot. Both nodes remain write-closed
until the new `complete_pair`, and old decisions/members cannot rejoin the new pair.

## Explicit first-version limits

This implements the three previously missing integration areas, not a general-purpose
production database release. One frozen publication and one bootstrap slot per file;
100,000 application rows, 100,000 receipts, 256 MiB content per category; SQL pages up to
256 rows/1 MiB and typed wrappers up to 1 MiB + 4 KiB. Typed publication now streams
application rows and receipts into page-sized buffers and encrypted staging in the same
transaction. After calculating the manifest, it finalizes both digest bindings one page
at a time before commit. Placeholder bindings are never a committed publication; failures
roll back staging and preserve the previous publication during rotation. Wire formats
and quotas are unchanged. This removes full export/page vectors from the typed publication
path, not from the compatibility `sql_snapshot::export` API. Adapter views, checkpoint
verification and SQLite caches can still grow with the tenant; this is not an overall
constant-memory guarantee or a measured RSS claim. Finalization adds a database update
per page; disk/WAL headroom and export latency still need operational measurement.
The shared replication JSON hash now serializes directly into SHA-256 instead of
allocating a complete JSON byte vector. Its byte/digest contract is unchanged, and
serialization errors return no digest. This removes an additional serialized copy,
not the adapter's logical view or checkpoint traversal. A manual isolated debug test
of 55,000,001 generated JSON bytes measured peak RSS of 64,487,424 bytes buffered
versus 7,667,712 streamed on macOS; elapsed times were 5.01 versus 5.21 seconds.
This single-run microbenchmark is not a whole-node memory or throughput guarantee.
`typed::profile_tests` adds a test-only local encrypted-pair profiler for journal
validation, view hashing, checkpoints, commit, publication and restore. The automatic
small case checks checkpoint/data/receipt equality; the ignored manual case accepts
`VESTA_PROFILE_ROWS` (1..=10000) and `VESTA_PROFILE_HISTORY` (1..=100). Its counted
adapter records view calls without changing production behavior. Debug fixtures use
one initial batch, so increasing rows also increases the first journal record; do not
interpret the results as an isolated view-size benchmark or production latency bound.
Checkpoint journal validation no longer hashes each Applied envelope twice: expected
scope is checked locally and receipt comparison invokes the existing checksum-validating
`OperationReceipt::from_applied`. Prepared/Decided envelopes still validate their
checksum directly because they have no receipt. This is not memoization or a trusted
stored-digest shortcut; public receipt construction remains independently validating.
Receipt retention and journal verification have growth costs. Measure them against real
tenants before choosing operational thresholds. Unsupported quotas/shapes are explicit errors.
Typed nodes now check these format limits before persisting a new Prepared record on
either member and before promoting a Prepared record to Decided. The check replays the
proposed changes in a rolled-back transaction and measures the exact SQL row encoding
and prospective receipt prefix. A rejected primary prepare leaves no journal entry or
application mutation. Receipt retries do not consume additional capacity.
With no receipt GC, reaching the receipt limit rejects every new operation, including
updates/deletes; it is an explicit lifetime bound until a retention lifecycle is delivered.
`snapshot_capacity()` reports encoded application rows/bytes and receipt count/bytes;
it validates the current prefix and returns an error if it already exceeds the format.
It is a scanning maintenance/diagnostic API, not a cheap per-request monitoring probe.
The scan retains one encoded row at a time, but adapter views can still allocate a full
logical view. Admission currently scans the tenant state on both members; measure latency
before production. This is not a disk-space reservation or an overall storage quota.
Already durable Decided records from older builds remain finishable, even if oversized;
audit existing files during upgrade. Prepared records are rechecked before decision.
Do not mix versions or assume the legacy/reference Node implements this typed guard.

Local receipt-preserving compaction and explicit publication pins are now implemented
for the original fixed pair; see [maintenance operations](typed-maintenance-operations.md).
Recovered-membership compaction is explicitly refused. There is no automatic schema
migration, mixed-version rolling upgrade, receipt GC, in-place
certificate rotation or arbitrary member replacement.
The [draft retention contract](typed-retention-contract.md) separates receipt-preserving
journal compaction from a future opt-in bounded-idempotency protocol. It is not an
implemented maintenance API and selects no receipt TTL or changed client guarantee.
Snapshot export from an already activated recovery member is also deliberately unsupported;
seal the next cycle before its maintenance export. This is not a rolling backup service.
No production authority backend, remote operator API, deployment, release, security audit,
measured coverage percentage, native FreeBSD/Linux or physical power-loss certification.
Root Rust 1.83 API/file formats and the separate broker/sync services remain unchanged.

## Verification

Checkpoint duplicate-checksum removal (2026-09-14): final all-feature workspace library
**68 passed**, four manual/subprocess helpers ignored; default SQL snapshot **19**,
SQL schema **12**, recovery foundation **7**. New corruption checks passed before and
after the optimization for Applied and Prepared entries, scope/key/chain damage,
missing receipts and independent public receipt validation. Default/all-feature
Clippy and fmt passed. No full separate reference/network integration rerun is claimed.

Streaming JSON hash verification (2026-09-14): all-feature workspace library **66
passed**, two subprocess helpers ignored; default SQL snapshot **19**, SQL schema
**12**, recovery foundation **7**. Three byte-compatibility/error tests passed before
and after the change. After adding the manual profiler, the final all-feature hash
selection passed **3** tests with the profiler ignored; production code was unchanged.
Both isolated profiling modes passed with equal digests. Default/all-feature Clippy
and fmt passed. This was not a full separate reference integration suite run.

Streaming-publication verification (2026-09-14): all-feature workspace library **63
passed**, two subprocess helpers ignored; default targeted publication **3**, SQL
snapshot **19**, SQL schema **12**, production-feature boundary **1**. The library
run preceded the final affected-row guard; a subsequent targeted regression passed
both aborted and silently skipped page updates with full rollback. Default/all-feature
Clippy and final all-feature Clippy/fmt passed. No full reference integration rerun or
overall-memory benchmark is claimed. Tests cover empty publication, row/byte page
boundaries, codec parity, receipts, restart/restore and transactional finalization.

Cycle/publication hardening verification (2026-09-14): final all-feature workspace library
suite **61 passed**, default library **44**, default SQL snapshot **19**, SQL schema **12**,
recovery foundation **7**, production-feature boundary **1**. Minimal experimental-recovery
without demo/test-support passed all **6** selected typed cases, including typed TLS and
successive replacement. The final metadata-inspection addition was followed by another
full all-feature library run (61) and default rotation/metadata test (1). Default/all-feature
workspace Clippy (`-D warnings`) and fmt passed. Subprocess helpers are invoked by parents.
These focused checks do not claim a new full run of the separate reference network suite.
The new tests include a real process exit after the second seal, two completed replacements
with intervening data changes, refusal of both retired primaries, stale authority and
baseline rejection, transactional rollback, publication restart/restore and damaged lineage.

New independent-inventory tests cover encrypted reopen, shared commit/recovery, exact retry,
aborted Prepared tails, secondary-applied/primary-not-applied reconciliation, frozen snapshot
restart and catch-up, corrupted receipt rollback, closed read admission, TLS contract/pin
rejection, and signed-grant replacement through both ACKs/completion, restart and a new TLS
write. Authority booleans in the test fixture are explicitly simulated evidence, not proof
of real infrastructure fencing.

Historical integration verification on 2026-09-14 (before capacity/cycle hardening):

- Full locked workspace/all-feature run with four test threads: **284 passed, 0 failed**;
  includes all 102 membership cases and all 15 network cases (806.17 s for network).
  Ten ignored entries are subprocess helper entry points invoked by parent tests.
- Subsequently strengthened the existing typed replacement test to start with a real
  subprocess exit (73, without destructors) after secondary apply and before primary
  apply. Re-ran the complete library: **53 passed, 0 failed**, one additional ignored
  helper invoked by the parent. Production code was unchanged between these runs.
- Default library: 38 passed. Explicit default production-boundary test: 1 passed;
  recovery foundation: 7 passed; SQL schema: 12 passed; SQL snapshots: 17 passed.
- Final Proximi consumer rerun: paging 5, protocol 12, recovery foundation 7 passed.
- Default/all-feature workspace Clippy with `-D warnings`, fmt, and minimal mTLS and
  experimental-recovery test-target compilation without demo API all passed.

The CI job now includes the minimal feature builds and default unit suite. These are
local results, not a claim that hosted CI, release qualification or deployment ran.

The inherited ACK-loss test no longer imposes an unrelated 150 ms ordinary storage/TLS
budget while the suite runs KDF/I/O work in parallel: normal RPCs use 5 s, and the explicit
timeout fault delays 6 s. Dropped ACK cases and the separate absolute slow-drip deadline
test remain. Production timeout defaults are unchanged. This fixes that test's conflated
functional/performance assumption; it does not establish a production latency SLA.

An overlapping final run (4 all-feature workers plus an uncapped default-library run)
later failed 52/53 at the fixture's 10 s database-open readiness channel, before retry.
The default run passed 38/38 in 235.51 s; the failing feature run took 310.03 s. Database
open/KDF now happens before spawning the ready peer rather than inside a timed startup
channel. The ordinary RPC and injected ACK faults remain bounded. Final verification
was rerun successfully without overlapping the two expensive suites. This failure is retained here,
not counted as a pass or attributed to production protocol corruption.
