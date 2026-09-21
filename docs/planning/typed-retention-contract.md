# Typed history retention — proposed contract

Status: **DRAFT, not implemented or approved as a change to client guarantees**.
Date: 2026-09-14. Applies to the new typed replication product, not root Vesta files.

## Evidence from the current implementation

- `typed::Node::completed_result` looks up a receipt by operation ID; request scope and
  fingerprint determine whether a retry returns the previous result or conflicts.
- `checkpoint::receipt_digest_from_for` requires receipts numbered continuously from
  1 through the requested sequence. `calculate_for` also checks the total receipt count.
- The typed snapshot manifest caps checkpoint sequence at 100,000. Capacity admission
  independently caps receipt count and encoded receipt bytes. Removing journal entries
  alone does not remove this lifetime operation limit.
- Installed-base receipts already support exact historical retries after bootstrap,
  but this is not a repeated live-base compaction protocol. Publication rotation alone
  does not install a new base or authorize journal deletion.

Relevant sources: [typed node](../../replication/fixed-pair/src/typed.rs),
[checkpoint](../../replication/fixed-pair/src/checkpoint.rs),
[receipts](../../replication/fixed-pair/src/receipts.rs),
[capacity](../../replication/fixed-pair/src/typed/capacity.rs),
[snapshot](../../replication/fixed-pair/src/typed/snapshot.rs).

## Recommended first increment: compact journal, retain receipts

Keep the current idempotency semantics: the same scoped key and fingerprint returns
the original result; the same key with different content conflicts. Retain all receipts,
including their key, fingerprint version/digest and original result. Never reset sequence
numbers to get under a format quota. Audit history is a separate product requirement:
receipts and a checkpoint are not a replacement for business change history.

The compaction cut is a verified quiescent checkpoint C shared by both admitted members.
No Prepared or Decided tail may cross the cut. It is maintenance, not member replacement:
it cannot change roles, grant writer authority or substitute for fencing.

Required protocol invariants, to be implemented and tested before any deletion:

1. Persist a uniquely identified maintenance plan bound to tenant/schema, current
   membership generation, expected old base and full checkpoint C on both members.
   Resolve any existing write decision first; block new writes during this first version.
2. Materialize a frozen recoverable snapshot at C with all receipts. Both members must
   durably verify and pin the exact snapshot before a compaction decision is recorded.
   Do not overwrite a publication still required by an active transfer or old recovery.
3. Persist the maintenance decision before irreversible deletion. Local activation must
   atomically install the base and remove only journal entries covered by C. Receipts
   are not deleted. Durability ACKs must describe the exact plan and installed base.
4. After a decision, crash recovery completes that same plan; it must not silently
   revert to an older base. A partially compacted pair stays write-closed and requires
   compaction-aware reconciliation, not ordinary tail replay assumptions.
5. Reopen writes only after both exact installations and durable completion are proven.
   Preserve all normal membership, admission and two-copy acknowledgement checks.
6. A stale peer below the available journal floor needs an admitted snapshot bootstrap;
   do not pretend a missing prefix is an empty log. Expired snapshot pins are released
   only through a durable transfer lifecycle, not a local wall-clock guess.

The current single publication/bootstrap slots do not implement these rules. Versioned
maintenance state, repeated base installation and pin ownership need an explicit schema
and crash-state design. Reuse shared primitives where valid; do not reuse a membership
grant as a compaction authorization. Operator authentication remains integration-owned.

This increment can reduce journal storage and repeated validation of large envelopes.
It **does not** bound receipt storage or receipt verification, lift the 100,000-operation
limit, establish audit retention, or necessarily reduce the physical SQLite file size.
Space reclamation and secure deletion are separate concerns and are not promised here.

## A separate decision: bounded idempotency

Deleting receipts under the existing request format is unsafe. Once the last record of
an old opaque operation ID is removed, an absent old key cannot be distinguished from
a genuinely new key. A digest of the discarded history alone cannot answer that lookup.
Client timestamps, changing membership epoch or a generic broker TTL do not solve it.

If bounded storage is required, propose a **new opt-in request/idempotency version** with
a server-authorized tenant-scoped generation included in request identity/fingerprint.
This is separate from the membership generation. No concrete retry duration is selected
by this draft; it requires a product decision based on offline/retry requirements.

Proposed behavior for that future version:

| Request | Result |
|---|---|
| Admitted open generation, unseen key | Normal two-copy write |
| Open generation, existing key and same fingerprint | Original result |
| Open generation, existing key and changed fingerprint | Conflict, no write |
| Closed/retired generation, even if a receipt is still physically present | Explicit expired-generation error, no execution |
| Unknown/future generation or wrong tenant | Reject, no write |
| Legacy request after a coordinated legacy-write retirement | Explicit unsupported/retired version, never reinterpret as a new request |

Both members durably close a generation and resolve all accepted operations before any
receipt deletion for it. Closure cannot revoke a durable Decided operation; complete it
first. A request racing closure is either admitted before the boundary and resolved or
rejected without being prepared. No unilateral closure during loss of the second member.

Persist monotonic retired-generation bounds and active-generation metadata in snapshots,
checkpoints and recovery, including on-prem restores. An old backup must not resurrect
an expired namespace into a live pair. Local metadata alone is not anti-rollback authority;
restore requires continuity/fencing and a compatible control-plane contract.

SDKs must retain the generation with every queued request. They must never automatically
wrap an expired retry in a fresh generation/key: that is a new operation, potentially a
duplicate business effect. The expiry error does not say whether the original operation
succeeded. Application reconciliation or an explicit new user intent is required.

This requires new receipt/checkpoint/snapshot contracts with an absolute applied sequence
and independently bounded retained receipt sets. The current contiguous receipt hash must
not be patched to silently skip missing rows. Version negotiation, migration and refusal
of old binaries must precede rollout. Legacy receipts remain retained until legacy write
admission is durably retired on both members under the agreed compatibility policy.

An authoritative receipt archive is another option, but it must preserve durable lookup
and recovery guarantees. OpenSearch/event ingestion is not automatically that authority;
moving receipts there merely moves storage, it does not make exact deduplication bounded.

## Implementation ordering and acceptance gates

1. Specify/test a non-mutating compaction plan: exact C/base/membership binding, unresolved
   tails, live snapshot pins, stale requests and conservative reclaimable-byte estimates.
   It must explicitly report that receipts and their lifetime quota remain unchanged.
2. Define maintenance state/schema compatibility and restart reconciliation. Add durable
   snapshot pins and repeated base activation; only then implement coordinated pruning.
3. Test two consecutive compactions with intervening writes, exact old retries and
   conflicting retries; restore a fresh candidate and compare data/checkpoints/receipts.
4. Fault-test before/after each durable decision, each local activation and each ACK,
   including lost replies, process exits, corrupt snapshots, disk-full errors, a stale
   secondary, active transfer, membership change and old primary return. Verify no
   acknowledged write loss, no uncertain phase accepting writes, and deterministic resume.
5. Measure checkpoint/write/restore cost after compaction. Receipt scans still count.
6. Before implementing receipt GC, explicitly choose either continued exact receipt
   retention or the opt-in bounded-generation semantics, its retry horizon and legacy
   transition policy. No automatic TTL is implied by continuing implementation work.

This document is source-backed design work, not evidence that compaction or GC works.
No runtime changes, production data operations or new test runs accompany this draft.
