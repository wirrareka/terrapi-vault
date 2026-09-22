# Participant loss during in-flight certified maintenance

Status: **NOT ENABLED.** Do not plan an operation around this path.

The code exists (`typed::maintenance::pending::terminate_by_loss`, `LossRequest` format 2
with `source_kind` and `abandoned_request`), but it is crate-internal, reachable only from
the crate's own tests, and the `LossPolicy` hooks it depends on are **default-deny**. An
integrator who has not written those hooks gets
`maintenance rollback evidence missing` or `maintenance finish-forward evidence missing`
and nothing happens.

## Why it exists

The ordinary [maintenance abort](vesta-maintenance-abort.md) needs proof that **both** nodes
are durably aborting. A lost member never supplies that. So an in-flight maintenance that
outlives one of its participants can only be terminated by the signed loss decision itself.
Without this path a survivor that had already applied a decided-but-uncompleted transition
is permanently unopenable (runtime 5, no completion will ever arrive, post-apply abort is
forbidden) and the only route is a backup from before the maintenance.

## The two branches

Which branch applies is decided by the survivor's **own durable phase**, and the signed loss
must agree with it. It is not a choice.

- **Rollback — the survivor has not applied** (phase `prepared` or `decided`).
  `source_kind = Completed`, `source_certificate` = the last *completed* certificate,
  `abandoned_request` = the digest of the in-flight request. Nothing was applied, so data,
  base, log, receipts and lineage are untouched. If the journal holds an open decided head
  with that digest, the loss invalidates it exactly as an abort would — revision and request
  id consumed for ever. If the request was only ever *prepared*, the journal has never seen
  it and `LossPolicy::maintenance_rollback_authorized` is the only thing that can refuse it.
- **Finish forward — the survivor has applied.** Rollback is impossible because the history
  has already been pruned. `source_kind = Decided`, `source_certificate` = the certificate
  of the **decided, never-completed** transition, `abandoned_request` = its digest,
  `source_cut` = its target. The journal requires a decided, uncompleted head with the lost
  member's ACK missing. Both `survivor_prepared` (under `Decided`) and the separate
  `maintenance_finish_forward_authorized` hook must prove, live, that the survivor durably
  **applied** exactly that transition.

Accepting a merely prepared or decided survivor on the finish-forward branch would promote
an unfinished certificate into provenance for data that was never written. That is the
failure the branch split exists to prevent.

## The format-2 completion archive

On finish forward the survivor writes, instead of a completion archive, a **format-2
archive**: `(2, request.id, token_digest, loss_certificate_id)`. It means "this certificate
was never completed; as provenance it is authenticated by the signed loss X", and it is the
opposite statement of the format-1 archive `(1, …, completion_id)`.

Consequences an operator must know:

- `verify_certified` accepts the format-2 variant **only** when this node carries a
  signature-anchored termination trace (`node_maintenance_terminated`) that accounts for
  exactly that archive, and a loss record or retired cycle row naming the same loss.
  Otherwise: `certified completion archive mismatch`.
- A node with a format-2 archive **never opens outside the loss flow**. The live-certified
  check refuses it with
  `certified transition was terminated by a participant loss`, because there is no completed
  revision at the authority and never will be. Admission rests on the live completed
  successor instead, which chains to the loss, which binds the decided certificate.
- No ACK is ever fabricated for the lost member, and the decided transition is never marked
  completed in the journal.

## What is still missing

- **The integrator adapter.** There are no production `LossPolicy` implementations for
  `maintenance_rollback_authorized`, `maintenance_finish_forward_authorized`, or
  `survivor_prepared` under `source_kind = Decided`. What is required is an adapter that
  reads the survivor's durable state read-only — phase, pending request, installed base,
  certificate — and proves the branch from it. Until that exists the path cannot be used
  even with the feature compiled in.
- **A public entry point.** `terminate_by_loss` is `pub(crate)`.

## Review status

Two independent adversarial reviews covered this area. Both concluded that the branch must
not be enabled before a set of fixes is verified. The conditions they raised, without
internal identifiers:

- an old binary must fail closed on a journal that recorded an abort or a superseding loss,
  rather than reading a cancelled transition as live;
- the finish-forward branch must have its own default-deny hook, separate from the hook
  every ordinary loss already implements;
- the two branches must be distinguishable **in the journal**, not only by which hook was
  called — an all-false acknowledgement set previously satisfied both;
- the appended loss chain must be length-bound in the same transaction that writes it, so
  deleting its last row cannot revive a cancelled replacement;
- the format-2 archive must not be authenticated by an unsigned local row; the termination
  trace must itself carry and verify the loss token by signature;
- a spent termination trace must never wedge a later, unrelated loss on the same survivor;
- retired replacement identities must be refused by the **node** as well as the journal.

Treat this document as a description of intent. Re-read the code and the review record
before any decision to enable.

## Interaction with the enabled paths

On a pair that has already been loss-recovered, certified maintenance is closed in this
release, so this situation cannot arise there. The explicit message is
`certified maintenance cannot be pending on a loss-recovered pair`.
