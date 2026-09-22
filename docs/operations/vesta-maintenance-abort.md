# Vesta certified-maintenance abort

Status: local qualification. The abort path is crate-internal
(`typed::maintenance::pending`, `pub(crate)`); it is exercised by in-crate tests and has no
public operator API in this release. This is not a remote operator RPC, a scheduler, or an
authority backend. Verified on macOS arm64 only.

## What this aborts

A certified maintenance (compaction) transition that is durably **PREPARED** on both nodes,
or **DECIDED but not applied**. The usual cause is an expired issuance token: without an
abort the pair can neither finish nor re-issue, and both nodes stay unopenable — runtime
format 5 with no route forward.

**Cannot be aborted:** a transition either node has **applied**. Its history has already
been pruned, so rollback is impossible. A completed transition is likewise final.
If exactly one member is permanently lost, this procedure is unusable by construction —
`Journal::abort` requires proof that **both** nodes are durably aborting, and a lost member
will never supply it. See [loss during maintenance](vesta-loss-during-maintenance.md).

## Preconditions

1. Both node processes stopped, application writers stopped, both files reachable, both
   restricted handles openable with the same scope/identity/passphrase.
2. Inspect each node first with `peek_pending(path, &identity, passphrase)`. It returns
   `PendingSummary { role, phase, request }` and performs **no** authority verification: it
   proves only that the marker, the progress record and the owner row agree.
   A node without pending maintenance fails with
   `node has no pending certified maintenance`.
3. Both nodes must report the same `request`, roles Primary and Secondary, and phase
   `prepared` or `decided` — identically. `abort.decided` must equal
   `(phase == "decided")`, or `invalid pending abort transition`.
4. An authority-signed `MaintenanceAbort` (format 2) whose `aborted_request`,
   `aborted_request_id`, `aborted_revision`, `authority_id`, `install`, `region`, `scope`,
   `schema`, `membership` and `source_anchor` match the pending request exactly. Mismatch:
   `pending abort binding mismatch`.

### Validity window of a never-decided abort

For a request that was **never decided**, the abort must take `last_revision + 1` with
`decided == false`, and is "only issuable while `last_revision + 1` is still the revision
the abandoned request was prepared for". Nothing can consume a revision in between except a
participant loss, and a loss that lands first makes this abort permanently unissuable; the
pair must then use the loss's own rollback branch.

An open decided transition must be cancelled on **its own** revision, never stepped over.

## Sequence

1. `begin_abort(&mut handle, &abort, token, now, &trust)` on **each** node. This verifies
   the token freshly, binds it to the durable request, and moves the node to phase
   `aborting`. It is **one-way**: from here no call can reach apply, acknowledge or
   complete. An exact retry converges; a different abort is `pending abort conflict`.
2. `abort_authority(&primary, &secondary, &journal, &abort, token, now, &trust, &policy)`.
   The journal records the abort only once **both** nodes are durably aborting on exactly
   this abort with the pending runtime still in place; otherwise
   `pending node is not aborting`. The nodes must be Primary and Secondary of the same
   identity and request, or `pending abort pair mismatch`.
   `Policy::abort_applicable` runs first and still gates on the live authority head.
3. `finish_abort(&mut handle, &journal, &trust, &policy)` per node — **secondary first**
   (`abort_pair` does exactly that order). Each call re-fetches the committed abort, checks
   it against the local `AbortLocal` record (`pending abort proof mismatch`), then in one
   transaction drops `node_pending_certified_progress` and
   `node_pending_certified_maintenance` and restores `node_runtime` from 5 to the recorded
   previous format (3 or 4). Failure: `pending abort runtime restoration failed` /
   `pending abort post-state mismatch`. The rolled-back node must pass the ordinary
   owner-level open validation inside that same transaction.
4. The pair is an **ordinary** certified pair again. The effective journal head reverts to
   the last record that actually completed, so `fetch_completed` on that certificate
   succeeds again and both nodes reopen on evidence they already hold.
5. **Readiness is not restored.** `replication_readiness` stays cleared by design; the
   secondary re-confirms its checkpoint through ordinary reconciliation before read
   admission returns. Run a normal resolve before admitting clients.

## Revisions after an abort

The abort **consumes** `aborted_revision` for ever. The revision is never reused and the
cancelled request id can never be decided again. Therefore `Status::last_revision` is
strictly greater than the revision of the effective head, and the gap grows with every
abort. `Policy::continuity` must accept that: an implementation that requires
`request.revision == authority.reservation` "will reject every post-abort read and brick the
pair". The next `decide` must use `last_revision + 1` while chaining its `old_base` to the
effective head.

## Crash and retry

- Crash between step 1 and step 2: re-run `begin_abort` with the **same** token bytes; it
  converges.
- Crash after the authority recorded the abort but before rollback (window C2): an exact
  retry of `Journal::abort` deliberately does **not** re-check the token's validity window,
  so resuming with the by-then expired token works. Keep the token.
- Crash between the two `finish_abort` calls: the other node finalizes on its own with the
  same call.
- `finish_abort` on an already finalized handle only re-fetches the abort and returns.

## Keep the abort token

Every retry binds the exact abort token bytes and their SHA-256 digest
(`AbortLocal.abort_token_digest`). Re-minting an abort for the same request is a conflict,
not a retry. Store the token with the job record before step 1.

## Journal effects

The first recorded abort creates `transition_abort` and burns the one-way `journal_format`
marker into the stored scope row. An older binary then fails closed on that journal
(`format-2 journal state without format marker` from a current reader; an older binary
fails while decoding the scope row). Downgrade after that point is unsupported.

`Journal::abort` is rejected in a successor journal.

## Evidence to capture

- `peek_pending` output for both nodes before and after: role, phase, request id, revision.
- The abort id, `aborted_revision`, `decided`, the exact token bytes and its digest.
- `Status { request, acknowledgements, completion, last_revision, aborted }` before and
  after the authority step.
- `node_runtime` format on both nodes before (5) and after (3 or 4).
- The reconciliation result that restored secondary read admission.

## What the library does not provide

Authority head/reservation management, token issuance or renewal, a public operator API for
this flow, proof that no node applied the transition (that is
`Policy::abort_applicable`'s duty — default error: `maintenance abort evidence missing`),
rollback of an applied transition, or any repair of a half-rolled-back node.
