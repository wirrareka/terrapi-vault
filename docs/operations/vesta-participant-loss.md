# Vesta permanent participant loss

Status: local qualification of an experimental library path. `maintenance::loss` is public
only under the `experimental-recovery` feature. This is not a deployment system, a fencing
implementation, an authority backend, or a remote operator RPC. Verified on macOS arm64
only; see [upgrade and compatibility](vesta-upgrade-compatibility.md) for formats.

## When a loss may be declared

A participant loss is an **authority decision**, not a library observation. The library
cannot prove that a host is dead, powered off, disconnected, or destroyed, and it never
infers loss from a failed connection, a timeout, or a health check.

Before the authority signs a `LossRequest` the operator must have:

- an independent determination that the lost member is permanently gone;
- a **durable external fencing reference** for the exact lost member *and* generation. It
  is carried opaquely as `LossRequest.fencing_ref`; the journal validates only that it is
  nonzero. Proving it really fences is `LossPolicy::continuity_and_fencing`'s duty;
- the reserved authority revision and the live authority head for that revision.

A loss is never revoked. The lost member, its generation and the pre-loss membership stay
rejected for ever, across restarts and partial failures (I8).

## Preconditions on the survivor

1. The pair is **certified**: the survivor's newest durable artefact is a completed
   certified maintenance (compaction) certificate, or — for a second loss — a **completed
   format-2 loss recovery**. `validate` derives the survivor's role from that signed
   document; a survivor that is not named in it fails with `loss survivor not certified`.
2. Maintenance is **idle**. Any pending certified maintenance on the survivor is refused:
   `loss survivor has pending certified maintenance`. On a loss-recovered pair the message
   is `certified maintenance cannot be pending on a loss-recovered pair`.
3. The survivor holds a current **frozen publication** covering `survivor_cut`, produced by
   `Node::rotate_snapshot` *before* the loss is decided. There is no export guard that will
   make one for you.
4. The replacement is a **fresh, empty typed node file**, opened as `Role::Secondary` with
   the *same* `Identity<SchemaId>` as the survivor, and already carrying the **signed**
   `replacement_generation`. Wrong values fail with `loss replacement owner mismatch` /
   `loss replacement generation mismatch`.
5. Both the survivor handle and the replacement `Node` are configured with the **same**
   `TrustStore`; otherwise `participant-loss trust mismatch`.

## Sequence

Rust API names, not shell commands. Stop application writers first and keep them stopped
until the completion receipt exists on both nodes.

1. **Decide the loss.** `Journal::decide_loss(request, token, …)` on the source journal.
   Format 2 is expected for anything beyond a plain first loss. Persist the issued token
   bytes in the operator job record.
2. **Open the survivor.** `LossSurvivorHandle::open_existing(path, identity, passphrase,
   adapter, trust, journal, policy)`. The handle takes the node lock, opens SQLite
   read-only, re-fetches the loss live, and derives the survivor role internally. The role
   is never a parameter.
3. **Export / bootstrap the replacement.** `bootstrap_replacement(&survivor, &mut
   replacement, &journal, &policy)` streams `manifest()`/`page(i, …)` into the empty node
   and binds the signed `survivor_cut` and the signed `replacement_generation`. It returns
   the installed `Prefix`.
4. **Decide the successor.** `Journal::decide_loss_successor(...)` on the **successor**
   journal (a separate file, scoped to `replacement_membership`). Issue **format 2**:
   participants in canonical `[primary, secondary]` order plus `survivor_index`. A format-2
   request without `survivor_index` is rejected: `invalid loss successor request`.
   Note: format 1 (`[survivor, replacement]`, no index) still decodes, but a pair recovered
   under it carries no role information and **cannot take a further loss**.
5. **Install on the survivor.** `survivor.install_successor(passphrase, &successor,
   &authorities)`. One `IMMEDIATE` transaction on a second, private read-write connection
   to the same file. The survivor's `node_identity` row is not touched.
6. **Install on the replacement.** `install_replacement(&mut replacement, &founding,
   &successor, &authorities)`, where `founding` is `Founding::Certificate(request, token)`
   for a first loss or `Founding::Successor(successor_request, token)` for a second one.
   The lost member's role is read out of that signed document; if the lost index was 0 the
   bootstrap Secondary is promoted to Primary inside the same transaction.
   (`install_pair` does step 5 then step 6 in one call.)
7. **ACK and complete.** `complete_successor(&survivor, &replacement, &successor,
   &authorities)`. It live-reads **both** durable installs before acknowledging either
   participant, then acknowledges survivor, then replacement, then completes. The
   completion id is derived from the request, the exact token and the acknowledgements;
   it is never chosen.
8. **Record completion on both nodes.** `record_completion(&node)` on the survivor's
   ordinary `Node` (the read-write install handle must be dropped first) and on the
   replacement. Until this row exists admission stays shut with
   `participant-loss recovery not complete; data admission closed`.
9. **First write.** Reopen both nodes with `Node::open_with_completed_transition(...)` and
   perform one write through the ordinary two-copy commit path. There is no single-copy
   fallback.

## Operational constraints

- **A loss-recovered node opens only with a `CertifiedAuthority`.** `Node::open` and
  `Node::open_with_transition_trust` fail closed on such a file. Admission requires a live
  `CompletedLossSuccessorTransition` from
  `CertifiedAuthority::fetch_completed_loss_successor` *and* a matching local completion
  receipt. The default implementation of that method denies, so an authority that knows
  nothing about participant loss keeps every recovered node closed for ever.
- **Keep every issued token.** Retries bind the exact token bytes (and their digest).
  Re-minting a token for the same request is a conflict, not a retry.
- **Compaction and the other maintenance entry points are closed after a loss recovery in
  this release.** `enable_maintenance`, `plan_compaction`, `pin_snapshot`,
  `release_snapshot_pin`, `cancel_snapshot` and the typed recovery entry points all run
  `require_no_loss_recovery` and fail with
  `closed after participant-loss recovery in this release`.
- **A second loss requires format-2 successors.** The retired-cycle walk requires
  `installed.format == 2` and a stored successor token on every retired row; otherwise
  `participant-loss cycle chain mismatch`.
- **Role rule.** The survivor keeps its pre-loss role; the replacement inherits the lost
  member's role. Note: the original design doc proposed promoting a Secondary survivor to
  Primary; the S2 findings reversed that and the code implements survivor-keeps-role.
- **Identity burn.** Each recovery permanently retires the local member, generation, the
  lost member/generation, the replacement member/generation, the old membership and the
  successor membership. Reuse fails with `participant-loss identity reuse`.
- **No repair.** Every step is an exact idempotent retry: byte-identical record converges,
  anything different is a conflict (`loss install conflict`,
  `loss successor installation mismatch`, `loss decision changed`). Nothing is repaired,
  nothing is migrated, and a partial record is never completed by hand.
- The survivor file is pinned by canonical path and `(device, inode)` for the whole handle
  lifetime. Replacing it under the lock fails with `loss survivor file replaced`.

## Abort points

- **Before completion — wrong replacement.** Use the authority-signed successor abort:
  `Journal::abort_loss_successor(...)` then `survivor.abort_successor_install(passphrase,
  &successor, &authorities)`. The successor journal becomes terminal. The authority then
  issues a **superseding** `LossRequest` carrying `Supersedes { loss_certificate,
  loss_token_digest, abort_certificate, abort_token_digest }`, with a fresh
  `replacement_membership`/member/generation. The aborted replacement is discarded and
  never reused: its identities are recorded in `recovery_loss_aborted` and burnt for ever.
  Destroy its database file.
- **After completion.** There is no abort. A wrong replacement that has completed must be
  handled as an ordinary new participant loss against the recovered pair.
- **The returning lost node is permanently fenced.** Do not reconnect it, do not restore it
  from backup into the pair, and do not reuse its member id, generation or certificates.
  After `decide_loss` the source journal reports the old certified transition as
  superseded, so both old members fail `Node::open_with_completed_transition` immediately.

## Durable node tables

| Table | Meaning |
| --- | --- |
| `recovery_loss_active` | Singleton install record of the decided successor membership. Inert evidence; it never opens admission. |
| `recovery_loss_completion` | Singleton local completion receipt. Only this **plus** a live completed-successor proof reopens admission. |
| `recovery_loss_cycles` | Append-only, hash-linked history of recoveries this survivor has already been through (max 1024 rows). |
| `recovery_loss_aborted` | Append-only, hash-linked tombstones of successor memberships installed and then un-installed under a signed abort. |
| `node_maintenance_terminated` | Singleton trace of a maintenance terminated by a loss; consumed into the cycle row on retirement. Only relevant to the not-enabled path. |

## Journal tables

| Table | Meaning |
| --- | --- |
| `transition_loss` | Singleton: the first loss decided in this journal, with its token. |
| `transition_loss_chain` | Append-only superseding losses (max 4096 rows), with `transition_loss_head` as its in-transaction row counter. |
| `transition_loss_successor` | Singleton successor record of a successor journal: request, token, ACKs, completion. |
| `transition_loss_successor_abort` | Singleton authority-signed abort of that successor; makes the successor journal terminal. |
| `journal_format` | Marker inside the stored scope row. `2` is **one-way**: written in the same transaction as the first row of `transition_abort`, `transition_loss_chain` or `transition_loss_successor_abort`. |

`transition_loss_parent` (in a successor journal) carries the parent loss and the retired
identity set. A journal that never touches the format-2 tables stays byte-identical to a
format-1 journal.

## Evidence to capture

- Authority decision ids, revisions, and the **exact token bytes** for the loss, the
  successor, and any abort or superseding loss.
- The external fencing reference for the lost generation, and the record that proves it is
  durable.
- Survivor: path, canonical `(device, inode)`, pre-loss role, `survivor_cut`, publication
  manifest digest, page count.
- Replacement: path, signed `replacement_generation`, installed `Prefix`, post-install role.
- Both `recovery_loss_active` record digests and both completion receipts.
- The completion id returned by the authority, and the first successful write after it.
- Command, OS/architecture, Rust/SQLite/SQLCipher versions, and result of every test run.

## Integrator contract — `LossPolicy` hooks

These are **not** implemented by the library. Every one below defaults to deny except the
first two, which have no default at all. Quoted obligations are from
`recovery/src/transition/loss.rs`.

| Hook | Documented obligation |
| --- | --- |
| `continuity_and_fencing` | "Must consult current external authority state and prove durable fencing of the exact lost member generation. A historical signature is insufficient." |
| `survivor_prepared` | "Must authenticate the survivor fields against durable participant evidence." For `source_kind == Decided` it "**must** prove, from live survivor evidence, that the survivor durably **applied** the decided transition named by `request.abandoned_request`." |
| `loss_successor_applied` | "Live-read durable installation evidence for this exact participant. The default is intentionally deny: a decision handle is not evidence that either node installed the replacement membership." Default error: `loss successor installation evidence missing`. |
| `loss_successor_continuity` | "Check the current external authority head for the exact successor." Default error: `loss successor continuity missing`. |
| `successor_abort_authorized` | Must "prove that the replacement member and generation named by `successor` are **durably fenced** under `abort.fencing_ref`… an abort that is not backed by durable fencing leaves a live node that believes it is a member of the pair" and must "consult the **live** external authority head, not the signature." Default error: `loss successor abort evidence missing`. |
| `superseded_successor_aborted` | Must "verify, against the live successor journal of `previous_loss`, that an abort with exactly `supersedes.abort_certificate` and `supersedes.abort_token_digest` is **recorded** there… this hook is the only thing standing between a superseding loss and a replacement that was never actually cancelled." Default error: `superseded loss abort evidence missing`. |
| `maintenance_rollback_authorized` | Loss-during-maintenance only; see that runbook. Default error: `maintenance rollback evidence missing`. |
| `maintenance_finish_forward_authorized` | Loss-during-maintenance only; see that runbook. Default error: `maintenance finish-forward evidence missing`. |

`CertifiedAuthority::fetch_completed_loss_successor` must also be implemented, against the
live authority, or no recovered node ever reopens.

## What the library does not provide

Fencing, host-death detection, authority continuity, revision reservation, key
distribution, operator authentication, a network operator API, journal GC, an anti-rollback
witness, automatic retry orchestration, or any repair of an inconsistent durable record.
