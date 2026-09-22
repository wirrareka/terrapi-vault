# Permanent participant loss: authority transition

Status: **implemented and locally verified.** The earlier statement that the durable
`transition_loss` schema "was rejected by the security gate and is not implemented" is
stale. The durable schema and the termination/replacement state machine exist in
`recovery/src/transition/loss.rs` and `fixed-pair/src/typed/maintenance/loss.rs`.

The fixed-pair side is public only under the `experimental-recovery` feature. Verified on
macOS arm64 only. This is not a deployment system, a fencing implementation, an authority
backend, or a remote operator API.

Operator runbook: [`docs/operations/vesta-participant-loss.md`](../../../docs/operations/vesta-participant-loss.md).

## Implemented durable semantics

A purpose-separated ES256 decision (`LossRequest`, token type
`terrapi-participant-loss+jwt`) binds the authority and revision,
installation/region/scope/schema, current membership, the source certificate and cut, the
missing member and generation, verified survivor evidence and cut, the survivor
publication, the replacement membership/member/generation, and a nonzero external fencing
reference. The trusted signing profile and keys remain externally supplied and are never
accepted from the token or from the encrypted database.

The authority journal persists one exact immutable request and token before any replacement
work, in `transition_loss` (singleton) and, for superseding losses, the append-only
`transition_loss_chain` with an in-transaction row counter in `transition_loss_head`.
Same-byte retries return the original decision; conflicting requests or re-signed tokens
fail. The missing member is never acknowledged and its absence never reopens the old pair.

Membership activation is a **separate** signed decision, `LossSuccessorRequest` (token type
`terrapi-loss-successor+jwt`), recorded in a separate successor journal file
(`transition_loss_successor`, with `transition_loss_parent` carrying the parent loss and the
retired identity set). Unlike an ordinary `Request` it may be a data no-op: both targets may
equal the survivor cut.

`LossPolicy::continuity_and_fencing` and `survivor_prepared` have no default; every other
hook is **default-deny**. Replacement completion requires authenticated applied evidence
read live from both node databases (`loss_successor_applied`) plus a fresh continuity check
(`loss_successor_continuity`). Historical certificates remain inspection-only.

Note: this section previously described the flow as a single decision. The code splits it
into the loss decision and the successor decision, in two journal files.

## Format-2 additions

All four are implemented; the last is **not enabled**.

- **Second loss on a recovered pair.** `SourceKind::LossSuccessor` lets a completed loss
  successor be the provenance a new loss is founded on. It requires format-2 successors:
  `LossSuccessorRequest` format 2 orders participants canonically `[primary, secondary]` and
  carries `survivor_index`, so the recovered pair still knows its roles. The node side
  retires the founding recovery into the append-only `recovery_loss_cycles` in the same
  transaction that installs the new one.
- **Successor abort.** `LossSuccessorAbort` (token type
  `terrapi-loss-successor-abort+jwt`) is an authority-signed cancellation of a decided
  successor, recorded in `transition_loss_successor_abort`. It is not a transition and never
  authorizes a write; it authorizes the survivor to un-install the replacement it already
  installed. The node writes a tombstone to `recovery_loss_aborted`; the aborted
  replacement's member, generation and membership are burnt for ever.
- **Supersession.** A new `LossRequest` may carry `Supersedes { loss_certificate,
  loss_token_digest, abort_certificate, abort_token_digest }`. Those last two name a record
  in a *different file* that this journal cannot open, so they are bound by nothing here
  except `LossPolicy::superseded_successor_aborted`, which must check them live.
- **Loss during in-flight certified maintenance** — `source_kind = Completed` with
  `abandoned_request` (rollback) or `source_kind = Decided` (finish forward, writing a
  format-2 completion archive). **NOT ENABLED**: crate-internal entry point, default-deny
  hooks, review fixes required. See
  [`docs/operations/vesta-loss-during-maintenance.md`](../../../docs/operations/vesta-loss-during-maintenance.md).

Format-1 requests re-serialise to exactly their format-1 bytes (skipped `None` fields), so
every stored digest and token binding stays valid.

## One-way journal format marker

The first write to `transition_abort`, `transition_loss_chain` or
`transition_loss_successor_abort` burns `journal_format = 2` into the stored scope row in
the same transaction. An older binary cannot see those tables and must fail closed; it does,
because the added scope member breaks its `deny_unknown_fields` decode. Downgrade after that
point is unsupported. A journal that never touches those tables stays byte-identical.

## Threat and operational boundary

The library cannot establish fencing, leases, host death, authority continuity, or a
current monotonic revision. A production integration must reserve the new revision, durably
fence the missing generation, authenticate survivor and replacement evidence, and reject
restored/stale authority state. Local checksums, encrypted storage, signed historical
tokens, or caller booleans are not substitutes.

The threat model for a node's local file is "rollback/swap", not "arbitrary overwrite".
Unsigned local histories are therefore tamper-evident only; every decisive piece of
evidence — including the maintenance termination trace — is verified by signature.

## Crash and retry invariants

- Before durable authority decision: no membership mutation.
- After decision but before replacement apply: old pair remains closed; exact retry.
- After replacement apply but before authority completion: admission remains closed.
  An install-only `CommittedLossSuccessorTransition` can never open admission; only a live
  `CompletedLossSuccessorTransition` plus matching local completion evidence can.
- After completion: exact completion retry succeeds; conflicting completion fails. The
  completion id is derived from the request, the exact token and the acknowledgements, never
  chosen.
- Reopen re-verifies the exact signature using externally supplied historical keys.
- Missing/corrupt record, stale revision, changed fencing reference, wrong survivor,
  wrong generation, or wrong source certificate fails closed.
- No path fabricates the missing participant ACK or clears it to resume the old pair.
- An aborted successor's identities, and every identity a completed recovery burns, are
  refused by both the journal and the node for ever.

## Verified scenarios

1. Valid survivor evidence, fencing, replacement install, completion, and reopen.
2. Lost member replies at decision, apply acknowledgement, and completion.
3. Conflicting/re-signed tokens and request-field mutation.
4. Missing/corrupt records and SQL rollback at every durable boundary.
5. Stale authority revision, failed continuity, absent fencing, wrong member or
   generation, wrong source certificate/cut, and untrusted signer.
6. Historical certificate can be inspected but cannot authorize a new transition.
7. Old pair never regains admission, including after restart or partial failure.
8. Second loss on a recovered pair; successor abort followed by a superseding loss.
9. Crash/retry matrix per durable boundary (two matrices are `ignored` by default; a
   release gate must run `-- --include-ignored`).

Record the exact command, OS/architecture and toolchain versions for each run. A local pass
is not remote key distribution, hardware-backed signing, Linux/FreeBSD runtime behavior, or
production fencing.
