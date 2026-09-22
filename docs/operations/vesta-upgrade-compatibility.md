# Vesta typed-pair upgrade and format compatibility

Status: format inventory taken from the code in this tree. It is not a release compatibility
promise, a migration service, or evidence of tested deployment. Anything marked
**to be confirmed** was inferred rather than read directly off a check.

**Mixed-binary operation is unsupported at every level below.** Both members of a pair, and
every reader of a journal, must run the same build.

## Root Vesta (outside this workspace)

| Artefact | Values | Notes |
| --- | --- | --- |
| Key-slot sidecar `<db>.meta.json` | `FORMAT_VERSION = 1` (legacy), `CURRENT_FORMAT_VERSION = 2` | v2 is the DEK key-slot model and the only version this build **writes**. v1 is read and transparently migrated to v2 on first unlock through the normal read-write open. |
| `Vesta::open_existing_read_write_with_passphrase` | v2 only | Existing steady-state vault only. Rejects missing/non-regular database or metadata, legacy v1 or malformed metadata, any staged migration/rekey artifact, wrong passphrase. Never creates, migrates, recovers or rekeys. |
| `Vesta::open_read_only_with_passphrase` | v1 and v2 | Validates both sidecars, never migrates, opens SQLite `SQLITE_OPEN_READ_ONLY` with `query_only` retained. An interrupted legacy migration must be finished through the read-write path first. |

`Vesta::rotate_key` re-wraps the stable DEK with a new passphrase. It is not DEK rotation
and does not revoke an older backup generation. See
[backup and restore](vesta-backup-restore.md).

## Typed node runtime (`node_runtime.format`)

| Value | Meaning | Transition |
| --- | --- | --- |
| 1 | Typed node, maintenance not enabled, no typed recovery history | created at open |
| 2 | Typed node carrying validated typed-recovery cycle history | set by the typed recovery cycle path; older typed runtimes reject the file |
| 3 | Maintenance enabled on a runtime-1 node | `enable_maintenance()`: `format = format + 2` |
| 4 | Maintenance enabled on a runtime-2 node | same statement; the recovery-history meaning of the original format is preserved |
| 5 | **Pending certified maintenance** | `prepare_pair` moves 3 or 4 → 5 and records the previous value in the marker; `finalize_node` and `finish_abort` restore it |

`history_format` maps 3/4 back to the underlying 1/2 and rejects anything else with
`unsupported typed lifecycle format`. A node stuck at 5 is not openable by the ordinary
`Node::open*` path; it must be finalized or aborted.

## Maintenance metadata (`node_maintenance_format.version`)

| Value | Meaning |
| --- | --- |
| 1 | Durable publication pins only |
| 2 | Compaction state, history and history root (installed atomically by the first compaction); old pin-only builds reject it |
| 3 | Certified maintenance: compaction certificates plus the completion archive |

Accepted set is `[1] | [2] | [3]`; anything else is `unsupported maintenance format`.
Version 3 additionally requires a transition trust store (`transition trust required`) and,
outside the participant-loss path, a live `CertifiedAuthority`
(`live certified authority required`).

## Checkpoint format (`checkpoint_format.version`)

| Value | Meaning |
| --- | --- |
| 1 | Ordinary pair; no `recovery_seal`/`recovery_active` tables may exist |
| 2 | Recovery-bound database; requires `recovery_seal` |

Mismatch is `unsupported checkpoint format`. This is a database compatibility marker; it
does **not** change the wire `Checkpoint.format`, which stays 1. Restricted certified
maintenance additionally requires exactly `[(1, 2)]`
(`pending checkpoint format mismatch`) — i.e. a certified pair is a previously recovered
pair.

Persisted recovery databases also carry compatibility marker 2 (older binaries reject them).
TLS protocol 12 requires matching schema contracts; protocol 11 is rejected; the typed
protocol name is `vesta-typed-pair-v1` and never downgrades to protocol 12.

## Receipt capacity format (`receipt_format.version`)

| Value | Ceiling | Notes |
| --- | --- | --- |
| 1 | 100,000 lifetime receipts | default at create |
| 2 | 1,000,000 lifetime receipts | `upgrade_receipt_capacity`; independent 256 MiB encoded-receipt ceiling unchanged |

A legacy binary expects format 1 and rejects an upgraded file; format 1 rejects orphan
format-2 objects. Downgrade is unsupported. Snapshot format 2 carries the expanded count
contract. See [capacity format 2](vesta-capacity-format.md).

## Participant-loss install record (`recovery_loss_active`, `Installed.format`)

| Value | Meaning |
| --- | --- |
| 1 | Written before the issued successor token was stored. Still decodes; still serves the first-loss flow unchanged |
| 2 | Additionally stores the exact issued successor token, so a later loss can authenticate this recovery's founding successor **by signature** |

`serde_json` omits a skipped `None`, so format-1 record bytes are untouched by the addition.
A **second loss requires format 2**: every retired cycle row must have
`installed.format == 2` and a stored token, or `participant-loss cycle chain mismatch`.

## Pending maintenance progress (`Prepared.format`)

| Value | Meaning |
| --- | --- |
| 1 | No abort field; the node can never be in phase `aborting` |
| 2 | Adds `abort: Option<AbortLocal>` and the `aborting` phase |

Format-1 rows serialise byte-identically (the field is skipped when absent). A format-1 row
carrying an abort or the `aborting` phase is `unsupported pending phase`.

## Completion archive (`node_compaction_completion`)

| Value | Tuple | Meaning |
| --- | --- | --- |
| 1 | `(1, request.id, token_digest, completion_id)` | the authority completed this transition |
| 2 | `(2, request.id, token_digest, loss_certificate_id)` | this certificate was **never** completed; a signed participant loss authenticates it instead |

Format 2 is accepted only with a signature-anchored termination trace that accounts for
exactly that archive and a loss record naming the same loss
(`certified completion archive mismatch`). A node holding a format-2 archive refuses the
live-certified check with `certified transition was terminated by a participant loss` and
is openable only through the participant-loss path. This is part of the **not enabled**
[loss-during-maintenance](vesta-loss-during-maintenance.md) path.

## Journal formats

| Marker | Values | Notes |
| --- | --- | --- |
| Recovery control journal (`decision.rs`) | 2 | The older experimental format 1 is rejected, not defaulted. No migration runbook for an in-flight legacy decision. |
| Transition journal `journal_format` (inside the stored scope row) | absent ⇒ 1, or 2 | **One-way.** |
| `Request` (certified transition) | 1 only | `invalid transition request` otherwise |
| `MaintenanceAbort` | 2 only | `invalid maintenance abort` otherwise |
| `LossRequest` | 1 or 2 | format 2 carries `source_kind`, `abandoned_request`, `supersedes`; format 1 must carry none of them |
| `LossSuccessorRequest` | 1 or 2 | format 1 orders participants `[survivor, replacement]`; format 2 orders them `[primary, secondary]` and **must** carry `survivor_index` |
| `LossSuccessorAbort` | 2 only | `invalid loss successor abort` otherwise |

### `journal_format = 2` is one-way

The marker is written into the stored scope row in the **same transaction** as the first row
of `transition_abort`, `transition_loss_chain` or `transition_loss_successor_abort`. A
binary that predates format 2 cannot see those tables and would read a cancelled transition
as live, hand out a writer proof for an aborted successor, or treat a superseded loss as
current — so it must fail closed. It does: adding the member to the scope row breaks its
`deny_unknown_fields` decode.

A current reader enforces the marker in both directions:
`format-2 journal state without format marker`, and `transition journal format` for any
value other than 2.

**Downgrade after any abort or superseding loss is unsupported.** A journal that never
touches those three tables keeps its scope row byte-identical and stays readable by older
binaries.

## Stopped-pair upgrade rule

1. Stop client ingress, application writers and automated maintenance. Resolve the pair
   normally; require the same committed checkpoint on both members and no pending write,
   recovery, compaction, abort or snapshot-transfer work.
2. Take and **verify** a backup generation of each member (database plus its matching
   `.meta.json` sidecar, absent/empty WAL) per [backup and restore](vesta-backup-restore.md).
   Record hashes, sizes, and every format value in the tables above for both members.
3. Stop both node processes and close all Node/Vesta/SQLite handles.
4. Upgrade **both** members to the same new binary. Never run one old and one new.
5. Reopen both read-only / without admitting writes and validate: owner rows, runtime
   format, maintenance format, checkpoint format, receipt format, capacity accounting,
   schema contract, publication binding, equal committed checkpoints, and journal status.
   Run a known exact old retry and a conflicting retry and confirm unchanged behavior.
6. Only then re-enable maintenance/ingress and admit writes.
7. Keep the old binary and the pre-upgrade backup until acceptance — but never roll a live
   pair back to older files after it accepted new writes. That is a data-reconciliation and
   cutover decision, not a binary rollback.

Any format-marker mismatch, incomplete metadata set, ledger mismatch, sequence gap or
divergent pair must fail closed. Restore a verified generation; do not edit markers or
delete lifecycle metadata.

## To be confirmed

- Whether any supported path writes `node_runtime` format 2 other than the typed recovery
  cycle path.
- Whether a format-1 `Installed` record can still be *created* by this build, or only read.
- Exact older-binary behaviour on a format-2 journal has been reasoned about from the scope
  row decode; the downgrade tests named in the review record should be cited here once run.
- Root Vesta v1 → v2 sidecar migration has not been re-qualified as part of this tree.
