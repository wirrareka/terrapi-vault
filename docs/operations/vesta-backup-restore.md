# Vesta typed-pair backup and restore qualification

Status: local stopped-pair qualification procedure. This is not a live-copy API,
deployment system, anti-rollback authority, or permission to join a restored member to a
live pair.

## Supported boundary

The qualified fixture copies each cleanly closed Vesta database together with its required
`<database>.meta.json` key-slot sidecar. Losing required key material can make the vault
unrecoverable; mismatched generations are not a qualified backup, even when an older
sidecar can still unwrap the same DEK. Do not copy a live database, omit a WAL, copy only the SQLCipher file, or
mix database and sidecar generations. The fixture refuses a DB-only copy while a nonempty
`-wal` remains; clean shutdown alone is not treated as proof of a completed checkpoint.

The test restores both members into new paths and verifies the adapter-specific view,
checkpoint, receipt set, snapshot capacity, exact old retry, conflicting retry rejection,
and normal reconciliation. The source pair is compacted first, so installed bases,
maintenance history and pre-compaction receipt retries are covered. It also checks wrong
passphrase, wrong tenant scope, truncated database and missing/damaged metadata rejection.

Root Vesta has a supported `Vesta::rotate_key` operation. Despite its historical name, it
only re-wraps the stable DEK with a new passphrase; it is not DEK rotation and does not
revoke an older backup generation containing the old metadata. It also does not rotate
mTLS certificates or change replication membership.
The qualification test exercises this only on a stopped restored copy and verifies that the
old passphrase fails while the new passphrase preserves replicated state.

## Rehearsal procedure

1. Stop client ingress, application writers and automated maintenance. Retain external
   fencing/authority evidence.
2. Resolve the pair normally. Require the same committed checkpoint on both members and
   no pending write, recovery, compaction or snapshot-transfer work. Record both member
   identities, roles, checkpoints, capacity reports and runtime/lifecycle formats.
3. Stop both node processes and close **all** Node/Vesta/SQLite connections. `Vesta::lock`
   closes its own handle and key material; it is not an application-writer lock or an
   explicit WAL checkpoint operation.
4. Require an absent/empty WAL before this test-only DB-copy procedure. Copy each database
   and its matching `.meta.json` sidecar as one inseparable backup generation.
   Refuse a DB-only procedure when a nonempty WAL remains; use a reviewed SQLite-aware
   mechanism instead of assuming that process stop checkpointed it.
   Record cryptographic hashes, file sizes, ownership, and durable storage location.
5. Restore into separate paths on an isolated host or namespace. Never overwrite the
   source files and never route production traffic to the restored files.
6. Open using the exact expected adapter, tenant/schema identity, role and passphrase.
   Compare both checkpoints, adapter views, receipt/capacity evidence and lifecycle
   metadata with the pre-backup record.
7. Reconcile only the isolated restored pair. Retry a known old operation with identical
   content and verify the original result; retry its key with changed content and verify
   rejection without state/checkpoint change.
8. If rotating the database passphrase, keep the node stopped, use the root Vesta rotation
   API, verify the old passphrase fails and repeat the complete reopen/state checks.
9. Treat promotion or joining as a separate authority-controlled operation. Local backup
   validity cannot prove that the image is newest, fence an old writer, or prevent an
   entire stale pair from being restored.

The automated fixture advances the isolated source pair after copying and verifies that the
restored clone remains at the earlier checkpoint. Writes against that temporary clone test
data integrity only; they are not production restore authority and do not prove rollback
protection. Transition-certificate-chain backup qualification remains pending typed
lifecycle integration. True DEK rotation and revocation of older backup credentials remain
explicit gaps.

## Failure rules

- Wrong passphrase, scope/schema/role mismatch, corrupt/truncated database, missing or
  damaged sidecar, incompatible format, divergent pair, or unresolved maintenance state:
  stop and preserve all evidence. Do not repair markers or delete lifecycle metadata.
- Never use a new operation ID to hide an uncertain retry outcome.
- Never interpret successful local open/reconcile as writer authorization.
- Certificate rotation is outside this procedure. Certificate fingerprints may be member
  identities and can require the authority-controlled replacement lifecycle.

## Verification commands

From `replication/`:

```sh
cargo +1.89.0 test --locked -p terrapi-vesta-replication \
  --test backup_restore_qualification
```

Linux and FreeBSD CI hooks run the same native test. Configuration in a workflow is not
evidence of execution; record the actual job URL, OS/architecture, Rust/SQLite/SQLCipher
versions, command, result and ignored-test count when qualifying a release.
