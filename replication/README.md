# Vesta replication and recovery

Unreleased product integration, 2026-09-13. This workspace owns the implementation;
the Proximi.io prototype is a compatibility/demo consumer, not a second engine.

## Ownership and compatibility

| Crate | Responsibility | Default runtime dependencies |
| --- | --- | --- |
| Root `terrapi-vesta` (outside this workspace) | Existing encrypted-at-rest lifecycle and key slots | Unchanged; Rust 1.83 |
| `terrapi-vesta-recovery` | Strict ES256 recovery grants and encrypted immutable decision/ACK/completion journal | Vesta, SQLite, serialization, cryptography; no HTTP/TLS runtime |
| `terrapi-vesta-replication` | Two-copy commit, operation receipts, read admission, snapshot/base transfer, local recovery installation | No HTTP/async/TLS runtime by default |

The new workspace declares Rust 1.89, independently of the root and services
workspaces. It has its own lockfile. Existing root file formats and downstream
path dependencies remain unchanged. Nothing is deployed or published by this port.

## Features

- Default: storage protocol and local control journal; no fixture crash hooks.
- `mtls`: authenticated replication transport with exact peer pinning and deadlines.
- `experimental-recovery`: local/offline survivor-first replacement and mTLS membership
  checks. Does not authorize recovery automatically or enable a public operator API.
- `demo-api`: Axum/Tokio reference HTTP projections and demo binaries. **Not authenticated
  end-user APIs; do not expose publicly.**
- `test-support`: demo binaries plus process fault injection. **Never enable in deployed
  applications. Do not use `--all-features` for a release build.**

The `vesta-node` stdio executable is a crash-test harness and requires `test-support`.
The new default-build subprocess test proves that an inherited crash environment
variable cannot terminate a normal commit. The root Vesta library never depends on
either of these new crates.

## Recovery control contract

[`recovery/src/decision.rs`](recovery/src/decision.rs) is independent of the data schema.
The caller provides a nonempty passphrase and a trusted `Policy` implementation.
`Context.profile` explicitly pins issuer, audience and token type; these values must
come from trusted application configuration, never an incoming token. There is no
implicit Proximi profile. Existing Proximi fixtures select their legacy profile explicitly;
standalone recovery tests use a different application profile.

`Scope.profile` persists that trust domain and must match `Context.profile` for a new
decision. Opening an existing journal requires the same expected profile, including
historical recovery. Control-journal format is now **2**; the older experimental format
1 is rejected, not silently assigned a default issuer. This is separate from the root
Vesta encryption format and the data-node compatibility marker. There is no migration
runbook for an in-flight legacy decision: never discard its journal and allocate another
recovery against the same predecessor to bypass a format error.

`decide` verifies scope, fresh authorization, reservation/fencing evidence and both
prepared installations before persisting one immutable decision. `fetch` supplies an
opaque committed decision, not a data write permit. `acknowledge` requires authenticated
durable member evidence; a message-broker ACK is insufficient. `complete` requires both
ACKs and preserves one completion identifier. Exact historical retries do not reissue
expired grants. A committed decision is irrevocable in this protocol variant.

The management integration must supply bounded callbacks and establish independent
authority continuity, operator authentication, actual fencing and current installation
evidence. A local SQL checksum or boolean does not establish any of those external facts.

## Current data-plane boundary

[`fixed-pair/`](fixed-pair/) retains the verified **reference `places/features` schema**.
The selected direction is **custom SQL schemas through an adapter**, not a mandatory
collection/ID/JSON document model. [`schema.rs`](fixed-pair/src/schema.rs) now provides
typed schema contracts and transactional changeset capture/replay. The existing Node
write/replay paths use this layer through [`reference::Proximi`](fixed-pair/src/reference.rs);
an independent inventory schema exercises the same helpers. Root-level Proximi type
re-exports preserve existing callers and serialization.

[`typed::Node<A>`](fixed-pair/src/typed.rs) is the custom-schema Node. It uses the same
commit/reconciliation and Coordinator algorithms as the reference profile, with
typed identities, durable operation receipts and checkpoint validation. Legacy
materialized row envelopes and HTTP projections remain reference-only; arbitrary
schemas use the explicit typed interfaces, not the legacy endpoints.

[`sql_snapshot`](fixed-pair/src/sql_snapshot.rs) now implements a separate generic
application-data snapshot format: persisted scope/catalog binding, typed SQL values,
bounded pages, restartable encrypted staging and atomic verified installation.
Its operation codec dispatches on a caller-owned, already-authorized connection;
it is not a new network listener or a replacement for the reference TLS protocol.
See [SQL snapshot transfer](../docs/planning/sql-snapshot-transfer.md) for supported
schema features. [`typed::snapshot`](fixed-pair/src/typed/snapshot.rs) adds frozen
encrypted publication, receipt pages, checkpoint binding and a completion gate over
that primitive. Final application/receipt/base installation is one transaction.
Typed publication also uses one transaction: bounded data/receipt page buffers are
staged encrypted, then bound to the final manifest before commit. Failed publication
or rotation leaves no partial replacement. The wire format and quotas are unchanged;
adapter views and checkpoint validation are not yet constant-memory operations.
The shared JSON digest streams serialization into SHA-256 with unchanged bytes;
it no longer allocates an extra complete JSON buffer when hashing these views.
[`network::typed`](fixed-pair/src/network/typed.rs) exposes the typed peer commands over
the shared mTLS transport, with protocol name `vesta-typed-pair-v1` and exact scope and
schema-contract checks in both directions. It never downgrades to protocol 12.

The implemented recovery path seals a quiescent survivor, exports bounded materialized
data and receipts into an empty candidate, records the control decision on both nodes,
then activates survivor before candidate. Candidate role and membership are committed
atomically. Partial activation cannot pair with the old primary. Recovered peers require
matching persisted membership and exact certificate fingerprints. New writes still need
both copies; there is no single-copy fallback or DNS/health-based election.

For the legacy reference bridge, keep API processes stopped through both member ACKs
and completion: its admission is based on active membership. The typed bridge adds a
mandatory persisted completion gate: `typed::recovery::activate_pair` alone cannot
enable writes; `complete_pair` verifies both installations, obtains both authority ACKs
and completion, then installs local completion receipts survivor-first. Keep API processes
stopped during maintenance in either profile. These are local exclusive-handle bridges,
**not remote distributed operator RPCs**. Deployment authentication/fencing stays mandatory.

Persisted recovery DBs use compatibility marker 2 (older binaries reject them); wire
checkpoint format remains 1. TLS protocol 12 requires matching schema contracts on
requests, replies and recovery summaries; protocol 11 is rejected. No automatic downgrade,
unseal, in-place certificate rotation or recovered-base rotation is supported. The reference
bridge still permits only one replacement; the typed bridge supports successive primary
replacements with the same survivor and independently authorized decisions for each cycle.
No journal GC, production anti-rollback backend or performance guarantee is claimed.

Typed snapshots have one frozen publication and one bootstrap slot per database,
with at most 100,000 SQL rows and 100,000 receipt entries, each category bounded to
256 MiB encoded content. Page limits and supported SQL shapes are enforced, not
silently bypassed. Typed writes now preflight these limits before a new durable decision.
Explicit `rotate_snapshot(expected_manifest)` atomically replaces frozen pages without
changing membership. Subsequent typed recovery cycles retain a validated local history
and advance the survivor's `node_runtime` format to 2; older typed runtimes reject that
file. There is no automatic publication rotation, staging cancellation, history GC or
arbitrary member replacement. Restored candidates must use fresh database files.
See the [typed integration guide](../docs/planning/typed-product-integration.md).

## Verification

Run from this directory; CI uses the same explicit feature split:

```sh
cargo +1.89.0 check --locked --workspace --all-targets --all-features
cargo +1.89.0 check --locked -p terrapi-vesta-replication --no-default-features --features mtls --tests
cargo +1.89.0 check --locked -p terrapi-vesta-replication --no-default-features --features experimental-recovery --tests
cargo +1.89.0 test --locked -p terrapi-vesta-replication --lib -- --test-threads=4
cargo +1.89.0 test --locked -p terrapi-vesta-recovery
cargo +1.89.0 test --locked -p terrapi-vesta-replication --test production_features --test recovery_foundation
cargo +1.89.0 test --locked --workspace --all-features -- --test-threads=4
cargo +1.89.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.89.0 clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo +1.89.0 fmt --all -- --check
```

Loopback/network permission is required for TLS tests. Network fixture cases acquire a
test-local async mutex and run serially: the inherited concurrent harness exceeded RPC
deadlines in two large snapshot scenarios. Internal concurrency exercised by each test
is preserved; production deadlines are unchanged. No tests are skipped to hide these
failures. Serialization does not prove throughput headroom or eliminate sensitivity to
unrelated external host load. Ignored subprocess entry points are called
by parent tests with temporary fixtures; they are not skipped parent scenarios.

Current port results and remaining gates are tracked in
[`docs/planning/replication-product.md`](../docs/planning/replication-product.md).
The inherited 222-test result is baseline evidence only, not evidence for this port.
No measured coverage, independent security audit, power-loss or live FreeBSD/Linux
failure-domain validation is implied.
