# Vesta replication product integration

> The custom-schema Node/snapshot/network/recovery integration is now implemented.
> See [typed product integration](typed-product-integration.md) for current interfaces,
> verification and operating limits. The frontier and test records below are historical.

Status: IN PROGRESS, 2026-09-13. User request: integrate the Proximi.io Vesta/replication/recovery foundation into Vesta as a reusable product.

## Compatibility boundaries

- Preserve the root `terrapi-vesta` crate, its Rust 1.83 contract, existing encrypted file formats and downstream applications.
- Keep fixed-writer synchronous replication distinct from personal `vesta-sync` and the secrets broker. No production deployment or existing service/API changes.
- Keep application-specific `places/features` outside the neutral product API. Separate schema execution, canonical state and snapshot rows from the replication protocol.
- Retain receipts, bounded snapshot transfer, persisted read admission, two-copy commit, encrypted control decisions, explicit recovery activation and exact peer membership.
- No automatic failover authorization from DNS/health checks; no default permitting recovery policy; no claim that local journals establish independent authority continuity or physical fencing.
- Existing untracked TLS fixture files in the repository belong to the user and are not read, changed or removed.

## Implementation and verification frontier

1. Inspect existing Vesta contracts and extract a dependency-neutral ownership layout. Obtain scoped write permission for this repository.
2. Move the reusable implementation and tests into Vesta-owned crates; preserve the root library MSRV and default dependency footprint.
3. Separate application schema from the replicated storage protocol, retain a Proximi-compatible adapter for regression evidence, and exercise another independent schema.
4. Remove production-accessible fixture crash switches; isolate test harnesses and credentials. Keep experimental recovery explicit until deployment trust prerequisites are fulfilled.
5. Point the Proximi prototype at Vesta's single implementation, avoiding two independently maintained engines.
6. Run existing library tests, replication/recovery regressions, feature checks, Clippy and formatting. Document exact results and any environment/deployment limitations; update product documentation and coordination boundary notes where relevant.

The inherited foundation had 222 distinct feature-enabled parent tests passing across split runs, with one parallel snapshot timeout that passed unchanged in isolation. This is baseline evidence, not evidence for the port. The port needs its own verification.

## Current implementation status

- Vesta owns `replication/recovery` and `replication/fixed-pair`; the Proximi prototype is a path-dependency facade. Sixteen implementation files were moved, with their implementation retained in Vesta and documentation links redirected.
- The root `Cargo.toml`, `Cargo.lock`, `src/` and `services/` are unchanged. Existing root library tests passed on Rust 1.83 (74 tests). New workspace all-target/all-feature compilation passed on Rust 1.89; it is pinned independently.
- Recovery verifier accepts an explicit trusted application profile, persisted in `Scope`; the new control-journal format 2 rejects the old unbound experimental format. No implicit Proximi trust domain, permissive policy, or automatic migration of an in-flight decision.
- Default replication/recovery dependency trees contain no HTTP/async/TLS runtimes. `mtls`, `demo-api`, `experimental-recovery`, and dangerous `test-support` are explicit features. A default-build subprocess test passed with an inherited crash variable ignored.
- Added six passing standalone recovery tests using an independent application profile, including persisted trust-domain binding and rejection of the old control-journal format.
- The first port regression passed 169 tests before a large staged-snapshot test exceeded its socket deadline (another large snapshot had been excluded based on the inherited timing failure). This failed run is retained as evidence. All 15 network cases now serialize via a test-local Tokio mutex; internal concurrent scenarios and production deadlines are unchanged. The complete network rerun passed all 15 cases without exclusions in 877.82 seconds; CI no longer excludes any network case.
- Both default and all-feature Clippy profiles passed on Rust 1.89 after the final scope-format binding change, with warnings denied.
- Root README, changelog and CI now expose the new workspace as UNRELEASED. No release, deploy, production keys or live service contracts changed. Existing unrelated untracked TLS fixture files are preserved.

## Port verification record — 2026-09-13

These are split local runs, not a claim of one final clean full-workspace run. Counts overlap where a suite was intentionally repeated under another feature profile or in the consumer.

| Check | Result |
| --- | --- |
| Unchanged root library, Rust 1.83 | 74 passed |
| New workspace all-target/all-feature check, Rust 1.89 | Passed |
| Complete serialized network suite, all features | 15 passed; no ignored or filtered cases |
| Final journal, paging, process-crash, protocol, publication, published-restore, receipts, recovery-foundation, secondary and snapshot-staging suites | 57 passed; two recovery subprocess helpers ignored by the parent harness |
| Final strict recovery-grant negative matrix | 8 passed; other model tests filtered |
| Final default-feature crash-switch isolation and recovery foundation | 1 + 7 passed; subprocess helper entries ignored |
| Final Proximi consumer recovery foundation | 7 passed; two subprocess helper entries ignored |
| Default and all-feature workspace Clippy, `-D warnings` | Both passed |
| Vesta and Proximi workspace formatting | Both passed |
| All-feature documentation tests | Passed; zero doctests present |
| CI YAML syntax and local Markdown targets | Valid; 195 local links resolved |

The network rerun preceded the final control-journal scope binding; the final recovery, grant, default-feature and consumer runs exercised that binding. The earlier 169-pass run stopped on the network timeout and is not final aggregate evidence. No coverage percentage was measured. CI was configured but not executed remotely. FreeBSD/Linux deployment, physical power loss, independent security review, and performance acceptance remain unverified.

The extraction deliberately preserves the existing root API and separates optional runtime dependencies; it does not silently redefine the application data model. Codebase indexes were refreshed after the move. No production readiness or universal-schema completion is claimed.

## SQL adapter continuation

Proceeding with the announced recommended direction after the user's continuation:
**custom SQL schemas through an adapter**. No further document-versus-SQL choice is
blocking this work. The typed capture/replay layer is implemented and the reference
Node uses it; an independent inventory schema verifies the same low-level operations.
The preceding table records the port before this extraction, not its new regression run.

See [SQL adapter implementation and verification](sql-schema-adapters.md). Full generic
Node envelopes and receipt-bearing recovery integration are still pending. The separate
[generic SQL snapshot transfer](sql-snapshot-transfer.md) now supplies durable staging,
typed rows and bounded operation codecs; it does not change the legacy TLS endpoint.
Physical authority
continuity, fencing, remote operator transport and real failure-domain/platform testing
remain deployment gates. Do not claim a completed universal database product.

## Peer compatibility continuation

[Reference peer schema admission](peer-schema-admission.md) now compares verified
contracts before recovery mutations and requires matching request/reply contracts
under TLS protocol 12. Old protocol 11 peers are rejected, not silently downgraded.
This is an unreleased replication-workspace boundary, not a change to deployed
broker/sync services or existing root database formats. See the linked record for
fresh regressions; the earlier port verification table remains historical evidence.
