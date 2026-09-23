# Vesta replication — platform qualification record

Only what was actually executed is recorded here. A build or cross-compile is never
reported as a runtime pass.

## FreeBSD 14.5-RELEASE, arm64 (local VM) — 2026-09-22/23

**Environment.** QEMU 11.1.1 with Apple Hypervisor acceleration on an Apple M1 host;
guest FreeBSD 14.5-RELEASE `GENERIC arm64`, 4 vCPU, 6 GB RAM, UFS. Tree: commit
`c34688e` (branch `vesta/replication-wip`), exported with `git archive`.
Toolchain: rustc/cargo **1.96.1** from FreeBSD packages (the pinned 1.89.0 / 1.83 do not
exist as rustup toolchains for `aarch64-unknown-freebsd`, a tier-3 target), FreeBSD
clang 21.1.8, OpenSSL 3.0.21, `llvm19` package for `libclang`.

**Limits of this evidence.** arm64, not the production architecture (amd64 templates in
`deploy/` assume FreeBSD 14.2); newer compiler than pinned; single host — no two-server
network isolation or hard-crash test; the VM shared the host with concurrent test runs.

**Build prerequisite found.** `fixed-pair` enables rusqlite's `session` feature, whose
build script runs `bindgen` and needs `libclang.so`. FreeBSD base clang does not ship it:
install an LLVM package (e.g. `pkg install llvm19`) and set
`LIBCLANG_PATH=/usr/local/llvm19/lib` on every FreeBSD build host. Without it the build
fails in `libsqlite3-sys` with "Unable to find libclang".

| Suite | Result |
| --- | --- |
| root `terrapi-vesta` (`cargo test --all-features`) | 79 + 5 + 2 passed |
| `recovery` crate (all tests + doctests) | 105 passed, 0 failed |
| `fixed-pair` `--lib` | 159 passed, 1 failed (see note 1), 8 ignored |
| `fixed-pair` integration, all 20 other files | all passed (incl. `membership_model` 102, `process_crash` 5, `backup_restore_qualification` 3, `capacity_contract` 6, `recovery_foundation` 7) |
| `fixed-pair` `tests/network.rs` | 12/15 in parallel; 14/15 single-threaded (see note 2) |

Notes:
1. `network::tests::missing_client_certificate_and_oversized_wire_frame_are_rejected`
   failed once under full parallel load (`recv_timeout(10 s)` expired while the node was
   opening — Argon2 KDF); it passes when run alone.
2. `staged_snapshot_over_wire_limit_resumes_after_receiver_restart` passed 1 of 2 isolated
   runs; the failure is always an RPC read timeout (`socket read: Resource temporarily
   unavailable (os error 35)`) with the test's 20 s per-RPC timeout, whole test 165–230 s
   on this VM. Classified **timing-sensitive, unresolved**: not proven to be a platform
   defect, not proven otherwise. The two other parallel-run failures in this file were read
   timeouts that did not reproduce single-threaded.
3. `tests/base_activation.rs::activation_preserves_records_and_recovers_with_either_side_activated_first`
   failed **once** with `WouldBlock` from the node lock when reopening a node right after
   dropping it, under heavy parallel load; it then passed 3/3 alone, single-threaded and
   5/5 full parallel runs. Unexplained; keep watching on the real FreeBSD CI host.

**Open.** Run the same suites on the amd64 FreeBSD CI VM (`runner-fbsd`). It has pkg
rustc 1.94.0 and no rustup, so `freebsd-build.yml` uses that toolchain, not a pinned one; two-server fault test (network isolation, hard crash, stale node return).

## Linux

Not executed yet (no local container runtime was available). `ci.yml` runs the workspace
on hosted Ubuntu but has not been run for this tree.

## macOS arm64 (development host) — commit `9a870c5`, 2026-09-23

Rust 1.89.0 (replication), 1.83 (root crate).

| Gate | Result |
| --- | --- |
| `cargo fmt --check`, strict Clippy `-D warnings` with and without features, `cargo check` without features, `cargo doc -D warnings` | pass |
| `cargo test --workspace --all-features --no-fail-fast` (replication) | 507 passed, 3 failed (all in `tests/network.rs`), 19 ignored |
| slow crash-matrix variants (`--include-ignored`) | 4 passed |
| root `terrapi-vesta` | 79 + 5 + 2 passed |
| `tests/network.rs` re-run twice on the idle host | 14/15, then 15/15 |

**Flaky: `tests/network.rs`.** Different tests fail on different runs
(`certificates_require_both_trust_and_exact_peer_authorization`,
`full_http_api_and_mtls_peer_binaries_survive_replica_restart`,
`staged_snapshot_over_wire_limit_resumes_after_receiver_restart`,
`paged_recovery_exceeds_whole_message_limit`), always as timeouts: fixed 250–500 ms / 10–20 s
limits in the tests versus Argon2 key derivation on every node open under load. The same
file failed the same way on FreeBSD. This is a test-harness robustness problem predating
this work (the file was unchanged by it), but it violates "the whole tree passes" and must
be fixed before the milestone is declared done.
