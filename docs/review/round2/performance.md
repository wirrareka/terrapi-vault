# terrapi-vault — performance review, round 2 (2026-05-30)

Scope: NEW hot-path / design findings **beyond** round 1
(`docs/review/performance.md` + `00-roadmap.md`). Round 1 was thorough: the SQLite
serialization choke, audit-shipper backlog cap, rate-bucket eviction, replay/tail
bounds, and the push fan-out double-query were all addressed. What remains is the
**newly-added surfaces** (metrics maps, at-rest KDF, reader pool, audit emit) plus a
couple of items round 1 did not reach.

Legend: **High** = bites under modest concurrency / has a correctness edge;
**Med** = real but bounded; **Low** = polish. These are low-QPS internal/personal
services, so most are deliberately rated conservatively — except where a correctness
bug hides behind the perf concern (4.1).

---

## 1. Audit `emit` opens+writes the chain file **per event, synchronously, on the async issuance worker** — High

**Location:** `vault-transport/src/audit.rs:247-276` (`HashChainSink::emit`);
called via `vault-broker/src/state.rs:331` (`AppState::emit`) from 10 issuance sites
in `vault-broker/src/http.rs` (`:369,441,550,653,695,726,774,808,845,899`).

**Issue.** Every credential/KMS/SSH issuance calls `state.emit(...)` **inline in the
async handler**, which:
1. `serde_json::to_vec(event)` + builds a second `RecordOut` JSON + SHA-256 — fine.
2. `OpenOptions::new().create(true).append(true).open(&self.path)` — a **full
   open()/close() syscall per event**, not a held `File`/`BufWriter`.
3. `write_all(&line)` — all while holding `state: Mutex<ChainState>`.

None of this is on `spawn_blocking`, so the open + write blocks the tokio worker for
the duration of the filesystem op, and the chain `Mutex` serializes **all** issuance
audit writes process-wide. Under a burst of issuances (sweeper teardown emits per
torn lease too — `sweeper.rs:34,50`) the open-per-event syscall cost and the single
chain lock become the serialization point of the whole broker, *after* round 1 freed
the store path.

There is also a **durability gap** hiding here: the comment says "only advance the
chain once the record is durably appended", but there is **no `f.sync_all()`** — the
write is only in the OS page cache. A crash between `write_all` and writeback loses
the tail record(s); on restart the in-memory `prev/seq` is rebuilt from the file
(`new()`), so the chain stays self-consistent, but the lost events are simply gone.
For a *tamper-evident* audit log that is the wrong default.

**Fix sketch.**
- Hold the file open: `state: Mutex<(ChainState, BufWriter<File>)>` opened once in
  `new()`; `emit` just `write_all` + `flush` (+ periodic or per-record `sync_all`,
  see below). Removes the open/close syscall per event.
- Move the emit off the runtime: either make `AuditSink::emit` fire onto a bounded
  `mpsc` drained by one dedicated blocking task (issuance just enqueues — never
  touches the disk or the chain lock), or wrap the broker-side `state.emit` in
  `spawn_blocking`. The mpsc-writer shape is cleaner: it also serializes the chain
  naturally (single consumer, no `Mutex`) and lets you batch `sync_all`.
- Decide durability explicitly: `sync_all()` per record (safe, slower) **or**
  group-commit fsync every N ms on the writer task (fast, bounded loss window).
  Document the choice next to the "durably appended" comment.

---

## 2. vault-sync metrics: two `Mutex<HashMap>` taken on **every** request — Med

**Location:** `vault-sync/src/metrics.rs:39-53` (`record_request`, locks `requests`
then `latency`); `harden.rs:49-62` (`record_metrics` middleware runs it per request);
render at `metrics.rs:108-145` locks both at scrape time. Same shape in the broker
(`vault-broker/src/state.rs:38-42,59`).

**Issue.** `record_request` acquires **two** separate mutexes per request and does two
`String` key allocations (`route.to_owned()` twice + `method.to_owned()`) for the map
lookups. At personal/fleet QPS this is not a throughput problem, but it is pure
overhead on the universal middleware path, and the two-lock pattern means the scrape
(`/metrics`) briefly contends with live traffic on both maps. The cardinality is
already bounded (MatchedPath template + method + status), so the map *set of keys* is
tiny and fixed after warm-up — which is exactly the case where a lock is the wrong
tool.

**Fix sketch.** Because the key space is small and effectively static, this is a
textbook case for a **pre-registered counter table** rather than a hot-path map
insert:
- Cheapest: keep the maps but collapse to **one** `Mutex<Inner>` holding both maps so
  it is a single lock per request (halves the acquisitions, and render takes one
  lock). Still allocates keys.
- Better: intern the route label. The route is a `&'static`-ish template from
  `MatchedPath`; build the `(route,method,status)` → `AtomicU64` / `(AtomicU64,
  AtomicU64)` table once (small, known set of routes × methods × the handful of
  statuses you actually emit) and `fetch_add(Relaxed)` on the request path — zero
  locks, zero allocation, render just snapshots the atomics. The `inflight` /
  `ops_*` counters already do exactly this; extend the pattern to requests+latency.
- If you keep maps, at least avoid the duplicate `route.to_owned()` (compute once,
  reuse for both entries) and take the lock once.

Note: this is shared between both services — a good candidate to lift into
`vault-transport` as a tiny `metrics` module so the fix lands once.

---

## 3. SQLCipher KDF cost is **open-once and bounded** — no action (with one caveat) — Low

**Location:** `vault-sync/src/store.rs:26-32` (`apply_key`), `:60-78` (`open` keys
writer + each of `readers` connections).

**Assessment.** The PBKDF2/KDF that SQLCipher runs on `PRAGMA key` happens **once per
connection at `Store::open`**, i.e. at process startup, before the server accepts
traffic. With `VAULT_SYNC_READERS=4` that is 5× KDF (writer + 4 readers) **serially**
at boot. That is acceptable: it is a one-time startup cost, off the request path, and
there is **no per-request keying** (handlers reuse the pooled connections). This is
correct and matches the broker's boot-time Argon2 (round 1 §"Other observations").

**Caveat (Low).** The 5× KDF is **serial** in the `for` loop (`store.rs:64-72`). With
SQLCipher's default 256k PBKDF2 iterations that can be ~100-250 ms each → up to ~1 s
added to startup at `READERS=4`, and it scales linearly if anyone raises the pool. If
boot latency ever matters (it gates readiness), open the reader connections in
parallel (`std::thread::scope`, key each, collect) so the KDF cost is `max` not `sum`.
Not worth doing today. **No per-request cost exists — the main question is answered:
keying is open-once.**

---

## 4. Reader-pool / writer lock scopes

### 4.1 `push` fan-out reads from a **pooled reader** right after committing on the writer — Med (correctness edge, not just perf)

**Location:** `vault-sync/src/http.rs:547-556` (push closure) →
`store.rs:push_ops` (writer) then `store.rs:pull_ops` (`with_reader`, `:309`) +
`latest_seq` (`with_reader`, `:245`).

**Issue.** Round 1's comment (`http.rs:541-546`) says it now derives the seq range
from `push_ops`' own result to avoid a *stale `latest_seq`* read — good — but the
closure still calls `pull_ops` to fetch the row bodies for the live-tail fan-out, and
**`pull_ops` runs on a round-robin pooled reader** (`with_reader`), a *different*
SQLite connection from the writer that just committed. Under WAL a separate
read-only connection is **not guaranteed to observe the just-committed transaction
immediately** (it reads at its own snapshot; visibility depends on the WAL
read-mark). The likely outcomes: the fan-out occasionally returns **fewer rows than
`accepted`** (some just-inserted ops invisible) → live-tail subscribers silently miss
ops until their next `pull`. It is not data loss (the ops are durably committed and
will come on `pull`), but it is a flaky live-tail and a confusing one to debug.

This is the deeper version of the very thing round 1 tried to fix — moving from
`latest_seq` to `pull_ops` swapped a stale *cursor* for a stale *row set*.

**Fix sketch.** Do not re-read at all (round 1's own §4 recommendation, only
half-applied): have `push_ops` **return the accepted `StoredOp`s** it just inserted
(it has every field + the assigned `seq` in hand at `store.rs:188-196`). Then the
fan-out serializes from those rows with **zero** second query, zero reader, and no
cross-connection visibility question. Removes a SELECT + base64 round-trip *and*
closes the consistency hole. If you must re-read, do it on the **writer** connection
(read-your-writes) inside the same `store_op` closure, not `with_reader`.

### 4.2 `pull_ops` does `latest_seq` as a **second** reader round-trip — Low

**Location:** `store.rs:341` (`pull_ops` ends with `let latest = self.latest_seq(...)`).

`pull_ops` runs its main SELECT on one round-robin reader, then calls `latest_seq`
which `fetch_add`s the cursor again and grabs *another* (possibly different) reader
lock + a second `MAX(seq)` query. Two reader acquisitions + two queries per pull, and
the two can land on different connections → the returned `(ops, latest)` can be
mutually inconsistent (latest computed from a newer snapshot than the rows). Fold the
`MAX(seq)` into the same `with_reader` closure as the row query (one connection, one
consistent snapshot, one lock). Minor, but it is on the pull hot path.

### 4.3 Writer-held-across-`spawn_blocking` is fine — confirmed

`store_op` (`http.rs:53-60`) wraps every store call in `spawn_blocking`, and the
`std::sync::Mutex<Connection>` is locked *inside* that blocking closure — so the lock
is held on a blocking-pool thread, never across an `.await`, and never on a runtime
worker. Correct, as the prompt anticipated. No action.

---

## 5. Broker single `Arc<Mutex<Vesta>>` serializes all store access — Med (by design; revisit only if KMS goes hot)

**Location:** `vault-broker/src/state.rs:170`; locked at `http.rs:265,416,648,690,721,764`.

**Issue.** One `Mutex<Vesta>` guards KMS wrap/unwrap, snapshot, and SSH-CA reads/writes
— all broker store operations are serialized through it. Round 1 verified the lock is
always released before any `.await` (no lock-across-await), and the snapshot `VACUUM
INTO` case was already flagged (round 1 §7). What round 1 did **not** flag: these
locked blocks also run their rusqlite work **synchronously on the async worker** (no
`spawn_blocking` around the `store.lock()` sites, unlike vault-sync's `store_op`).
KMS wrap/unwrap is AEAD-only on already-derived KEKs (microseconds — fine), and SSH
sign is in-memory Ed25519 (fine), so today nothing blocks meaningfully. The risk is
purely *future*: if any store-backed op grows a real I/O cost (large snapshot read at
`http.rs:421` already does — round 1 §7), the single mutex + on-worker execution
turns into a head-of-line block for every other issuance.

**Fix sketch.** No change needed now. When/if KMS volume or store size grows: (a) move
the store-mutex blocks to `spawn_blocking` (mirror vault-sync's `store_op`), and
(b) if read concurrency is ever wanted, give the `Vesta` the same WAL writer+reader
split vault-sync now has. Track as "do when KMS goes live", not now.

---

## 6. Allocation / serialization on push/pull fan-out — Low

**Locations:** `vault-sync/src/http.rs:570-574` (fan-out `serde_json::to_string` per
op into a `Vec<String>`); `state.rs:69-76` (`publish` clones each `String` per
subscriber while holding the `tails` map lock); `store.rs:334` / `:253` (base64
encode of every payload on every pull/fan-out).

**Issue.** Mostly round 1 §3 territory (already rated Low there), with the
fan-out clone still present: `publish` holds the `tails` `Mutex` across the whole
`tx.send(m.clone())` loop, and `tokio::broadcast<String>` additionally clones the
`String` once **per receiver** internally. So a push of K ops to N subscribers does
K×(1 + N) `String` allocations, all under the map lock. At personal scale (≤ a few
devices) this is negligible — flagging only for completeness and because the fix is
nearly free.

**Fix sketch (cheap, do alongside 4.1):**
- Switch the channel to `broadcast::Sender<Arc<str>>` (or `Arc<StoredOp>`): fan-out
  to N receivers shares **one** allocation instead of N clones. The frame is built
  once in `push`.
- In `publish`, clone the `Sender` out of the map (cheap, Arc-backed), **drop the map
  lock**, then run the send loop — don't hold the global `tails` lock across sends.
- base64 on payloads is inherent to the JSON wire format; only worth revisiting if
  you ever move the tail frames to a binary framing (out of scope).

---

## Top 5 (prioritized)

1. **(High)** `HashChainSink::emit` does an `open()`+`write_all` **per audit event,
   synchronously on the async issuance worker, under the chain Mutex, with no
   `sync_all`** — serializes all issuance audit, blocks the runtime per syscall, and
   silently drops the tail record on crash. Hold the file open in a `BufWriter`, move
   writes to a single mpsc-drained blocking task, and pick an explicit fsync policy.
   `vault-transport/src/audit.rs:247-276`, `vault-broker/src/state.rs:331`.

2. **(Med, correctness)** vault-sync `push` fan-out re-reads via a **pooled reader**
   after committing on the **writer** — WAL cross-connection visibility means the
   live-tail can silently emit fewer ops than `accepted`. Return the accepted
   `StoredOp`s from `push_ops` and fan out from those (no second query, no reader, no
   stale snapshot). `http.rs:547-556`, `store.rs:push_ops`.

3. **(Med)** Metrics `record_request` takes **two** `Mutex<HashMap>` + three `String`
   allocs on **every** request in both services, and `/metrics` contends both at
   scrape. Key space is tiny/static → replace with a pre-registered atomic counter
   table (extend the existing `inflight`/`ops_*` atomic pattern); lift into
   `vault-transport`. `vault-sync/src/metrics.rs:39-53`, `vault-broker/src/state.rs:38-71`.

4. **(Low)** `pull_ops` issues a **second** reader round-trip for `latest_seq` on a
   possibly-different connection → inconsistent `(ops, latest)` + extra lock/query per
   pull. Fold `MAX(seq)` into the same `with_reader` closure. `store.rs:309-343`.

5. **(Low)** Live-tail `publish` holds the `tails` map lock across the send loop and
   `broadcast<String>` clones per receiver. Use `broadcast<Arc<str>>` and drop the map
   lock before sending. `state.rs:48-76`, `http.rs:570-574`.

**Honest bottom line:** round 1 cleared the structural problems. Of the round-2
items, only #1 (audit emit) is a genuine new hot-path issue worth doing soon, and #2
is a real (if low-frequency) correctness edge introduced by the reader-pool split.
The rest are low-QPS polish. SQLCipher keying is open-once and clean (§3) — the
prompt's main at-rest question is a clean bill of health.
