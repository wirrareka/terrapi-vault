# terrapi-vault — performance review

Scope: `services/{vault-broker,vault-sync,vault-transport}` + root SQLCipher lib (`src/`).
These are low-to-moderate-QPS internal services (mTLS fleet broker; personal multi-device
sync). The design is sound; most findings below are about hot-path async hygiene and
unbounded in-memory maps rather than algorithmic problems. Severity reflects realistic
internal load, not public-internet scale.

Legend: **High** = will bite under modest concurrency or over time; **Med** = real but
bounded; **Low** = correctness-of-design / cleanliness.

---

## 1. Blocking SQLite under a `std::sync::Mutex` on the async runtime (vault-sync)

**Impact: High** (it is the central serialization point of the whole service)
**Location:** `services/vault-sync/src/state.rs:19` (`store: Arc<Mutex<Store>>`);
every handler in `services/vault-sync/src/http.rs` (`:174, :210, :248, :276, :308, :377,
:392, :435, :452`).

**Issue.** A single `rusqlite::Connection` lives behind one `std::sync::Mutex`. Every
`push`/`pull`/`status`/enrol call locks it and runs SQLite synchronously *inside the async
handler* on a tokio worker thread. Two compounding problems:

1. **All sync traffic across all vaults is serialized** through one connection + one mutex.
   A `pull` that scans/serializes a large op batch (`pull_ops`, `store.rs:225`) blocks every
   other device's request for its full duration — there is no per-vesta or reader
   parallelism.
2. **It blocks the runtime.** SQLite I/O (and base64 encode of every payload in
   `pull_ops`, `store.rs:253`) runs on the worker thread without `spawn_blocking`. Under a
   handful of concurrent devices doing large pulls this starves *other* async tasks
   (including the live-tail WS sends) on that worker.

There is also a latent deadlock-shaped foot-gun: `push` locks the store twice in sequence
(`http.rs:377` then `:392`) — fine today because each lock is released between, but it means
two SQLite round-trips + two lock acquisitions per push.

**Fix.** Two independent moves, do both:

- Move blocking DB work off the async threads. Cheapest: wrap each store call in
  `tokio::task::spawn_blocking`. Cleaner: give `AppState` a small dedicated DB executor
  (a `tokio::sync::Mutex<Store>` is *not* the fix — it still serializes; the point is to
  not hold the runtime thread). Sketch:
  ```rust
  // state.rs
  pub async fn with_store<R: Send + 'static>(
      &self, f: impl FnOnce(&Store) -> R + Send + 'static,
  ) -> R {
      let store = self.store.clone();
      tokio::task::spawn_blocking(move || f(&store.lock().expect("store lock")))
          .await
          .expect("store task")
  }
  ```
  then `let (ops, latest) = state.with_store(move |s| s.pull_ops(&vid, since, limit)).await?;`
- Allow read concurrency. Open with a small r2d2/`deadpool-sqlite` pool (e.g. 1 writer +
  N readers, WAL already enabled at `store.rs:51`). With WAL, readers don't block the
  writer; a pool lets concurrent `pull`/`status` run in parallel. If a pool is too much,
  at minimum add `PRAGMA busy_timeout` (see finding 6) and keep writes on one connection.

The lib already does this right for SQLCipher (`src/vault.rs:289` sets `busy_timeout(5s)`,
WAL, `synchronous=NORMAL`); the sync store omits `busy_timeout`.

---

## 2. Unbounded in-memory maps that never evict

**Impact: Med** (slow leak; matters for long-lived processes)

These all grow with the number of *distinct keys ever seen* and are never shrunk:

- **Rate-limiter buckets** — `services/vault-broker/src/hardening.rs:30,54`.
  `buckets: Mutex<HashMap<String, Bucket>>` inserts a bucket per principal and never
  removes it. Principal keys are bounded in prod (verified mTLS SANs = the fleet), so this
  is small *unless* the `anonymous`/`x-client-cert-san` dev path is reachable, where an
  attacker-chosen header value (`hardening.rs:98`) makes the key space unbounded → memory
  growth + the `allow()` mutex is taken on *every* request (`hardening.rs:53`), so the map
  also slows lookups as it grows.
  **Fix:** evict idle buckets. Since a full bucket carries no state, drop any entry whose
  `tokens` has refilled to `rate_burst` (i.e. `now - last >= burst/rate`). Do it inline in
  `allow()` with an occasional sweep, or cap the map size + reject-with-shared-bucket on
  overflow. Also collapse all dev-header / anonymous traffic into a *single* fixed key so
  the key space can't be inflated.

- **Replay nonce store** — `services/vault-sync/src/auth.rs:106,112`.
  `seen: Mutex<HashMap<String,i64>>`. This one *is* bounded: `check_and_record` runs
  `seen.retain(|_, ts| now - *ts <= MAX_SKEW_SECS)` on every call (`auth.rs:115`), so it
  holds at most one skew-window (5 min) of nonces. **But** `retain` is O(n) over the whole
  map on *every* request — at high nonce rate this is wasted work under the lock. Low risk
  at this QPS; if it ever matters, switch to a 2-bucket time-wheel (current + previous
  window) and rotate instead of scanning. No change needed now beyond a note.

- **Metrics maps** — `services/vault-broker/src/state.rs:38,40,42`. Keyed by
  `route` (the `MatchedPath` template, `hardening.rs:158`) + method + status, all bounded
  cardinality. Correct — explicitly avoids the tenant-bearing concrete path. No action.

---

## 3. `publish` clones every message while holding the tails lock (vault-sync)

**Impact: Low**
**Location:** `services/vault-sync/src/state.rs:48-56`.

`publish` holds the `tails` mutex and, for each subscriber message, calls `tx.send(m.clone())`
(`state.rs:53`). The clone is a `String` per op per publish; the lock is the global tails
map lock, so a large `push` (many accepted ops) holds it across all the sends. At personal
scale this is negligible, but two cheap wins:

- Take the `broadcast::Sender` out of the map (clone the `Sender`, which is cheap/Arc-based),
  drop the map lock, then send — don't hold the map lock across the send loop.
- The messages are already-serialized JSON `String`s built in `http.rs:402`; consider
  `broadcast::Sender<Arc<str>>` so fan-out to N subscribers shares one allocation instead
  of `tokio::broadcast` cloning the `String` per receiver internally.

Live-tail back-pressure itself is handled correctly: per-vesta `broadcast` capacity 256
(`state.rs:14`) with `Lagged` → `{"resync":true}` (`http.rs:498`) instead of unbounded
buffering. Good design.

---

## 4. `push` does an extra full DB round-trip just to fan out (vault-sync)

**Impact: Low/Med**
**Location:** `services/vault-sync/src/http.rs:376-406`.

After `push_ops` commits, the handler re-locks the store and calls `pull_ops(before, accepted)`
(`http.rs:392-401`) purely to get the `StoredOp`s (with server `seq`) to broadcast. That is a
second SELECT + base64 round-trip over rows it *just inserted*. `push_ops` already has every
field and the assigned `seq` in hand (`store.rs:204-216`).

**Fix:** have `push_ops` return the accepted `StoredOp`s (or their `(seq, Op)`), so the
handler broadcasts directly with no second query/lock:
```rust
// store.rs push_ops: accumulate accepted rows
accepted_ops.push(StoredOp { seq: seq as u64, op: op.clone() });
// return (accepted, duplicates, latest, accepted_ops)
```
Removes one lock acquisition + one query + one base64 decode/re-encode round-trip per push.

---

## 5. Audit shipper reads the whole backlog into memory; no batch cap (vault-broker)

**Impact: Med** (only after downtime / large backlog; steady-state is fine)
**Location:** `services/vault-broker/src/audit_ship.rs:130-143` (`read_new_records`),
`:219-246` (`bulk_ship`).

The out-of-band design is correct and does **not** block issuance — the shipper tails the
durable chain file from a persisted cursor on a 5 s timer (`audit_ship.rs:23,89`), and a
slow/down OpenSearch just leaves the cursor unmoved for replay (`:123`). Good.

But `read_new_records` does `f.read_to_string(&mut buf)` (`:141`) — it reads *all* bytes
past the cursor into one `String`, then `collect_backlog` builds a `Vec` of every event, and
`bulk_ship` concatenates them all into one `_bulk` body (`:227`). After a multi-day outage
the chain could be very large; this is an unbounded allocation **and** a single huge bulk
request OpenSearch may reject (HTTP/heap limits), which then never advances the cursor →
stuck replaying the same oversized batch forever.

**Fix:** cap each tick's work. Read at most `MAX_SHIP_BYTES` past the cursor (e.g. read a
bounded buffer, not `read_to_string`), or cap `items` to e.g. 1–5k events / a few MB per
`bulk_ship`, advance the cursor by the bytes actually shipped, and let the next tick (or a
tight inner loop) drain the rest. This bounds memory and guarantees forward progress.

---

## 6. vault-sync store missing `busy_timeout`; minor SQLite tuning

**Impact: Low**
**Location:** `services/vault-sync/src/store.rs:49-81`.

The sync store sets `journal_mode=WAL` + `foreign_keys=ON` but not `busy_timeout` or
`synchronous` (contrast the lib at `src/vault.rs:289-292`). Today a single connection behind
the mutex means no in-process lock contention, but the moment finding 1's pool lands you'll
want `PRAGMA busy_timeout=5000` and `PRAGMA synchronous=NORMAL` (safe under WAL) to avoid
`SQLITE_BUSY` and to cut fsync cost on `push` commits.

**Index check (requested):** the oplog's `PRIMARY KEY (vault_id, seq)` (`store.rs:77`) is
exactly the index `pull_ops` needs — `WHERE vault_id=?1 AND seq>?2 ORDER BY seq ASC`
(`store.rs:234-236`) is a direct range scan on the PK, and `MAX(seq) WHERE vault_id`
(`latest_seq`, `store.rs:170`) walks the tail of the same index. No table scans, no N+1.
The `UNIQUE (vault_id, op_id)` index backs the dedup `exists` check in the push loop
(`store.rs:189,197`). Indexing here is correct and complete — no action.

---

## 7. `store_snapshot` holds the store mutex across a full `VACUUM INTO` (vault-broker)

**Impact: Low** (admin-only, rare)
**Location:** `services/vault-broker/src/http.rs:409-412`.

`VACUUM INTO ?1` runs while holding the `Vesta` mutex (`http.rs:410`), then the file is
read back with `std::fs::read` (`:421`) on the async thread. On a large at-rest store this
blocks the runtime worker *and* every other store user (KMS wrap/unwrap, SSH sign) for the
duration. It's a capability-gated snapshot op so frequency is low, but if the store ever
grows, wrap the VACUUM + file read in `spawn_blocking` and copy the `Arc<Mutex<Vesta>>` in.

---

## Other observations (no action needed)

- **Lock-across-await audit (broker):** checked the issuance handlers
  (`http.rs:475` `creds`, `:633/:675/:716` KMS, `:797` session). The `leases` /
  `store` / `cred_handles` `std::sync::Mutex`es are all acquired in tight scoped blocks
  and released *before* any `.await` (e.g. `creds` releases the lease lock at
  `http.rs:525` before the next await). Correct — no std mutex is held across an await.
- **Argon2id (~500 ms, 64 MiB):** only runs at boot in `boot_unseal`
  (`vault-broker/src/main.rs:41`, before the server accepts traffic) and client-side for
  enrolment; the server-side enrol verifier is a single SHA-256 (`auth.rs:79`). It is
  *not* on any request hot path. Correct.
- **KMS wrap/unwrap:** operate on already-derived KEKs from the unsealed store (AEAD only),
  no per-request KDF. Fine.
- **Rate-limit / concurrency back-pressure (broker):** token bucket + `Semaphore`
  `try_acquire_owned` → `503` (`hardening.rs:105,125`) is the right shape (reject, don't
  queue). The inflight gauge is updated around the inner call (`hardening.rs:132-134`).

---

## Top 5, prioritized

1. **(High)** vault-sync serializes *all* DB work through one `std::sync::Mutex<Connection>`
   on the async runtime — no read parallelism and it blocks tokio workers.
   Move DB calls to `spawn_blocking` and adopt a small WAL reader pool.
   `state.rs:19`, `http.rs` (all handlers), `store.rs:225`.
2. **(Med)** Audit shipper reads the entire backlog into memory and ships it as one
   unbounded `_bulk` body — after an outage this can OOM/stall and never advance the cursor.
   Cap bytes/events per tick and drain incrementally. `audit_ship.rs:141,219`.
3. **(Med)** Rate-limiter `buckets` map never evicts and is keyed by a
   potentially attacker-controlled header on the dev path → unbounded growth + lock taken
   per request. Evict refilled buckets; collapse anonymous traffic to one key.
   `hardening.rs:30,54,98`.
4. **(Low/Med)** vault-sync `push` issues a second SELECT+base64 round-trip (and re-locks
   the store) solely to fan out ops it just inserted. Return the accepted rows from
   `push_ops`. `http.rs:392`, `store.rs:180`.
5. **(Low)** Add `PRAGMA busy_timeout`/`synchronous=NORMAL` to the vault-sync store (parity
   with the lib) ahead of the pool change; mutex-held `VACUUM INTO` in `store_snapshot`
   should move to `spawn_blocking`. `store.rs:49`, `http.rs:409`.
