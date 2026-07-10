//! Canonical B3 audit event (`source:"vesta"`) + local sinks.
//!
//! Ownership decision (coordination/conventions/secrets-broker.md): the broker emits
//! its own B3 events; consumers do NOT double-record. The durable local store
//! ([`HashChainSink`], tamper-evident) is the source of truth; the broker's OpenSearch
//! shipper fans out a best-effort copy on top and must never block an issuance.
//!
//! **Redaction by construction:** `AuditEvent` has no field that can hold a secret
//! value, private key, password, or signed certificate. Only metadata (action, ids,
//! ttl, outcome) is representable, so a secret cannot be emitted by accident.

use crate::lock::MutexExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Actor kind, mirroring `conventions/audit-event-schema.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    ApiToken,
    System,
    DevBypass,
}

/// Who performed the action. Never carries credential material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub label: String,
    pub kind: ActorKind,
    pub id: Option<String>,
    pub tenant: Option<String>,
}

/// What was acted on (a lease, a session, an SSH principal set, a role) — id only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: String,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
}

/// One canonical B3 audit document. `source` is fixed to `"vesta"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// RFC3339 millis UTC.
    pub ts: String,
    pub schema_version: u8,
    pub source: &'static str,
    pub node: String,
    pub residency_group: Option<String>,
    pub actor: Actor,
    /// `<noun>.<verb>`, e.g. `ssh.sign`, `creds.issue`, `lease.revoke`, `session.end`.
    pub action: String,
    pub target: Target,
    pub outcome: Outcome,
    pub request_id: Option<String>,
}

impl AuditEvent {
    /// Build a vault-sourced event. `ts` is supplied by the caller (the broker passes an
    /// RFC3339 millis UTC string) so this crate stays clock-agnostic and test-friendly.
    // Mirrors the canonical B3 document field-for-field; a builder would obscure that.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn vault(
        ts: String,
        node: String,
        residency_group: Option<String>,
        actor: Actor,
        action: impl Into<String>,
        target: Target,
        outcome: Outcome,
        request_id: Option<String>,
    ) -> Self {
        Self {
            ts,
            schema_version: 1,
            source: "vesta",
            node,
            residency_group,
            actor,
            action: action.into(),
            target,
            outcome,
            request_id,
        }
    }
}

/// Why a durable audit append failed — the record did NOT reach the chain.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("audit event could not be serialized")]
    Serialize,
    #[error("audit append failed (chain not advanced)")]
    Append,
}

/// A sink the broker emits audit events to.
pub trait AuditSink: Send + Sync {
    /// Best-effort: a failure here must never break the user-visible action. Use for events that
    /// describe state the issuance already committed elsewhere (session open/end, revoke).
    fn emit(&self, event: &AuditEvent);

    /// Like [`AuditSink::emit`] but reports whether the record reached the durable store.
    /// **Issuance** ops (mint a cert / backend user) call this and fail closed on `Err`, so no
    /// credential is ever handed out without a durable audit record. Default: best-effort emit
    /// that always reports success — for sinks with no durability guarantee to make.
    ///
    /// # Errors
    /// [`AuditError`] when the record could not be durably recorded.
    fn try_emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.emit(event);
        Ok(())
    }
}

/// Durable local sink: append one JSON line per event. The source of truth; the broker's
/// `audit_ship::ShippingSink` wraps this and best-effort ships to OpenSearch on top. (The
/// hash-chained tamper-evident store is still to come.) Errors are swallowed (best-effort).
pub struct JsonlSink {
    path: PathBuf,
}

impl JsonlSink {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl AuditSink for JsonlSink {
    fn emit(&self, event: &AuditEvent) {
        let Ok(mut line) = serde_json::to_vec(event) else {
            return;
        };
        line.push(b'\n');
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = f.write_all(&line);
        }
    }
}

// --- Hash-chained tamper-evident local store --------------------------------------

const GENESIS: [u8; 32] = [0u8; 32];

/// Durable, **tamper-evident** local audit store: append-only JSONL where each record
/// carries a SHA-256 hash chained to the previous record. Any edit, reorder, or deletion
/// of a record breaks the chain and is caught by [`verify`].
///
/// Per record: `seq` (0-based), `prev` (previous record's hash, hex), `event` (the
/// canonical B3 object), and `hash = SHA256(prev_bytes ++ seq_be ++ event_bytes)` (hex).
/// `event_bytes` is the event serialized by serde_json; on read the exact bytes are
/// recovered via `RawValue`, so verification is byte-exact without round-tripping the type.
pub struct HashChainSink {
    path: PathBuf,
    state: Mutex<ChainState>,
}

struct ChainState {
    seq: u64,
    prev: [u8; 32],
    /// Held append writer (opened once, not per event). `None` if it can't be opened; `emit`
    /// then retries the open. Keeping it open avoids an `open()` syscall per audit event.
    file: Option<std::fs::File>,
    /// Set when the tip could not be cleanly recovered at open (a mid-chain read error → the true
    /// tail is unknown). The chain then **refuses all appends** (fail-closed) rather than resume
    /// from a stale seq and fork the chain; issuance `try_emit` therefore 503s until fixed.
    corrupt: bool,
}

#[derive(Serialize)]
struct RecordOut<'a> {
    seq: u64,
    prev: &'a str,
    hash: &'a str,
    event: &'a AuditEvent,
}

#[derive(Deserialize)]
struct RecordIn {
    seq: u64,
    prev: String,
    hash: String,
    event: Box<serde_json::value::RawValue>,
}

/// Why a chain failed to verify.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("read error: {0}")]
    Io(String),
    #[error("malformed record at line {0}")]
    Malformed(u64),
    #[error("sequence gap: expected {expected}, got {got}")]
    SeqGap { expected: u64, got: u64 },
    #[error("broken chain at seq {0}: prev hash does not match")]
    BrokenChain(u64),
    #[error("tampered record at seq {0}: hash mismatch")]
    Tampered(u64),
}

fn record_hash(prev: &[u8; 32], seq: u64, event_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(seq.to_be_bytes());
    h.update(event_bytes);
    h.finalize().into()
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn from_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

impl HashChainSink {
    /// Open the store at `path`, recovering the chain tip (next seq + last hash) from any
    /// existing file so appends continue the chain across restarts.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let (seq, prev, clean) = recover_tip(&path);
        if !clean {
            eprintln!(
                "vault audit: chain at {} could not be cleanly read (mid-file read error); \
                 refusing to append (fail-closed) to avoid forking the chain — investigate/repair \
                 the audit file. Issuance will 503 until resolved.",
                path.display()
            );
        }
        let file = open_append(&path);
        Self {
            path,
            state: Mutex::new(ChainState {
                seq,
                prev,
                file,
                corrupt: !clean,
            }),
        }
    }
}

fn open_append(path: &Path) -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// Recover `(next_seq, last_hash, clean)` from the file. `clean` is `false` if a line could not be
/// read (mid-chain I/O error) — the true tail is then unknown, so the caller fail-closes rather
/// than resume from a stale tip and fork the chain. An absent/empty file is a clean `(0, GENESIS)`
/// start. Uses the last parseable record (a partial trailing line from a crash is ignored).
fn recover_tip(path: &Path) -> (u64, [u8; 32], bool) {
    let Ok(file) = std::fs::File::open(path) else {
        return (0, GENESIS, true); // absent/unopenable → clean empty start (append will create it)
    };
    // Stream line-by-line — the append-only chain grows unbounded, so never load it whole.
    let mut tip = None;
    let mut clean = true;
    for line in std::io::BufReader::new(file).lines() {
        let Ok(line) = line else {
            // A read error before EOF: we cannot know the real tail. Do NOT silently truncate.
            clean = false;
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(r) = serde_json::from_str::<RecordIn>(line) {
            if let Some(h) = from_hex32(&r.hash) {
                tip = Some((r.seq, h));
            }
        }
    }
    let (seq, prev) = tip.map_or((0, GENESIS), |(seq, h)| (seq + 1, h));
    (seq, prev, clean)
}

/// One audit record for the read-only observe API: its sequence + the canonical B3 event.
/// (Chain `prev`/`hash` are omitted — integrity is `verify_chain`'s concern, not the view's.)
pub struct AuditTail {
    pub seq: u64,
    pub event: serde_json::Value,
}

/// Read up to `limit` records with `seq >= since` from the chain file at `path`, in file order.
/// Best-effort: a missing/partial file yields whatever is parseable (no error) — this is a
/// read-only operator view, not the integrity check. Already-redacted B3 events.
#[must_use]
pub fn read_tail(path: &Path, since: u64, limit: usize) -> Vec<AuditTail> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    // Stream line-by-line and stop at `limit` — never load the whole append-only chain into memory.
    let mut out = Vec::new();
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(r) = serde_json::from_str::<RecordIn>(line) else {
            continue;
        };
        if r.seq < since {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(r.event.get()) {
            out.push(AuditTail { seq: r.seq, event });
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

impl HashChainSink {
    /// Append one record, advancing the chain iff it reaches the file. Returns whether the record
    /// was durably written so `try_emit` can fail issuance closed.
    fn append(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let event_bytes = serde_json::to_vec(event).map_err(|_| AuditError::Serialize)?;
        let mut st = self.state.lock_recover();
        // Fail-closed: if the tip couldn't be cleanly recovered, never append (would fork the
        // chain at an unknown seq). Issuance try_emit() then 503s; best-effort emit() drops.
        if st.corrupt {
            return Err(AuditError::Append);
        }
        let hash = record_hash(&st.prev, st.seq, &event_bytes);
        let rec = RecordOut {
            seq: st.seq,
            prev: &to_hex(&st.prev),
            hash: &to_hex(&hash),
            event,
        };
        let mut line = serde_json::to_vec(&rec).map_err(|_| AuditError::Serialize)?;
        line.push(b'\n');
        // Reopen if we lost the handle (first open failed, or a prior write errored).
        if st.file.is_none() {
            st.file = open_append(&self.path);
        }
        // Advance the chain iff the record reached the file. `write_all` with `O_APPEND` is the
        // integrity point (the bytes are atomically in the file at this seq); `sync_all` (fsync)
        // then flushes them to the device so the record survives power loss — the audit chain is
        // the durable source of truth. fsync is best-effort: if it fails the bytes are still in
        // the file (integrity holds), only durability degrades — we must NOT re-use this seq, so
        // advance is gated on the write, not the fsync.
        let wrote = {
            match st.file.as_mut() {
                Some(file) => match file.write_all(&line) {
                    Ok(()) => {
                        let _ = file.sync_all();
                        true
                    }
                    Err(_) => false,
                },
                None => false,
            }
        };
        if wrote {
            st.seq += 1;
            st.prev = hash;
            Ok(())
        } else {
            st.file = None; // drop a wedged handle; next emit reopens
            Err(AuditError::Append)
        }
    }
}

impl AuditSink for HashChainSink {
    fn emit(&self, event: &AuditEvent) {
        let _ = self.append(event);
    }

    fn try_emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        self.append(event)
    }
}

/// Verify the whole chain at `path`. Returns the number of records on success, else the
/// first integrity failure (gap, broken link, or tampered record).
///
/// # Errors
/// See [`VerifyError`].
pub fn verify(path: impl AsRef<Path>) -> Result<u64, VerifyError> {
    let file = std::fs::File::open(path).map_err(|e| VerifyError::Io(e.to_string()))?;
    // Stream line-by-line so verification memory stays flat regardless of chain length.
    let mut prev = GENESIS;
    let mut expected: u64 = 0;
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|e| VerifyError::Io(e.to_string()))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let r: RecordIn =
            serde_json::from_str(line).map_err(|_| VerifyError::Malformed(expected))?;
        if r.seq != expected {
            return Err(VerifyError::SeqGap {
                expected,
                got: r.seq,
            });
        }
        let rec_prev = from_hex32(&r.prev).ok_or(VerifyError::Malformed(r.seq))?;
        if rec_prev != prev {
            return Err(VerifyError::BrokenChain(r.seq));
        }
        let recomputed = record_hash(&prev, r.seq, r.event.get().as_bytes());
        let stored = from_hex32(&r.hash).ok_or(VerifyError::Malformed(r.seq))?;
        if recomputed != stored {
            return Err(VerifyError::Tampered(r.seq));
        }
        prev = recomputed;
        expected += 1;
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditEvent {
        AuditEvent::vault(
            "2026-05-26T10:00:00.000Z".into(),
            "vault-eu-1".into(),
            Some("eu".into()),
            Actor {
                label: "demon@host".into(),
                kind: ActorKind::System,
                id: None,
                tenant: Some("11111111-1111-4111-8111-111111111111".into()),
            },
            "ssh.sign",
            Target {
                kind: "ssh_cert".into(),
                id: Some("serial-42".into()),
            },
            Outcome::Success,
            Some("req-1".into()),
        )
    }

    #[test]
    fn source_is_always_vesta() {
        assert_eq!(sample().source, "vesta");
        assert_eq!(sample().schema_version, 1);
    }

    #[test]
    fn serializes_without_any_secret_field() {
        let json = serde_json::to_string(&sample()).unwrap();
        // The type cannot represent secret material; assert the shape is metadata-only.
        assert!(json.contains("\"source\":\"vesta\""));
        assert!(json.contains("\"action\":\"ssh.sign\""));
        assert!(!json.to_lowercase().contains("password"));
        assert!(!json.to_lowercase().contains("private_key"));
    }

    #[test]
    fn jsonl_sink_appends_line() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vault-audit-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sink = JsonlSink::new(&path);
        sink.emit(&sample());
        sink.emit(&sample());
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2);
        let _ = std::fs::remove_file(&path);
    }

    fn chain_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vault-audit-chain-{name}-{}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn hash_chain_verifies_intact() {
        let path = chain_path("ok");
        let _ = std::fs::remove_file(&path);
        let sink = HashChainSink::new(&path);
        sink.emit(&sample());
        sink.emit(&sample());
        sink.emit(&sample());
        assert_eq!(verify(&path), Ok(3));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn try_emit_reports_durable_success_and_advances_chain() {
        let path = chain_path("tryemit");
        let _ = std::fs::remove_file(&path);
        let sink = HashChainSink::new(&path);
        // try_emit returns Ok when the record is durably appended (the issuance fail-closed path).
        assert_eq!(sink.try_emit(&sample()), Ok(()));
        assert_eq!(sink.try_emit(&sample()), Ok(()));
        assert_eq!(verify(&path), Ok(2));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hash_chain_recovers_across_reopen() {
        let path = chain_path("reopen");
        let _ = std::fs::remove_file(&path);
        {
            let sink = HashChainSink::new(&path);
            sink.emit(&sample());
            sink.emit(&sample());
        }
        // reopen → recover tip → append continues the chain
        {
            let sink = HashChainSink::new(&path);
            sink.emit(&sample());
        }
        assert_eq!(verify(&path), Ok(3));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampering_with_an_event_is_detected() {
        let path = chain_path("tamper");
        let _ = std::fs::remove_file(&path);
        let sink = HashChainSink::new(&path);
        sink.emit(&sample());
        sink.emit(&sample());
        // flip a field in the second record's event without recomputing the hash
        let body = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();
        lines[1] = lines[1].replace("ssh.sign", "ssh.forged");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert_eq!(verify(&path), Err(VerifyError::Tampered(1)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deleting_a_record_breaks_the_chain() {
        let path = chain_path("delete");
        let _ = std::fs::remove_file(&path);
        let sink = HashChainSink::new(&path);
        sink.emit(&sample());
        sink.emit(&sample());
        sink.emit(&sample());
        // drop the middle record → the next record's seq no longer matches
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert_eq!(
            verify(&path),
            Err(VerifyError::SeqGap {
                expected: 1,
                got: 2
            })
        );
        let _ = std::fs::remove_file(&path);
    }
}
