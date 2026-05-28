//! Server-blind op store (plain SQLite via the lib's `rusqlite` re-export). Holds only:
//! the per-vault enrolment verifier, device public keys, and opaque encrypted ops. Never
//! the vault key or plaintext. `seq` is a per-`vault_id` monotonic cursor for `pull`.

use crate::dto::{EnrollVerifier, Op, StoredOp};
use base64::Engine as _;
use terrapi_vault::rusqlite::{self, params, Connection, OptionalExtension};
use vault_transport::Hlc;

/// Current unix time in seconds.
#[must_use]
pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The enrolment record a new device needs (salt + Argon2 params) plus the server's verifier
/// hash: `(enroll_salt, params, enroll_hash)`.
pub type EnrollRecord = (Vec<u8>, terrapi_vault::KdfParams, Vec<u8>);

/// The op store. Wraps one SQLite connection; the caller serialises access (the connection
/// is `!Sync`, so [`crate::state::AppState`] holds it behind a `Mutex`).
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the SQLite database at `path` and apply the schema.
    ///
    /// # Errors
    /// Propagates any `rusqlite` open/DDL error.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    /// In-memory store for tests.
    #[cfg(test)]
    pub fn open_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    fn init(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS accounts (
                 vault_id      TEXT PRIMARY KEY,
                 enroll_salt   BLOB NOT NULL,
                 enroll_params TEXT NOT NULL,
                 enroll_hash   BLOB NOT NULL,
                 created_at    INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS devices (
                 vault_id    TEXT NOT NULL,
                 device_id   TEXT NOT NULL,
                 pubkey      BLOB NOT NULL,
                 enrolled_at INTEGER NOT NULL,
                 PRIMARY KEY (vault_id, device_id)
             );
             CREATE TABLE IF NOT EXISTS ops (
                 vault_id      TEXT NOT NULL,
                 seq           INTEGER NOT NULL,
                 op_id         TEXT NOT NULL,
                 device_id     TEXT NOT NULL,
                 hlc_wall      INTEGER NOT NULL,
                 hlc_counter   INTEGER NOT NULL,
                 collection_id TEXT NOT NULL,
                 payload       BLOB NOT NULL,
                 created_at    INTEGER NOT NULL,
                 PRIMARY KEY (vault_id, seq),
                 UNIQUE (vault_id, op_id)
             );",
        )
    }

    /// Create the account + register the first device, atomically. Returns `false` (and
    /// changes nothing) if the account already exists.
    pub fn create_account(
        &self,
        vault_id: &str,
        enroll: &EnrollVerifier,
        device_id: &str,
        pubkey: &[u8; 32],
    ) -> rusqlite::Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        if tx
            .prepare("SELECT 1 FROM accounts WHERE vault_id = ?1")?
            .exists([vault_id])?
        {
            return Ok(false);
        }
        let salt = b64().decode(enroll.salt_b64.as_bytes()).unwrap_or_default();
        let hash = b64().decode(enroll.hash_b64.as_bytes()).unwrap_or_default();
        let params_json = serde_json::to_string(&enroll.params).unwrap_or_default();
        let now = now_unix();
        tx.execute(
            "INSERT INTO accounts (vault_id, enroll_salt, enroll_params, enroll_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![vault_id, salt, params_json, hash, now],
        )?;
        tx.execute(
            "INSERT INTO devices (vault_id, device_id, pubkey, enrolled_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![vault_id, device_id, pubkey.as_slice(), now],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// The enrolment challenge (salt + params) a new device needs, plus the verifier hash.
    /// `None` if no such account.
    pub fn enroll_record(&self, vault_id: &str) -> rusqlite::Result<Option<EnrollRecord>> {
        self.conn
            .query_row(
                "SELECT enroll_salt, enroll_params, enroll_hash FROM accounts WHERE vault_id = ?1",
                [vault_id],
                |r| {
                    let salt: Vec<u8> = r.get(0)?;
                    let params_json: String = r.get(1)?;
                    let hash: Vec<u8> = r.get(2)?;
                    let params = serde_json::from_str(&params_json).unwrap_or_default();
                    Ok((salt, params, hash))
                },
            )
            .optional()
    }

    /// Register (or replace, for key rotation) a device's public key.
    pub fn register_device(
        &self,
        vault_id: &str,
        device_id: &str,
        pubkey: &[u8; 32],
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO devices (vault_id, device_id, pubkey, enrolled_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![vault_id, device_id, pubkey.as_slice(), now_unix()],
        )?;
        Ok(())
    }

    /// A registered device's ed25519 public key, if any.
    pub fn device_pubkey(
        &self,
        vault_id: &str,
        device_id: &str,
    ) -> rusqlite::Result<Option<[u8; 32]>> {
        let raw: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT pubkey FROM devices WHERE vault_id = ?1 AND device_id = ?2",
                params![vault_id, device_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw.and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()))
    }

    /// Highest `seq` stored for `vault_id` (0 if none).
    pub fn latest_seq(&self, vault_id: &str) -> rusqlite::Result<u64> {
        let seq: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM ops WHERE vault_id = ?1",
            [vault_id],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(seq).unwrap_or(0))
    }

    /// Append `ops`, assigning each a fresh per-vault `seq`. Idempotent: an `op_id` already
    /// stored is skipped (counted as a duplicate). Returns `(accepted, duplicates, latest_seq)`.
    /// Malformed base64 in a payload aborts the whole batch with `InvalidPayload`.
    pub fn push_ops(&self, vault_id: &str, ops: &[Op]) -> Result<(u64, u64, u64), PushError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM ops WHERE vault_id = ?1",
            [vault_id],
            |r| r.get(0),
        )?;
        let (mut accepted, mut duplicates) = (0u64, 0u64);
        {
            let mut exists = tx.prepare("SELECT 1 FROM ops WHERE vault_id = ?1 AND op_id = ?2")?;
            let mut insert = tx.prepare(
                "INSERT INTO ops
                   (vault_id, seq, op_id, device_id, hlc_wall, hlc_counter, collection_id, payload, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            let now = now_unix();
            for op in ops {
                if exists.exists(params![vault_id, op.op_id])? {
                    duplicates += 1;
                    continue;
                }
                let payload = b64()
                    .decode(op.encrypted_payload.as_bytes())
                    .map_err(|_| PushError::InvalidPayload)?;
                seq += 1;
                insert.execute(params![
                    vault_id,
                    seq,
                    op.op_id,
                    op.device_id,
                    i64::try_from(op.hlc.wall_ms).unwrap_or(i64::MAX),
                    i64::from(op.hlc.counter),
                    op.collection_id,
                    payload,
                    now,
                ])?;
                accepted += 1;
            }
        }
        tx.commit()?;
        Ok((accepted, duplicates, u64::try_from(seq).unwrap_or(0)))
    }

    /// Ops with `seq > since`, ascending, capped at `limit`. Also returns the vault's
    /// current high-water `seq` so the client knows whether more remains.
    pub fn pull_ops(
        &self,
        vault_id: &str,
        since: u64,
        limit: u32,
    ) -> rusqlite::Result<(Vec<StoredOp>, u64)> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, op_id, device_id, hlc_wall, hlc_counter, collection_id, payload
               FROM ops
              WHERE vault_id = ?1 AND seq > ?2
              ORDER BY seq ASC
              LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![vault_id, i64::try_from(since).unwrap_or(i64::MAX), limit],
            |r| {
                let seq: i64 = r.get(0)?;
                let payload: Vec<u8> = r.get(6)?;
                Ok(StoredOp {
                    seq: u64::try_from(seq).unwrap_or(0),
                    op: Op {
                        op_id: r.get(1)?,
                        device_id: r.get(2)?,
                        hlc: Hlc {
                            wall_ms: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                            counter: u32::try_from(r.get::<_, i64>(4)?.max(0)).unwrap_or(u32::MAX),
                        },
                        collection_id: r.get(5)?,
                        encrypted_payload: b64().encode(payload),
                    },
                })
            },
        )?;
        let ops: Vec<StoredOp> = rows.collect::<rusqlite::Result<_>>()?;
        let latest = self.latest_seq(vault_id)?;
        Ok((ops, latest))
    }

    /// `(latest_seq, op_count, device_count)` for `vault_id`.
    pub fn status(&self, vault_id: &str) -> rusqlite::Result<(u64, u64, u64)> {
        let op_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ops WHERE vault_id = ?1",
            [vault_id],
            |r| r.get(0),
        )?;
        let device_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM devices WHERE vault_id = ?1",
            [vault_id],
            |r| r.get(0),
        )?;
        Ok((
            self.latest_seq(vault_id)?,
            u64::try_from(op_count).unwrap_or(0),
            u64::try_from(device_count).unwrap_or(0),
        ))
    }
}

/// Push failure: a storage error, or a client op whose payload was not valid base64.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("storage error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("op payload is not valid base64")]
    InvalidPayload,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(id: &str, wall: u64) -> Op {
        Op {
            op_id: id.into(),
            device_id: "dev-a".into(),
            hlc: Hlc {
                wall_ms: wall,
                counter: 0,
            },
            collection_id: "notes".into(),
            encrypted_payload: b64().encode(b"ciphertext"),
        }
    }

    #[test]
    fn push_assigns_monotonic_seq_and_dedupes() {
        let s = Store::open_memory().unwrap();
        let (acc, dup, latest) = s.push_ops("v1", &[op("a", 1), op("b", 2)]).unwrap();
        assert_eq!((acc, dup, latest), (2, 0, 2));
        // Re-pushing "a" plus a new "c": one dup, one accepted, seq advances to 3.
        let (acc, dup, latest) = s.push_ops("v1", &[op("a", 1), op("c", 3)]).unwrap();
        assert_eq!((acc, dup, latest), (1, 1, 3));
    }

    #[test]
    fn pull_returns_ops_after_cursor() {
        let s = Store::open_memory().unwrap();
        s.push_ops("v1", &[op("a", 1), op("b", 2), op("c", 3)])
            .unwrap();
        let (ops, latest) = s.pull_ops("v1", 1, 100).unwrap();
        assert_eq!(latest, 3);
        assert_eq!(ops.len(), 2); // seq 2,3
        assert_eq!(ops[0].seq, 2);
        assert_eq!(ops[0].op.op_id, "b");
        assert_eq!(ops[0].op.encrypted_payload, b64().encode(b"ciphertext"));
    }

    #[test]
    fn ops_are_isolated_per_vault() {
        let s = Store::open_memory().unwrap();
        s.push_ops("v1", &[op("a", 1)]).unwrap();
        s.push_ops("v2", &[op("a", 1)]).unwrap(); // same op_id, different vault → fine
        assert_eq!(s.latest_seq("v1").unwrap(), 1);
        assert_eq!(s.latest_seq("v2").unwrap(), 1);
        assert_eq!(s.pull_ops("v2", 0, 10).unwrap().0.len(), 1);
    }

    #[test]
    fn account_create_is_idempotent_and_registers_device() {
        let s = Store::open_memory().unwrap();
        let enroll = EnrollVerifier {
            salt_b64: b64().encode(b"salt"),
            params: terrapi_vault::KdfParams::default(),
            hash_b64: b64().encode([7u8; 32]),
        };
        let pk = [1u8; 32];
        assert!(s.create_account("v1", &enroll, "dev-a", &pk).unwrap());
        assert!(!s.create_account("v1", &enroll, "dev-a", &pk).unwrap()); // exists
        assert_eq!(s.device_pubkey("v1", "dev-a").unwrap(), Some(pk));
        let (_, _, dev_count) = s.status("v1").unwrap();
        assert_eq!(dev_count, 1);
    }

    #[test]
    fn malformed_payload_is_rejected() {
        let s = Store::open_memory().unwrap();
        let bad = Op {
            encrypted_payload: "not base64!!!".into(),
            ..op("a", 1)
        };
        assert!(matches!(
            s.push_ops("v1", &[bad]),
            Err(PushError::InvalidPayload)
        ));
    }
}
