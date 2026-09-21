//! Fixed-writer, two-copy replication experiment. Not a production protocol.
#[cfg(feature = "demo-api")]
pub mod api;
mod checkpoint;
pub mod coordinator;
pub mod journal;
pub mod materialized;
#[cfg(feature = "mtls")]
pub mod network;
pub mod publication;
pub mod receipts;
pub mod recovery;
pub mod reference;
pub mod schema;
pub mod schema_contract;
pub mod sql_snapshot;
pub mod typed;
pub use reference::{Change, Feature, Place, View};
use schema::Schema;
#[cfg(feature = "demo-api")]
pub mod secondary;
pub mod snapshot_staging;
pub use checkpoint::Checkpoint;
pub use receipts::{OperationReceipt, WriteResult};
use rusqlite::{params, Connection, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};
use terrapi_vesta::{KdfParams, Vesta};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn hash<T: Serialize>(value: &T) -> Result<String> {
    // Preserve the existing JSON byte contract without a full serialized buffer.
    let mut digest = Sha256::new();
    serde_json::to_writer(&mut digest, value)?;
    Ok(format!("{:x}", digest.finalize()))
}
#[cfg(test)]
mod hash_tests;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Replication scope. The default schema field preserves the legacy numeric wire
/// format; a typed schema descriptor is opt-in and is not accepted by legacy Node.
pub struct Identity<S = u32> {
    pub cluster: String,
    pub tenant: String,
    pub epoch: u64,
    pub schema: S,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Primary,
    Secondary,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Ordered application request. Generic parameters do not add serialized fields.
pub struct Batch<C = Change, S = u32> {
    pub identity: Identity<S>,
    pub operation_id: String,
    pub changes: Vec<C>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum State {
    Prepared,
    Decided,
    Applied,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Journal data envelope, not authenticated evidence or a commit authorization.
/// The existing runtime still accepts only the default reference specialization.
pub struct Entry<C = Change, S = u32> {
    pub batch: Batch<C, S>,
    pub sequence: u64,
    pub before: String,
    pub after: String,
    pub changeset: Vec<u8>,
    pub digest: String,
    pub state: State,
}
impl<C: Serialize, S: Serialize + PartialEq> Entry<C, S> {
    fn checksum(&self) -> Result<String> {
        hash(&(
            &self.batch,
            self.sequence,
            &self.before,
            &self.after,
            &self.changeset,
        ))
    }
    fn validate(&self, identity: &Identity<S>) -> Result<()> {
        ensure(
            &self.batch.identity == identity,
            "identity/epoch/schema mismatch",
        )?;
        ensure(
            self.digest == self.checksum()?,
            "changeset checksum mismatch",
        )
    }
}

#[cfg(test)]
mod envelope_tests;
#[cfg(test)]
mod node_identity_tests;
#[derive(Debug, Serialize, Deserialize)]
pub struct Status<C = Change, I = u32> {
    pub read_generation: [u8; 32],
    pub identity: Identity<I>,
    pub role: Role,
    pub cipher_version: String,
    pub synchronous: i64,
    pub journal_mode: String,
    pub entries: Vec<Entry<C, I>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub identity: Identity,
    pub view: View,
    pub entries: Vec<Entry>,
    pub digest: String,
    pub receipt_digest: String,
}

pub struct Node {
    db: Vesta,
    role: Role,
    identity: Identity,
    _lock: File,
}
fn view(c: &Connection) -> Result<View> {
    reference::Proximi.view(c)
}
fn entries(c: &Connection) -> Result<Vec<Entry>> {
    journal::store::all(c)
}
fn save(c: &Connection, e: &Entry) -> Result<()> {
    journal::store::write(c, e)?;
    if e.state == State::Applied {
        receipts::insert(c, e)?;
    }
    Ok(())
}
fn apply_changeset(c: &Transaction<'_>, e: &Entry) -> Result<()> {
    schema::replay_data(
        c,
        &reference::Proximi,
        &reference::Proximi.identity(),
        &e.before,
        &e.after,
        &e.changeset,
    )
}
fn validate_node_identity(c: &Connection, identity: &Identity, role: Role) -> Result<()> {
    let count: u64 = c.query_row("SELECT count(*) FROM node_identity", [], |r| r.get(0))?;
    ensure(count == 1, "missing/ambiguous persisted node identity")?;
    let actual: String = c.query_row("SELECT value FROM node_identity", [], |r| r.get(0))?;
    ensure(
        actual == serde_json::to_string(&(identity, role))?,
        "persisted node identity/role mismatch",
    )
}

impl Node {
    /// Initialize a missing database path, or reopen an existing node with exactly
    /// one matching persisted identity/role. Existing non-Node files and damaged
    /// identities are never adopted or repaired. Interrupted first initialization
    /// can therefore require explicit operator recovery instead of an automatic retry.
    pub fn open(
        path: impl AsRef<Path>,
        role: Role,
        identity: Identity,
        passphrase: &str,
    ) -> Result<Self> {
        Self::open_inner(path.as_ref(), role, identity, passphrase, false)
    }

    /// Explicit local migration of a legacy Node without a schema-contract table.
    /// Requires its existing identity, canonical application DDL and valid history.
    /// Never repairs a present but damaged contract. This grants no remote authority.
    pub fn upgrade_legacy_schema_contract(
        path: impl AsRef<Path>,
        role: Role,
        identity: Identity,
        passphrase: &str,
    ) -> Result<Self> {
        Self::open_inner(path.as_ref(), role, identity, passphrase, true)
    }

    fn open_inner(
        path: &Path,
        role: Role,
        identity: Identity,
        passphrase: &str,
        upgrade: bool,
    ) -> Result<Self> {
        ensure(
            identity.schema == 1 && identity.epoch > 0,
            "unsupported identity",
        )?;
        let parent = path.parent().ok_or("missing parent")?.canonicalize()?;
        let path = parent.join(path.file_name().ok_or("missing filename")?);
        ensure(!path.is_symlink(), "symlink database unsupported")?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("node-lock"))?;
        lock.try_lock()?;
        let existing = path.exists();
        ensure(
            !upgrade || existing,
            "schema upgrade requires an existing Node",
        )?;
        let db = if existing {
            Vesta::open(&path, passphrase)?
        } else {
            Vesta::create(&path, passphrase, KdfParams::default())?
        };
        let node = Self {
            db,
            role,
            identity,
            _lock: lock,
        };
        node.connection(|c| {
            let contract = schema_contract::expected(&reference::Proximi)?;
            // An existing encrypted file must already belong to this node. Do
            // this before schema initialization can conceal missing metadata or
            // modify a database opened with the wrong scope/role.
            if existing {
                validate_node_identity(c, &node.identity, node.role)?;
            }
            let bound = schema_contract::exists(c)?;
            if existing {
                if bound {
                    schema_contract::verify(c, &reference::Proximi, &contract)?;
                } else {
                    ensure(upgrade, "missing schema contract; explicit legacy upgrade required")?;
                    ensure(schema_contract::describe(c, &reference::Proximi)? == contract,
                        "legacy application schema contract mismatch")?;
                    // Upgrade only the pre-binding Node format whose complete
                    // history is already readable. Do not bootstrap missing
                    // history/receipt metadata under the guise of schema binding.
                    schema::foreign_key_check(c)?;
                    checkpoint::current(c, &node.identity, false)?;
                    publication::validate_primary_base(c, node.role, &node.identity)?;
                }
            }
            c.pragma_update(None, "synchronous", "FULL")?;
            c.pragma_update(None, "temp_store", "MEMORY")?;
            schema::initialize(c, &reference::Proximi)?;
            c.execute_batch("CREATE TABLE IF NOT EXISTS node_identity(value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS replication_log(sequence INTEGER PRIMARY KEY,operation_id TEXT UNIQUE NOT NULL,entry TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS replication_readiness(id INTEGER PRIMARY KEY CHECK(id=1),checkpoint TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS replication_generation(id INTEGER PRIMARY KEY CHECK(id=1),value BLOB NOT NULL CHECK(length(value)=32));")?;
            checkpoint::initialize(c)?;
            journal::initialize(c)?;
            snapshot_staging::initialize(c)?;
            materialized::initialize(c)?;
            let expected = serde_json::to_string(&(&node.identity, node.role))?;
            if !existing { c.execute("INSERT INTO node_identity VALUES(?1)", [&expected])?; }
            validate_node_identity(c, &node.identity, node.role)?;
            receipts::initialize(c, &node.identity)?;
            publication::initialize(c, &node.identity)?;
            publication::validate_primary_base(c, node.role, &node.identity)?;
            if !bound {
                schema_contract::install(c, &reference::Proximi, &contract)?;
            }
            Ok(())
        })?;
        Ok(node)
    }
    fn connection<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.db.with_connection(|c| Ok(f(c)))?
    }
    pub fn view(&self) -> Result<View> {
        self.connection(view)
    }
    /// Read the locally verified schema contract. This is not peer admission or
    /// evidence that two replicas have committed an operation.
    pub fn schema_contract(&self) -> Result<schema_contract::Contract> {
        self.connection(|c| {
            let expected = schema_contract::expected(&reference::Proximi)?;
            schema_contract::verify(c, &reference::Proximi, &expected)?;
            Ok(expected)
        })
    }
    pub fn status(&self) -> Result<Status> {
        self.connection(|c| {
            Ok(Status {
                read_generation: checkpoint::generation(c)?,
                identity: self.identity.clone(),
                role: self.role,
                cipher_version: c.query_row("PRAGMA cipher_version", [], |r| r.get(0))?,
                synchronous: c.query_row("PRAGMA synchronous", [], |r| r.get(0))?,
                journal_mode: c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?,
                entries: entries(c)?,
            })
        })
    }
    pub fn prepare(&mut self, batch: Batch) -> Result<Entry> {
        ensure(self.role == Role::Primary, "only fixed primary may prepare")?;
        ensure(
            batch.identity == self.identity && !batch.operation_id.is_empty(),
            "invalid batch identity",
        )?;
        self.connection(|c| {
            recovery::activation::admission(c, self.role, &self.identity)?;
            if let Some(e) = journal::by_operation(c, &batch.operation_id)? {
                receipts::validate_entry(c, &e)?;
                ensure(
                    e.batch == batch,
                    "idempotency key reused for different request",
                )?;
                return Ok(e);
            }
            ensure(
                receipts::get(c, &batch.operation_id)?.is_none(),
                "historical operation requires receipt retry, not prepare",
            )?;
            let sequence = journal::head(c, &self.identity)?
                .length
                .checked_add(1)
                .ok_or("sequence overflow")?;
            publication::ensure_idle(c)?;
            ensure(journal::resolved(c)?, "recovery required")?;
            let schema::Captured {
                before,
                after,
                changeset,
                ..
            } = schema::capture(c, &reference::Proximi, &batch.changes)?;
            let mut e = Entry {
                batch,
                sequence,
                before,
                after,
                changeset,
                digest: String::new(),
                state: State::Prepared,
            };
            e.digest = e.checksum()?;
            journal::check_entry_size(&e)?;
            save(c, &e)?;
            Ok(e)
        })
    }
    pub fn stage(&mut self, entry: Entry) -> Result<()> {
        ensure(self.role == Role::Secondary, "only secondary may stage")?;
        entry.validate(&self.identity)?;
        journal::check_entry_size(&entry)?;
        self.connection(|c| {
            recovery::activation::admission(c, self.role, &self.identity)?;
            snapshot_staging::ensure_idle(c)?;
            if let Some(old) = journal::by_sequence(c, entry.sequence)? {
                return ensure(old.digest == entry.digest, "divergent log");
            }
            publication::ensure_idle(c)?;
            ensure(
                entry.sequence == journal::head(c, &self.identity)?.length + 1
                    && journal::resolved(c)?,
                "out-of-order stage",
            )?;
            ensure(hash(&view(c)?)? == entry.before, "base state mismatch")?;
            let tx = c.unchecked_transaction()?;
            apply_changeset(&tx, &entry)?;
            tx.rollback()?;
            let mut prepared = entry;
            prepared.state = State::Prepared;
            save(c, &prepared)
        })
    }
    pub fn decide(&mut self, operation_id: &str) -> Result<Entry> {
        ensure(self.role == Role::Primary, "only primary decides")?;
        self.connection(|c| {
            recovery::activation::admission(c, self.role, &self.identity)?;
            let mut e = journal::by_operation(c, operation_id)?.ok_or("unknown operation")?;
            if e.state == State::Prepared {
                e.state = State::Decided;
                save(c, &e)?;
            }
            Ok(e)
        })
    }
    pub fn apply(&mut self, decision: Entry) -> Result<()> {
        decision.validate(&self.identity)?;
        ensure(
            decision.state != State::Prepared,
            "commit decision required",
        )?;
        self.connection(|c| {
            recovery::activation::admission(c, self.role, &self.identity)?;
            snapshot_staging::ensure_idle(c)?;
            let mut local = journal::by_sequence(c, decision.sequence)?.ok_or("not staged")?;
            ensure(local.digest == decision.digest, "decision mismatch")?;
            if local.state == State::Applied {
                receipts::validate_entry(c, &local)?;
                return Ok(());
            }
            ensure(
                self.role == Role::Secondary || local.state == State::Decided,
                "primary has no durable decision",
            )?;
            ensure(hash(&view(c)?)? == local.before, "base state mismatch")?;
            let verified = self.role == Role::Secondary
                && checkpoint::verified_view(c, &self.identity)?.is_some();
            let tx = c.unchecked_transaction()?;
            apply_changeset(&tx, &local)?;
            local.state = State::Applied;
            save(&tx, &local)?;
            if verified {
                checkpoint::advance(&tx, &self.identity)?;
            }
            // Crash after all writes, before the entity+journal+readiness transaction commits.
            #[cfg(feature = "test-support")]
            if std::env::var_os("VESTA_PROTOTYPE_CRASH_APPLY").is_some() {
                std::process::exit(86);
            }
            tx.commit()?;
            Ok(())
        })
    }
    pub fn abort(&mut self, operation_id: &str) -> Result<()> {
        self.connection(|c| {
            recovery::activation::admission(c, self.role, &self.identity)?;
            snapshot_staging::ensure_idle(c)?;
            if let Some(e) = journal::by_operation(c, operation_id)? {
                ensure(
                    e.state == State::Prepared && journal::tail(c)?.as_ref() == Some(&e),
                    "cannot abort committed/non-tail entry",
                )?;
                c.execute(
                    "DELETE FROM replication_log WHERE operation_id=?1",
                    [operation_id],
                )?;
            }
            Ok(())
        })
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        ensure(self.role == Role::Primary, "snapshot requires primary")?;
        self.connection(|c| {
            ensure(
                checkpoint::base(c)?.is_none(),
                "replay snapshot requires complete active history",
            )?;
            let receipt_digest = checkpoint::current(c, &self.identity, true)?
                .0
                .receipt_digest;
            let entries = entries(c)?;
            ensure(
                entries.iter().all(|e| e.state == State::Applied),
                "snapshot requires quiescent committed state",
            )?;
            let view = view(c)?;
            let digest = hash(&(&self.identity, &view, &entries, &receipt_digest))?;
            Ok(Snapshot {
                identity: self.identity.clone(),
                view,
                entries,
                digest,
                receipt_digest,
            })
        })
    }
    pub fn install(&mut self, snapshot: Snapshot) -> Result<()> {
        ensure(
            self.role == Role::Secondary && snapshot.identity == self.identity,
            "snapshot target mismatch",
        )?;
        ensure(
            snapshot.digest
                == hash(&(
                    &snapshot.identity,
                    &snapshot.view,
                    &snapshot.entries,
                    &snapshot.receipt_digest,
                ))?,
            "snapshot checksum mismatch",
        )?;
        self.connection(|c| {
            recovery::activation::bootstrap(c)?;
            snapshot_staging::ensure_idle(c)?;
            publication::ensure_absent(c)?;
            ensure(
                entries(c)?.is_empty()
                    && view(c)? == View::default()
                    && receipts::count(c)? == 0
                    && checkpoint::base(c)?.is_none(),
                "snapshot target must be empty",
            )?;
            let tx = c.unchecked_transaction()?;
            // Replay also validates ordering and every before/after checksum.
            journal::replay_history_in(
                &tx,
                &reference::Proximi,
                &self.identity,
                &snapshot.entries,
            )?;
            ensure(
                view(&tx)? == snapshot.view,
                "snapshot content/history mismatch",
            )?;
            ensure(
                checkpoint::current(&tx, &self.identity, true)?
                    .0
                    .receipt_digest
                    == snapshot.receipt_digest,
                "snapshot receipt mismatch",
            )?;
            tx.execute("DELETE FROM replication_readiness", [])?;
            tx.commit()?;
            Ok(())
        })
    }
}

/// Only the secondary-side operations cross the replication transport.
pub trait Replica<C = Change, I = u32, V = View> {
    /// Authenticated leaf pin (or owned local member identity) for recovered pairs.
    fn peer_identity(&self) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }
    /// Optional for legacy test adapters; activation requires this capability when floors differ.
    fn checkpoint_at(&mut self, _sequence: u64) -> Result<Checkpoint<I>> {
        Err("replica does not support checkpoint prefixes".into())
    }
    fn summary(&mut self) -> Result<journal::Summary<I>>;
    fn journal_page(
        &mut self,
        head: &journal::JournalHead<I>,
        after: u64,
        limit: u32,
    ) -> Result<journal::JournalPage<C, I>>;
    fn confirm_checkpoint(&mut self, checkpoint: Checkpoint<I>) -> Result<()>;
    fn status(&mut self) -> Result<Status<C, I>>;
    fn view(&mut self) -> Result<V>;
    fn stage(&mut self, entry: Entry<C, I>) -> Result<()>;
    fn apply(&mut self, entry: Entry<C, I>) -> Result<()>;
    fn abort(&mut self, operation_id: &str) -> Result<()>;
}

/// Local writer operations required by the shared fixed-pair engine. Implementors
/// own durable identity, role and recovery admission; this trait grants no authority.
pub trait Primary<C = Change, I = u32, V = View>: Replica<C, I, V> {
    fn journal_head(&self) -> Result<journal::JournalHead<I>>;
    fn required_recovery_peer(&self) -> Result<Option<[u8; 32]>>;
    fn checkpoint(&self) -> Result<Checkpoint<I>>;
    fn completed_result(&self, batch: &Batch<C, I>) -> Result<Option<WriteResult>>;
    fn prepare(&mut self, batch: Batch<C, I>) -> Result<Entry<C, I>>;
    fn decide(&mut self, operation_id: &str) -> Result<Entry<C, I>>;
    fn receipt(&self, operation_id: &str) -> Result<Option<OperationReceipt>>;
}

impl Primary for Node {
    fn journal_head(&self) -> Result<journal::JournalHead> {
        Node::journal_head(self)
    }
    fn required_recovery_peer(&self) -> Result<Option<[u8; 32]>> {
        Node::required_recovery_peer(self)
    }
    fn checkpoint(&self) -> Result<Checkpoint> {
        Node::checkpoint(self)
    }
    fn completed_result(&self, batch: &Batch) -> Result<Option<WriteResult>> {
        Node::completed_result(self, batch)
    }
    fn prepare(&mut self, batch: Batch) -> Result<Entry> {
        Node::prepare(self, batch)
    }
    fn decide(&mut self, operation_id: &str) -> Result<Entry> {
        Node::decide(self, operation_id)
    }
    fn receipt(&self, operation_id: &str) -> Result<Option<OperationReceipt>> {
        Node::receipt(self, operation_id)
    }
}
impl Replica for Node {
    fn peer_identity(&self) -> Result<Option<[u8; 32]>> {
        self.recovery_member_identity()
    }
    fn checkpoint_at(&mut self, sequence: u64) -> Result<Checkpoint> {
        Node::checkpoint_at(self, sequence)
    }
    fn summary(&mut self) -> Result<journal::Summary> {
        Node::summary(self)
    }
    fn journal_page(
        &mut self,
        head: &journal::JournalHead,
        after: u64,
        limit: u32,
    ) -> Result<journal::JournalPage> {
        Node::journal_page(self, head, after, limit)
    }
    fn confirm_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<()> {
        Node::confirm_checkpoint(self, checkpoint)
    }
    fn status(&mut self) -> Result<Status> {
        Node::status(self)
    }
    fn view(&mut self) -> Result<View> {
        Node::view(self)
    }
    fn stage(&mut self, entry: Entry) -> Result<()> {
        Node::stage(self, entry)
    }
    fn apply(&mut self, entry: Entry) -> Result<()> {
        Node::apply(self, entry)
    }
    fn abort(&mut self, operation_id: &str) -> Result<()> {
        Node::abort(self, operation_id)
    }
}

pub fn recover<C, I, V, P, R>(p: &mut P, s: &mut R) -> Result<usize>
where
    C: Clone + Serialize,
    I: Clone + Serialize + PartialEq,
    P: Primary<C, I, V>,
    R: Replica<C, I, V>,
{
    let ps = p.summary()?;
    let ss = s.summary()?;
    ensure(
        ps.schema_contract == ss.schema_contract,
        "replica schema contract mismatch",
    )?;
    ensure(
        ps.role == Role::Primary
            && ss.role == Role::Secondary
            && ps.membership == ss.membership
            && ps.head.identity == ss.head.identity,
        "pair mismatch",
    )?;
    if let Some(expected) = p.required_recovery_peer()? {
        ensure(
            s.peer_identity()? == Some(expected),
            "recovered replica identity mismatch",
        )?;
    }
    ensure(
        ps.synchronous == 2
            && ss.synchronous == 2
            && ps.journal_mode == "wal"
            && ss.journal_mode == "wal"
            && !ps.cipher_version.is_empty()
            && !ss.cipher_version.is_empty(),
        "durability profile mismatch",
    )?;
    ensure(
        ss.head.length <= ps.head.length,
        "secondary ahead of primary journal",
    )?;
    // Verify the entire shared prefix before any mutation. Byte budgets may produce
    // different page boundaries, so advance only through entries checked on both sides.
    let pf = ps.head.base.as_ref().map_or(0, |b| b.sequence);
    let sf = ss.head.base.as_ref().map_or(0, |b| b.sequence);
    let mut cursor = pf.max(sf);
    ensure(
        cursor <= ss.head.length,
        "secondary below active base; explicit snapshot required",
    )?;
    if ps.head.base.is_some() && (ss.head.base.is_none() || pf > sf) {
        let base = ps.head.base.as_ref().ok_or("missing primary base")?;
        ensure(
            s.checkpoint_at(pf)? == *base,
            "primary base differs from secondary history",
        )?;
    } else if let Some(base) = &ss.head.base {
        ensure(
            base.sequence <= ss.head.length && p.checkpoint_at(base.sequence)? == *base,
            "secondary base differs from primary history",
        )?;
    }
    let mut applied_prefix = cursor;
    while cursor < ss.head.length {
        let limit = (ss.head.length - cursor).min(journal::MAX_PAGE_ENTRIES as u64) as u32;
        let a = p.journal_page(&ps.head, cursor, limit)?;
        let b = s.journal_page(&ss.head, cursor, limit)?;
        a.validate(&ps.head, cursor, limit)?;
        b.validate(&ss.head, cursor, limit)?;
        let n = a.entries.len().min(b.entries.len());
        for (a, b) in a.entries.iter().zip(&b.entries) {
            ensure(a.digest == b.digest, "divergent journals")?;
            if applied_prefix == a.sequence - 1
                && a.state == State::Applied
                && b.state == State::Applied
            {
                applied_prefix += 1;
            }
        }
        cursor += n as u64;
    }
    ensure(
        p.journal_head()? == ps.head && s.summary()?.head == ss.head,
        "journal changed during comparison",
    )?;
    let mut completed = 0;
    cursor = applied_prefix;
    while cursor < ps.head.length {
        // Only this coordinator owns primary. Our own apply/abort advances its revision.
        let head = p.journal_head()?;
        let page = p.journal_page(&head, cursor, journal::MAX_PAGE_ENTRIES)?;
        for e in page.entries {
            cursor = e.sequence;
            if e.state == State::Prepared {
                s.abort(&e.batch.operation_id)?;
                p.abort(&e.batch.operation_id)?;
            } else {
                completed += 1;
                s.stage(e.clone())?;
                s.apply(e.clone())?;
                p.apply(e)?;
            }
        }
    }
    // Exact checkpoint equality checks both data and the full applied journal without
    // transporting the entire business view or journal in a single response.
    s.confirm_checkpoint(p.checkpoint()?)?;
    Ok(completed)
}
pub fn commit<C, I, V, P, R>(p: &mut P, s: &mut R, batch: Batch<C, I>) -> Result<WriteResult>
where
    C: Clone + Serialize,
    I: Clone + Serialize + PartialEq,
    P: Primary<C, I, V>,
    R: Replica<C, I, V>,
{
    recover(p, s)?;
    if let Some(result) = p.completed_result(&batch)? {
        return Ok(result);
    }
    let e = p.prepare(batch)?;
    s.stage(e.clone())?;
    let decision = p.decide(&e.batch.operation_id)?;
    s.apply(decision.clone())?;
    p.apply(decision.clone())?;
    Ok(p.receipt(&e.batch.operation_id)?
        .ok_or("missing committed receipt")?
        .result)
}
