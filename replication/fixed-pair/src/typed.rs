//! Schema-typed fixed-pair nodes using the shared commit and reconciliation engine.
//! Adapter code is trusted. An operation receipt is not a two-copy acknowledgement.
use crate::*;
use rusqlite::OptionalExtension;
use schema::{RequestSchema, SchemaId};
use serde::de::DeserializeOwned;
use std::sync::Arc;
pub mod capacity;
#[cfg(test)]
mod checkpoint_tests;
pub mod maintenance;
#[cfg(test)]
mod profile_tests;
pub mod recovery;
pub mod snapshot;

pub trait ReplicatedSchema:
    RequestSchema<
    Change: Clone + Serialize + DeserializeOwned + PartialEq,
    View: Clone + DeserializeOwned,
>
{
}
impl<A> ReplicatedSchema for A
where
    A: RequestSchema,
    A::Change: Clone + Serialize + DeserializeOwned + PartialEq,
    A::View: Clone + DeserializeOwned,
{
}

pub type Request<A> = Batch<<A as Schema>::Change, SchemaId>;
pub type Record<A> = Entry<<A as Schema>::Change, SchemaId>;
pub type Head = journal::JournalHead<SchemaId>;
pub type Prefix = Checkpoint<SchemaId>;
pub type Coordinator<A, R> =
    coordinator::Coordinator<R, Node<A>, <A as Schema>::Change, SchemaId, <A as Schema>::View>;

pub trait CertifiedAuthority: Send + Sync {
    fn fetch_completed(
        &self,
        request: &crate::recovery::transition::Request,
    ) -> terrapi_vesta_recovery::Result<crate::recovery::transition::CompletedTransition>;

    fn fetch_completed_revision(
        &self,
        request: &crate::recovery::transition::Request,
    ) -> terrapi_vesta_recovery::Result<crate::recovery::transition::HistoricalCompletedTransition>;

    /// Live writer authority for a completed participant-loss successor
    /// membership. The default denies, so an authority that knows nothing about
    /// participant loss keeps every loss-recovered node closed for ever. An
    /// install-only `CommittedLossSuccessorTransition` can never be returned.
    fn fetch_completed_loss_successor(
        &self,
        _request: &crate::recovery::transition::LossSuccessorRequest,
    ) -> terrapi_vesta_recovery::Result<crate::recovery::transition::CompletedLossSuccessorTransition>
    {
        Err("participant-loss completion authority missing".into())
    }
}

/// Take the node lock beside `path`. The file name is unchanged for
/// compatibility; only its nature is checked. A symlink, directory, FIFO or
/// device in that position is refused before and after the open, so the lock
/// can never be redirected at something else.
fn node_lock_path(path: &Path) -> std::path::PathBuf {
    path.with_extension("node-lock")
}

fn lock_regular_file(lock: &Path, create: bool) -> Result<File> {
    if let Ok(existing) = std::fs::symlink_metadata(lock) {
        ensure(existing.is_file(), "node lock is not a regular file")?;
    }
    let file = OpenOptions::new()
        .create(create)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock)?;
    ensure(
        file.metadata()?.is_file() && std::fs::symlink_metadata(lock)?.is_file(),
        "node lock is not a regular file",
    )?;
    file.try_lock()?;
    Ok(file)
}

/// Create the lock if it is missing. Used by the ordinary node open, which also
/// creates the database.
pub(crate) fn create_node_lock(path: &Path) -> Result<File> {
    lock_regular_file(&node_lock_path(path), true)
}

/// Take an existing lock only. Used by every restricted handle.
pub(crate) fn open_node_lock(path: &Path) -> Result<File> {
    lock_regular_file(&node_lock_path(path), false)
}

pub struct Node<A: ReplicatedSchema> {
    db: Vesta,
    adapter: A,
    identity: Identity<SchemaId>,
    role: Role,
    contract: schema_contract::Contract,
    initial: String,
    transition_trust: Option<crate::recovery::transition::TrustStore>,
    certified_authority: Option<Arc<dyn CertifiedAuthority>>,
    _lock: File,
}

impl<A: ReplicatedSchema> Node<A> {
    /// Create a missing path or reopen exactly the same typed node. Never adopt,
    /// migrate or repair an existing reference Node or unowned encrypted database.
    pub fn open(
        path: impl AsRef<Path>,
        role: Role,
        identity: Identity<SchemaId>,
        passphrase: &str,
        adapter: A,
    ) -> Result<Self> {
        Self::open_inner(path, role, identity, passphrase, adapter, None, None)
    }

    /// Experimental read-side configuration for externally trusted historical
    /// transition keys. This does not enable maintenance v3 or certified compaction.
    pub fn open_with_transition_trust(
        path: impl AsRef<Path>,
        role: Role,
        identity: Identity<SchemaId>,
        passphrase: &str,
        adapter: A,
        trust: crate::recovery::transition::TrustStore,
    ) -> Result<Self> {
        Self::open_inner(path, role, identity, passphrase, adapter, Some(trust), None)
    }

    pub fn open_with_completed_transition(
        path: impl AsRef<Path>,
        role: Role,
        identity: Identity<SchemaId>,
        passphrase: &str,
        adapter: A,
        trust: crate::recovery::transition::TrustStore,
        authority: Arc<dyn CertifiedAuthority>,
    ) -> Result<Self> {
        Self::open_inner(
            path,
            role,
            identity,
            passphrase,
            adapter,
            Some(trust),
            Some(authority),
        )
    }

    fn open_inner(
        path: impl AsRef<Path>,
        role: Role,
        identity: Identity<SchemaId>,
        passphrase: &str,
        adapter: A,
        transition_trust: Option<crate::recovery::transition::TrustStore>,
        certified_authority: Option<Arc<dyn CertifiedAuthority>>,
    ) -> Result<Self> {
        ensure(
            identity.schema == adapter.identity()
                && identity.epoch > 0
                && !identity.cluster.is_empty()
                && !identity.tenant.is_empty(),
            "invalid typed node identity",
        )?;
        snapshot::scope(&identity).validate()?;
        let scratch = Connection::open_in_memory()?;
        scratch.pragma_update(None, "foreign_keys", "ON")?;
        schema::initialize(&scratch, &adapter)?;
        let contract = schema_contract::describe(&scratch, &adapter)?;
        let initial = hash(&adapter.view(&scratch)?)?;
        let path = path.as_ref();
        let path = path
            .parent()
            .ok_or("missing parent")?
            .canonicalize()?
            .join(path.file_name().ok_or("missing filename")?);
        ensure(!path.is_symlink(), "symlink database unsupported")?;
        let lock = create_node_lock(&path)?;
        let existing = path.exists();
        let db = if existing {
            Vesta::open(&path, passphrase)?
        } else {
            Vesta::create(&path, passphrase, KdfParams::default())?
        };
        let node = Self {
            db,
            adapter,
            identity,
            role,
            contract,
            initial,
            transition_trust,
            certified_authority,
            _lock: lock,
        };
        node.connection(|c| {
            c.pragma_update(None, "synchronous", "FULL")?;
            c.pragma_update(None, "temp_store", "MEMORY")?;
            if existing {
                node.verify_owner(c)?;
                node.verify_current_certified(c)?;
            }
            if !existing {
                schema::initialize(c, &node.adapter)?;
                c.execute_batch("CREATE TABLE node_identity(value TEXT NOT NULL);
                    CREATE TABLE node_runtime(id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL,initial_digest TEXT NOT NULL);
                    CREATE TABLE replication_log(sequence INTEGER PRIMARY KEY,operation_id TEXT UNIQUE NOT NULL,entry TEXT NOT NULL);
                    CREATE TABLE replication_generation(id INTEGER PRIMARY KEY CHECK(id=1),value BLOB NOT NULL CHECK(length(value)=32));
                    CREATE TABLE replication_readiness(id INTEGER PRIMARY KEY CHECK(id=1),checkpoint TEXT NOT NULL);
                    CREATE TABLE operation_receipts(operation_id TEXT PRIMARY KEY NOT NULL,sequence INTEGER UNIQUE NOT NULL,receipt TEXT NOT NULL);
                    CREATE TABLE receipt_format(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
                    INSERT INTO receipt_format VALUES(1,1);
                    CREATE TABLE node_restore(id INTEGER PRIMARY KEY CHECK(id=1),manifest TEXT NOT NULL,progress INTEGER NOT NULL);
                    CREATE TABLE node_restore_pages(position INTEGER PRIMARY KEY,page TEXT NOT NULL);
                    CREATE TABLE node_restore_complete(id INTEGER PRIMARY KEY CHECK(id=1),manifest TEXT NOT NULL);
                    CREATE TABLE node_publication(id INTEGER PRIMARY KEY CHECK(id=1),manifest TEXT NOT NULL);
                    CREATE TABLE node_publication_pages(position INTEGER PRIMARY KEY,page TEXT NOT NULL);")?;
                c.execute("INSERT INTO node_identity VALUES(?1)", [serde_json::to_string(&(&node.identity, node.role))?])?;
                c.execute("INSERT INTO node_runtime VALUES(1,1,?1)", [&node.initial])?;
                checkpoint::initialize(c)?;
                journal::initialize(c)?;
                schema_contract::install(c, &node.adapter, &node.contract)?;
                sql_snapshot::bind(c, &node.adapter, &snapshot::scope(&node.identity))?;
            }
            node.verify_owner(c)?;
            let restoring: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM node_restore)", [], |r| r.get(0))?;
            if restoring { node.restore_manifest_in(c)?; } else { node.current(c, false)?; }
            capacity::verify_accounting(c)?;
            Ok(())
        })?;
        Ok(node)
    }

    fn connection<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.db.with_connection(|c| Ok(f(c)))?
    }
    fn verify_owner(&self, c: &Connection) -> Result<()> {
        self.verify_owner_as(c, self.role)
    }
    fn verify_current_certified(&self, c: &Connection) -> Result<()> {
        // A node whose participant-loss successor membership is installed can
        // never present its pre-loss certificate as a live head again: the
        // source authority reports it superseded. It is checked as history,
        // and a live authority is required whatever the maintenance format is.
        if maintenance::loss::state(c)?.is_some() {
            return maintenance::loss::verify_certified_history(
                c,
                self.certified_authority.as_deref(),
            );
        }
        maintenance::verify_current_certified(c, self.certified_authority.as_deref())
    }
    fn verify_owner_as(&self, c: &Connection, role: Role) -> Result<()> {
        let identities: Vec<String> = c
            .prepare("SELECT value FROM node_identity")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        ensure(
            identities == [serde_json::to_string(&(&self.identity, role))?],
            "typed node owner mismatch",
        )?;
        let runtime: Vec<(u32, String)> = c
            .prepare("SELECT format,initial_digest FROM node_runtime")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        ensure(
            runtime.len() == 1 && runtime[0].1 == self.initial,
            "typed node runtime mismatch",
        )?;
        let maintenance_format = maintenance::history_format(c, runtime[0].0)?;
        recovery::verify_history(c, maintenance_format)?;
        maintenance::verify_certified(c, self.transition_trust.as_ref())?;
        capacity::verify_schema(c)?;
        let versions: Vec<u32> = c
            .prepare("SELECT version FROM checkpoint_format")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let sealed: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='recovery_seal')",
            [],
            |r| r.get(0),
        )?;
        ensure(
            versions == [if sealed { 2 } else { 1 }],
            "typed node metadata format mismatch",
        )?;
        schema_contract::verify(c, &self.adapter, &self.contract)?;
        sql_snapshot::verify_binding(c, &self.adapter, &snapshot::scope(&self.identity))
    }
    fn admission(&self, c: &Connection) -> Result<()> {
        // With a participant-loss successor membership installed, ordinary
        // admission needs the durable local completion receipt *and* a live
        // completed-successor proof equal to it. Without one it is a no-op and
        // every other check below is exactly what it always was.
        maintenance::loss::admission(
            c,
            &self.identity,
            self.role,
            self.certified_authority.as_deref(),
        )?;
        self.verify_owner(c)?;
        self.verify_current_certified(c)?;
        maintenance::compaction::require_idle(c)?;
        let blocked: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM node_restore)", [], |r| {
            r.get(0)
        })?;
        ensure(
            !blocked,
            "typed node restoration/recovery requires completion",
        )?;
        self.recovery_admission(c)?;
        let synchronous: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        ensure(
            synchronous == 2 && mode == "wal",
            "typed node durability mismatch",
        )
    }
    fn current(&self, c: &Connection, quiescent: bool) -> Result<(Prefix, A::View)> {
        checkpoint::current_for(c, &self.adapter, &self.identity, &self.initial, quiescent)
    }
    fn save(&self, c: &Connection, entry: &Record<A>) -> Result<()> {
        journal::store::write(c, entry)?;
        if entry.state == State::Applied {
            receipts::insert_for(c, &self.adapter, entry)?;
        }
        Ok(())
    }
    pub fn identity(&self) -> &Identity<SchemaId> {
        &self.identity
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn schema_contract(&self) -> Result<schema_contract::Contract> {
        self.connection(|c| {
            self.verify_owner(c)?;
            Ok(self.contract.clone())
        })
    }
    pub fn view(&self) -> Result<A::View> {
        self.connection(|c| {
            self.verify_owner(c)?;
            self.adapter.view(c)
        })
    }
    pub fn checkpoint(&self) -> Result<Prefix> {
        self.connection(|c| {
            self.admission(c)?;
            Ok(self.current(c, true)?.0)
        })
    }
    pub fn journal_head(&self) -> Result<Head> {
        self.connection(|c| {
            self.admission(c)?;
            journal::head_for(c, &self.identity)
        })
    }
    pub fn receipt(&self, id: &str) -> Result<Option<OperationReceipt>> {
        self.connection(|c| {
            self.admission(c)?;
            if let Some(e) = journal::store::by_operation::<A::Change, SchemaId>(c, id)? {
                e.validate(&self.identity)?;
                receipts::validate_entry_for(c, &self.adapter, &e)
            } else {
                let r = receipts::get_for(c, &self.adapter, id)?;
                if let Some(r) = &r {
                    let base = checkpoint::base_for::<SchemaId>(c)?.ok_or("orphan receipt")?;
                    ensure(r.result.sequence <= base.sequence, "orphan receipt")?;
                    self.current(c, false)?;
                }
                Ok(r)
            }
        })
    }
    pub fn completed_result(&self, batch: &Request<A>) -> Result<Option<WriteResult>> {
        ensure(
            batch.identity == self.identity && !batch.operation_id.is_empty(),
            "invalid request scope",
        )?;
        self.receipt(&batch.operation_id)?
            .map(|r| {
                r.matches_request(&self.adapter, batch)?;
                Ok(r.result)
            })
            .transpose()
    }
    pub fn prepare(&mut self, batch: Request<A>) -> Result<Record<A>> {
        ensure(
            self.role == Role::Primary
                && batch.identity == self.identity
                && !batch.operation_id.is_empty(),
            "invalid primary request",
        )?;
        self.connection(|c| {
            self.admission(c)?;
            if let Some(e) =
                journal::store::by_operation::<A::Change, SchemaId>(c, &batch.operation_id)?
            {
                e.validate(&self.identity)?;
                receipts::validate_entry_for(c, &self.adapter, &e)?;
                ensure(e.batch == batch, "idempotency key conflict")?;
                if e.state == State::Prepared {
                    self.check_write_capacity(c, &e)?;
                }
                return Ok(e);
            }
            ensure(
                receipts::get_for(c, &self.adapter, &batch.operation_id)?.is_none(),
                "historical operation requires receipt retry",
            )?;
            ensure(journal::resolved(c)?, "recovery required")?;
            self.current(c, true)?;
            let sequence = journal::head_for(c, &self.identity)?
                .length
                .checked_add(1)
                .ok_or("sequence overflow")?;
            let captured = schema::capture(c, &self.adapter, &batch.changes)?;
            let mut e = Entry {
                batch,
                sequence,
                before: captured.before,
                after: captured.after,
                changeset: captured.changeset,
                digest: String::new(),
                state: State::Prepared,
            };
            e.digest = e.checksum()?;
            journal::check_entry_size(&e)?;
            self.check_write_capacity(c, &e)?;
            self.save(c, &e)?;
            Ok(e)
        })
    }
    pub fn stage(&mut self, entry: Record<A>) -> Result<()> {
        ensure(self.role == Role::Secondary, "only secondary stages")?;
        entry.validate(&self.identity)?;
        journal::check_entry_size(&entry)?;
        self.connection(|c| {
            self.admission(c)?;
            if let Some(old) =
                journal::store::by_sequence::<A::Change, SchemaId>(c, entry.sequence)?
            {
                old.validate(&self.identity)?;
                receipts::validate_entry_for(c, &self.adapter, &old)?;
                ensure(old.digest == entry.digest, "divergent log")?;
                if old.state == State::Prepared {
                    self.check_write_capacity(c, &old)?;
                }
                return Ok(());
            }
            ensure(
                entry.sequence == journal::head_for(c, &self.identity)?.length + 1
                    && journal::resolved(c)?,
                "out-of-order stage",
            )?;
            self.check_write_capacity(c, &entry)?;
            let mut e = entry;
            e.state = State::Prepared;
            self.save(c, &e)
        })
    }
    pub fn decide(&mut self, id: &str) -> Result<Record<A>> {
        ensure(self.role == Role::Primary, "only primary decides")?;
        self.connection(|c| {
            self.admission(c)?;
            let mut e = journal::store::by_operation::<A::Change, SchemaId>(c, id)?
                .ok_or("unknown operation")?;
            e.validate(&self.identity)?;
            receipts::validate_entry_for(c, &self.adapter, &e)?;
            if e.state == State::Prepared {
                self.check_write_capacity(c, &e)?;
                e.state = State::Decided;
                self.save(c, &e)?;
            }
            Ok(e)
        })
    }
    pub fn apply(&mut self, decision: Record<A>) -> Result<()> {
        decision.validate(&self.identity)?;
        ensure(
            decision.state != State::Prepared,
            "commit decision required",
        )?;
        self.connection(|c| {
            self.admission(c)?;
            let mut e = journal::store::by_sequence::<A::Change, SchemaId>(c, decision.sequence)?
                .ok_or("not staged")?;
            e.validate(&self.identity)?;
            ensure(e.digest == decision.digest, "decision mismatch")?;
            if e.state == State::Applied {
                receipts::validate_entry_for(c, &self.adapter, &e)?;
                return Ok(());
            }
            ensure(
                self.role == Role::Secondary || e.state == State::Decided,
                "primary has no durable decision",
            )?;
            let verified = self.verified_view_in(c)?.is_some();
            let tx = c.unchecked_transaction()?;
            schema::replay_data(
                &tx,
                &self.adapter,
                &self.identity.schema,
                &e.before,
                &e.after,
                &e.changeset,
            )?;
            e.state = State::Applied;
            self.save(&tx, &e)?;
            if verified {
                let cp = self.current(&tx, true)?.0;
                tx.execute(
                    "UPDATE replication_readiness SET checkpoint=?1 WHERE id=1",
                    [serde_json::to_string(&cp)?],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
    }
    pub fn abort(&mut self, id: &str) -> Result<()> {
        self.connection(|c| {
            self.admission(c)?;
            if let Some(e) = journal::store::by_operation::<A::Change, SchemaId>(c, id)? {
                e.validate(&self.identity)?;
                ensure(
                    e.state == State::Prepared
                        && journal::store::tail::<A::Change, SchemaId>(c)?.as_ref() == Some(&e),
                    "cannot abort committed/non-tail operation",
                )?;
                c.execute("DELETE FROM replication_log WHERE operation_id=?1", [id])?;
            }
            Ok(())
        })
    }
    fn verified_view_in(&self, c: &Connection) -> Result<Option<A::View>> {
        let marker: Option<String> = c
            .query_row(
                "SELECT checkpoint FROM replication_readiness WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(marker) = marker else {
            return Ok(None);
        };
        let expected: Prefix = serde_json::from_str(&marker)?;
        let (actual, view) = self.current(c, false)?;
        ensure(actual == expected, "read-admission checkpoint mismatch")?;
        Ok(Some(view))
    }
    pub fn verified_view(&self) -> Result<Option<A::View>> {
        self.connection(|c| {
            self.admission(c)?;
            self.verified_view_in(c)
        })
    }
    pub fn confirm_checkpoint(&mut self, expected: Prefix) -> Result<()> {
        ensure(
            self.role == Role::Secondary,
            "read admission requires secondary",
        )?;
        self.connection(|c| {
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            ensure(self.current(&tx, true)?.0 == expected, "checkpoint mismatch")?;
            tx.execute("INSERT INTO replication_readiness VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint", [serde_json::to_string(&expected)?])?;
            tx.commit()?;
            Ok(())
        })
    }
    pub fn summary(&self) -> Result<journal::Summary<SchemaId>> {
        self.connection(|c| {
            self.admission(c)?;
            Ok(journal::Summary {
                schema_contract: self.contract.clone(),
                membership: self.recovery_membership(c)?,
                head: journal::head_for(c, &self.identity)?,
                role: self.role,
                cipher_version: c.query_row("PRAGMA cipher_version", [], |r| r.get(0))?,
                synchronous: c.query_row("PRAGMA synchronous", [], |r| r.get(0))?,
                journal_mode: c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?,
            })
        })
    }
    pub fn status(&self) -> Result<Status<A::Change, SchemaId>> {
        let s = self.summary()?;
        self.connection(|c| {
            Ok(Status {
                read_generation: s.head.read_generation,
                identity: self.identity.clone(),
                role: self.role,
                cipher_version: s.cipher_version,
                synchronous: s.synchronous,
                journal_mode: s.journal_mode,
                entries: journal::store::all(c)?,
            })
        })
    }
    pub fn journal_page(
        &self,
        expected: &Head,
        after: u64,
        limit: u32,
    ) -> Result<journal::JournalPage<A::Change, SchemaId>> {
        ensure(
            limit > 0
                && limit <= journal::MAX_PAGE_ENTRIES
                && after <= expected.length
                && after >= expected.base.as_ref().map_or(0, |b| b.sequence),
            "invalid page cursor",
        )?;
        self.connection(|c| {
            self.admission(c)?;
            let tx = c.unchecked_transaction()?;
            ensure(journal::head_for(&tx, &self.identity)? == *expected, "stale journal cursor")?;
            let mut stmt = tx.prepare("SELECT sequence,operation_id,length(CAST(entry AS BLOB)),entry FROM replication_log WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?;
            let mut rows = stmt.query(params![after, limit])?;
            let mut entries = Vec::new();
            let mut bytes = 0;
            while let Some(row) = rows.next()? {
                let size: usize = row.get(2)?;
                ensure(size < journal::MAX_PAGE_BYTES, "entry too large")?;
                if bytes + size + 1 > journal::MAX_PAGE_BYTES { break; }
                let e: Record<A> = serde_json::from_str(&row.get::<_, String>(3)?)?;
                ensure(e.sequence == row.get::<_, u64>(0)? && e.batch.operation_id == row.get::<_, String>(1)?, "stored journal key mismatch")?;
                bytes += size + 1;
                entries.push(e);
            }
            let page = journal::JournalPage { head: expected.clone(), after, entries };
            page.validate(expected, after, limit)?;
            Ok(page)
        })
    }
}

impl<A: ReplicatedSchema> Replica<A::Change, SchemaId, A::View> for Node<A> {
    fn peer_identity(&self) -> Result<Option<[u8; 32]>> {
        self.recovery_member_identity()
    }
    fn summary(&mut self) -> Result<journal::Summary<SchemaId>> {
        Node::summary(self)
    }
    fn journal_page(
        &mut self,
        h: &Head,
        after: u64,
        limit: u32,
    ) -> Result<journal::JournalPage<A::Change, SchemaId>> {
        Node::journal_page(self, h, after, limit)
    }
    fn checkpoint_at(&mut self, sequence: u64) -> Result<Prefix> {
        self.connection(|c| {
            self.admission(c)?;
            checkpoint::calculate_for(
                c,
                &self.adapter,
                &self.identity,
                &self.initial,
                true,
                Some(sequence),
            )
        })
    }
    fn confirm_checkpoint(&mut self, c: Prefix) -> Result<()> {
        Node::confirm_checkpoint(self, c)
    }
    fn status(&mut self) -> Result<Status<A::Change, SchemaId>> {
        Node::status(self)
    }
    fn view(&mut self) -> Result<A::View> {
        Node::view(self)
    }
    fn stage(&mut self, e: Record<A>) -> Result<()> {
        Node::stage(self, e)
    }
    fn apply(&mut self, e: Record<A>) -> Result<()> {
        Node::apply(self, e)
    }
    fn abort(&mut self, id: &str) -> Result<()> {
        Node::abort(self, id)
    }
}
impl<A: ReplicatedSchema> Primary<A::Change, SchemaId, A::View> for Node<A> {
    fn journal_head(&self) -> Result<Head> {
        Node::journal_head(self)
    }
    fn required_recovery_peer(&self) -> Result<Option<[u8; 32]>> {
        Node::required_recovery_peer(self)
    }
    fn checkpoint(&self) -> Result<Prefix> {
        Node::checkpoint(self)
    }
    fn completed_result(&self, b: &Request<A>) -> Result<Option<WriteResult>> {
        Node::completed_result(self, b)
    }
    fn prepare(&mut self, b: Request<A>) -> Result<Record<A>> {
        Node::prepare(self, b)
    }
    fn decide(&mut self, id: &str) -> Result<Record<A>> {
        Node::decide(self, id)
    }
    fn receipt(&self, id: &str) -> Result<Option<OperationReceipt>> {
        Node::receipt(self, id)
    }
}

impl<A: ReplicatedSchema> coordinator::CoordinatedPrimary<A::Change, SchemaId, A::View>
    for Node<A>
{
    fn role(&self) -> Role {
        self.role
    }
    fn identity(&self) -> &Identity<SchemaId> {
        &self.identity
    }
    fn local_view(&self) -> Result<A::View> {
        self.connection(|c| {
            self.admission(c)?;
            Ok(self.current(c, false)?.1)
        })
    }
    fn local_status(&self) -> Result<Status<A::Change, SchemaId>> {
        Node::status(self)
    }
    fn operation(&self, id: &str) -> Result<Option<Record<A>>> {
        self.connection(|c| {
            self.admission(c)?;
            let entry = journal::store::by_operation::<A::Change, SchemaId>(c, id)?;
            if let Some(e) = &entry {
                e.validate(&self.identity)?;
                receipts::validate_entry_for(c, &self.adapter, e)?;
            }
            Ok(entry)
        })
    }
    fn receipt_matches(&self, r: &OperationReceipt, b: &Request<A>) -> Result<()> {
        r.matches_request(&self.adapter, b)
    }
    fn ensure_write_ready(&self) -> Result<()> {
        self.connection(|c| self.admission(c))
    }
}
