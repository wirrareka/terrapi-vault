//! Strict ES256 verification for authority-approved checkpoint transitions.
//!
//! The external issuer must authenticate both participants' frozen evidence before
//! signing. Verification proves only that a configured trusted key signed the exact
//! request. It does not provide fencing, durable participant acknowledgements, or an
//! anti-rollback witness.
use super::{grant::Profile, model::Id};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::signature;
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    time::Duration,
};
use terrapi_vesta::{KdfParams, Vesta};
mod loss;
pub use loss::*;

const MAX_TOKEN: usize = 64 * 1024;
const MAX_TEXT: usize = 512;
const MAX_RECORD: usize = 256 * 1024;
/// Hard row cap on the append-only `main.transition_abort` table. Checked
/// before any row is decoded.
const MAX_ABORT_ROWS: usize = 4096;
pub const TOKEN_TYPE: &str = "terrapi-checkpoint-transition+jwt";
pub const ABORT_TOKEN_TYPE: &str = "terrapi-maintenance-abort+jwt";
/// Member added to the stored scope row the first time this journal records
/// state an older binary cannot see. Old readers decode `JournalScope` with
/// `deny_unknown_fields`, so its presence makes them fail closed.
const JOURNAL_FORMAT_MARKER: &str = "journal_format";
const JOURNAL_FORMAT_TWO: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub sequence: u64,
    pub digest: Id,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub member: Id,
    pub generation: Id,
    pub old_base: Option<Checkpoint>,
    pub target: Checkpoint,
    pub plan: Id,
    pub publication: Id,
}

/// Participants are canonically ordered primary, then secondary/survivor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub format: u32,
    pub id: Id,
    pub authority_id: Id,
    pub revision: u64,
    pub install: String,
    pub region: String,
    pub scope: Id,
    pub schema: Id,
    pub membership: Id,
    pub source_anchor: Checkpoint,
    pub participants: [Participant; 2],
}

impl Request {
    pub fn validate(&self) -> Result<(), &'static str> {
        let [primary, secondary] = &self.participants;
        if self.format != 1
            || self.id == [0; 32]
            || self.authority_id == [0; 32]
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.scope == [0; 32]
            || self.schema == [0; 32]
            || self.membership == [0; 32]
            || !valid_text(&self.install)
            || !valid_text(&self.region)
            || !valid_checkpoint(&self.source_anchor)
            || primary.member == [0; 32]
            || secondary.member == [0; 32]
            || primary.member == secondary.member
            || primary.generation == [0; 32]
            || secondary.generation == [0; 32]
            || primary.generation == secondary.generation
            || primary.plan == [0; 32]
            || secondary.plan == [0; 32]
            || primary.plan != secondary.plan
            || primary.publication == [0; 32]
            || secondary.publication == [0; 32]
            || !valid_target(&primary.target)
            || primary.target != secondary.target
            || primary.target.sequence <= self.source_anchor.sequence
            || self.participants.iter().any(|p| {
                p.old_base.as_ref().is_some_and(|base| {
                    !valid_checkpoint(base) || base.sequence >= p.target.sequence
                })
            })
        {
            Err("invalid transition request")
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Result<Id, &'static str> {
        self.validate()?;
        let json = serde_json::to_vec(self).map_err(|_| "request encoding")?;
        Ok(Sha256::digest(json).into())
    }
}

/// Authority-signed cancellation of an in-flight certified maintenance
/// transition. It is *not* a transition: it applies nothing, it chains to
/// nothing and it can never authorize a write. It only burns a journal
/// revision so that the cancelled attempt can never be revived.
///
/// Two shapes, discriminated by [`MaintenanceAbort::decided`]:
///
/// * `decided == true` — a decided record exists at `aborted_revision`; it has
///   no completion and is not acknowledged by both participants.
/// * `decided == false` — nothing was ever decided; the abort takes the next
///   free revision (`last_revision + 1`) so the counter stays monotonic.
///
/// `revision` is the journal revision the abort occupies and must equal
/// `aborted_revision`; it exists so the signed shape matches every other
/// journal request and the field can never be padding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceAbort {
    pub format: u32,
    pub id: Id,
    pub authority_id: Id,
    pub revision: u64,
    pub install: String,
    pub region: String,
    pub scope: Id,
    pub schema: Id,
    pub membership: Id,
    /// `Request::digest` of the cancelled transition request.
    pub aborted_request: Id,
    pub aborted_request_id: Id,
    pub aborted_revision: u64,
    pub decided: bool,
    pub source_anchor: Checkpoint,
}

impl MaintenanceAbort {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.format != 2
            || self.id == [0; 32]
            || self.authority_id == [0; 32]
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || !valid_text(&self.install)
            || !valid_text(&self.region)
            || self.scope == [0; 32]
            || self.schema == [0; 32]
            || self.membership == [0; 32]
            || self.aborted_request == [0; 32]
            || self.aborted_request_id == [0; 32]
            || self.aborted_revision == 0
            || self.aborted_revision > i64::MAX as u64
            || self.revision != self.aborted_revision
            || !valid_checkpoint(&self.source_anchor)
        {
            Err("invalid maintenance abort")
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Result<Id, &'static str> {
        self.validate()?;
        let json = serde_json::to_vec(self).map_err(|_| "maintenance abort encoding")?;
        Ok(Sha256::digest(json).into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalScope {
    pub install: String,
    pub region: String,
    pub profile: Profile,
    pub scope: Id,
    pub schema: Id,
    pub membership: Id,
    pub source_anchor: Checkpoint,
    pub authority_id: Id,
    pub initial_revision: u64,
}

pub trait Policy {
    /// Must check the external durable authority head/reservation for this revision.
    ///
    /// # Post-abort contract
    ///
    /// A [`Journal::abort`] permanently consumes a journal revision without
    /// producing a transition. After an abort the journal's reservation
    /// counter (`Status::last_revision`) is therefore **strictly greater**
    /// than the revision of the *effective* head that this hook is called
    /// with, and the gap grows by one with every further abort. An
    /// implementation that equates the two — for example one that requires
    /// `request.revision == authority.reservation` — will reject every
    /// post-abort read and brick the pair.
    ///
    /// The steady state an implementation must accept is: reservation =
    /// `last_revision`, live certificate = `last_revision - k` for `k` equal
    /// to the number of consumed-but-never-completed revisions. The next
    /// [`Journal::decide`] must use `last_revision + 1` while still chaining
    /// its `old_base` to the effective head.
    fn continuity(&self, scope: &JournalScope, request: &Request) -> super::Result<()>;
    fn prepared(
        &self,
        scope: &JournalScope,
        request: &Request,
        member: &Participant,
    ) -> super::Result<()>;
    fn applied(
        &self,
        scope: &JournalScope,
        decision: &CommittedTransition,
        member: &Participant,
    ) -> super::Result<()>;

    /// Authorize inspection of a completed transition that has been
    /// superseded by `current_head`. Implementations must check the live
    /// external authority state; a historical signature alone is not an
    /// authorization to use old authority state.
    fn historical_completion(
        &self,
        _scope: &JournalScope,
        _historical: &Request,
        _current_head: &Request,
    ) -> super::Result<()> {
        Err("historical transition not authorized".into())
    }

    /// Authorize a [`Journal::abort`]. The default is deliberately deny: a
    /// signed abort token is an *instruction*, never evidence that the
    /// participants are in a state in which nothing was applied.
    ///
    /// An implementation **must** do both of the following, and neither is
    /// done for it anywhere else:
    ///
    /// 1. **Check the external authority's live head/reservation for
    ///    `abort.aborted_revision` itself.** [`Policy::continuity`] is called
    ///    around this hook only when the journal has an effective head; for a
    ///    never-decided abort on an empty journal — the first-ever certified
    ///    PREPARE that expired, which is the case this whole mechanism exists
    ///    for — there is no [`Request`] to pass and `continuity` never fires.
    ///    On that path `abort_applicable` is the *only* authority gate.
    /// 2. **Prove from live participant evidence that neither node has
    ///    applied the transition**, i.e. that both are durably in the
    ///    node-side aborting phase. A journal transaction cannot observe the
    ///    node files, so a node that is still able to roll the decision
    ///    forward after a restart would otherwise diverge from the journal.
    fn abort_applicable(
        &self,
        _scope: &JournalScope,
        _abort: &MaintenanceAbort,
    ) -> super::Result<()> {
        Err("maintenance abort evidence missing".into())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    request: Request,
    token: String,
    acknowledgements: [bool; 2],
    completion: Option<Id>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AbortRecord {
    format: u32,
    abort: MaintenanceAbort,
    token: String,
    certificate_id: Id,
}

struct History {
    /// The *effective* head: the last history record whose revision was not
    /// consumed by an abort. `None` for an empty journal and for a journal
    /// whose every record was aborted.
    head: Option<Record>,
    /// The last non-aborted record that actually completed. Equal to `head`
    /// whenever the head is completed; otherwise the record the head chains
    /// to, which is the certificate the pair is still live on.
    completed: Option<Record>,
    ids: HashSet<Id>,
    aborts: BTreeMap<u64, AbortRecord>,
    /// The highest revision consumed by any history record or abort, `None`
    /// when nothing has been consumed yet.
    consumed: Option<u64>,
    /// `consumed` defaulted to `scope.initial_revision - 1`.
    last_revision: u64,
}

impl History {
    fn aborted_request_id(&self, id: Id) -> bool {
        self.aborts
            .values()
            .any(|r| r.abort.aborted_request_id == id)
    }
}

#[derive(Clone)]
pub struct CommittedTransition {
    request: Request,
    token: String,
    token_digest: Id,
    certificate_id: Id,
    acknowledgements: [bool; 2],
    completion: Option<Id>,
}

/// Opaque proof that the current durable authority head was re-read under the
/// caller's live continuity policy and contains both acknowledgements and its
/// immutable completion identifier. It is deliberately not serializable: a
/// persisted node record must be matched against a freshly fetched value after
/// restart rather than promoting local bytes into authority evidence.
pub struct CompletedTransition {
    committed: CommittedTransition,
    completion: Id,
}

/// Opaque, read-only evidence for a completed transition that has been
/// superseded by the current journal head. This is intentionally a distinct
/// provenance type from [`CompletedTransition`]: it cannot authorize current
/// writer admission or finalization.
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{CompletedTransition, HistoricalCompletedTransition};
/// fn admit_current(_: CompletedTransition) {}
/// fn historical_is_inspection_only(proof: HistoricalCompletedTransition) {
///     admit_current(proof);
/// }
/// ```
pub struct HistoricalCompletedTransition {
    request: Request,
    token: String,
    token_digest: Id,
    certificate_id: Id,
    completion: Id,
}
/// Opaque, durable proof that a certified maintenance transition was
/// cancelled by the authority. It authorizes local *rollback* only.
///
/// It is deliberately a distinct provenance type with no conversion to or
/// from a transition proof: an abort is the evidence that nothing was
/// applied, so accepting it anywhere a [`CommittedTransition`] or a
/// [`CompletedTransition`] is accepted would open writer admission on a
/// transition that never happened.
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{CommittedMaintenanceAbort, CommittedTransition};
/// fn takes_decision(_: CommittedTransition) {}
/// fn abort_is_not_a_decision(proof: CommittedMaintenanceAbort) {
///     takes_decision(proof);
/// }
/// ```
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{CommittedMaintenanceAbort, CompletedTransition};
/// fn admit_writes(_: CompletedTransition) {}
/// fn abort_cannot_admit(proof: CommittedMaintenanceAbort) {
///     admit_writes(proof);
/// }
/// ```
#[derive(Clone)]
pub struct CommittedMaintenanceAbort {
    abort: MaintenanceAbort,
    token: String,
    token_digest: Id,
    certificate_id: Id,
}

impl CommittedMaintenanceAbort {
    pub fn abort(&self) -> &MaintenanceAbort {
        &self.abort
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }
    pub fn aborted_request(&self) -> Id {
        self.abort.aborted_request
    }
    pub fn aborted_revision(&self) -> u64 {
        self.abort.aborted_revision
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The effective head; see [`Journal::abort`].
    pub request: Option<Request>,
    pub acknowledgements: [bool; 2],
    pub completion: Option<Id>,
    /// The highest consumed revision, including revisions consumed by aborts.
    /// The next decision must use `last_revision + 1`.
    pub last_revision: u64,
    /// Number of revisions permanently consumed by a maintenance abort.
    pub aborted: u64,
}
impl CommittedTransition {
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }
    pub fn acknowledgements(&self) -> [bool; 2] {
        self.acknowledgements
    }
    pub fn completion(&self) -> Option<Id> {
        self.completion
    }
}

impl CompletedTransition {
    pub fn request(&self) -> &Request {
        self.committed.request()
    }

    pub fn token(&self) -> &str {
        self.committed.token()
    }

    pub fn token_digest(&self) -> Id {
        self.committed.token_digest()
    }

    pub fn certificate_id(&self) -> Id {
        self.committed.certificate_id()
    }

    pub fn completion(&self) -> Id {
        self.completion
    }
}

impl HistoricalCompletedTransition {
    pub fn request(&self) -> &Request {
        &self.request
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn token_digest(&self) -> Id {
        self.token_digest
    }

    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }

    pub fn completion(&self) -> Id {
        self.completion
    }
}

pub struct Journal {
    db: Vesta,
    scope: JournalScope,
}
impl JournalScope {
    fn validate(&self) -> Result<(), &'static str> {
        if !valid_text(&self.install)
            || !valid_text(&self.region)
            || self.scope == [0; 32]
            || self.schema == [0; 32]
            || self.membership == [0; 32]
            || self.authority_id == [0; 32]
            || self.initial_revision == 0
            || self.initial_revision > i64::MAX as u64
            || !valid_checkpoint(&self.source_anchor)
        {
            Err("invalid transition journal scope")
        } else {
            self.profile.validate()
        }
    }
}
impl Journal {
    pub fn create(path: &Path, passphrase: &str, scope: JournalScope) -> super::Result<Self> {
        scope.validate()?;
        super::ensure(
            !path.exists() && !passphrase.is_empty(),
            "invalid transition journal initialization",
        )?;
        let db = Vesta::create(path, passphrase, KdfParams::default())?;
        let this = Self { db, scope };
        this.connection(|c|{c.execute_batch("CREATE TABLE transition_scope(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL); CREATE TABLE transition_head(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL); CREATE TABLE transition_history(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32));")?; c.execute("INSERT INTO transition_scope VALUES(1,?1)",[serde_json::to_string(&this.scope)?])?; c.execute("INSERT INTO transition_head VALUES(1,?1)",[this.scope.initial_revision-1])?; Ok(())})?;
        Ok(this)
    }
    pub fn open(
        path: &Path,
        passphrase: &str,
        scope: JournalScope,
        trust: &Trust<'_>,
    ) -> super::Result<Self> {
        scope.validate()?;
        super::ensure(
            path.is_file() && !passphrase.is_empty(),
            "transition journal absent",
        )?;
        let this = Self {
            db: Vesta::open(path, passphrase)?,
            scope,
        };
        this.connection(|c| {
            let tx = c.unchecked_transaction()?;
            this.read(&tx, trust).map(|_| ())
        })?;
        Ok(this)
    }
    fn connection<T>(&self, f: impl FnOnce(&Connection) -> super::Result<T>) -> super::Result<T> {
        self.db.with_connection(|c| {
            c.busy_timeout(Duration::from_secs(5))?;
            c.pragma_update(None, "synchronous", "FULL")?;
            Ok(f(c))
        })?
    }
    fn read(&self, c: &Connection, trust: &Trust<'_>) -> super::Result<History> {
        self.read_with_revision(c, trust, None)
            .map(|(history, _)| history)
    }

    fn read_with_revision(
        &self,
        c: &Connection,
        trust: &Trust<'_>,
        revision: Option<u64>,
    ) -> super::Result<(History, Option<Record>)> {
        super::ensure(
            trust.profile == &self.scope.profile,
            "transition trust profile mismatch",
        )?;
        validate_successor_parent(c, trust, &self.scope)?;
        self.ensure_journal_format(c)?;
        let aborts = self.read_aborts(c, trust)?;
        let mut pending = aborts.keys().copied().peekable();
        let mut stmt =
            c.prepare("SELECT revision,record,digest FROM transition_history ORDER BY revision")?;
        let mut rows = stmt.query([])?;
        let mut effective: Option<Record> = None;
        let mut completed: Option<Record> = None;
        let mut consumed: Option<u64> = None;
        let mut selected = None;
        let mut ids = HashSet::new();
        while let Some(row) = rows.next()? {
            let rev: u64 = row.get(0)?;
            // Aborts strictly below this record were never decided: they must
            // each have taken the next free revision at the time they were
            // recorded, so the counter stays gapless and monotonic.
            while let Some(a) = pending.next_if(|a| *a < rev) {
                self.undecided_abort(&aborts[&a], consumed, effective.as_ref())?;
                consumed = Some(a);
            }
            let json: String = row.get(1)?;
            super::ensure(json.len() <= MAX_RECORD, "transition record limit")?;
            let digest: Vec<u8> = row.get(2)?;
            super::ensure(
                digest == Sha256::digest(json.as_bytes()).to_vec(),
                "transition record integrity",
            )?;
            let record: Record = serde_json::from_str(&json)?;
            super::ensure(
                record
                    .completion
                    .is_none_or(|id| id != [0; 32] && record.acknowledgements == [true; 2]),
                "invalid transition completion",
            )?;
            super::ensure(
                rev == record.request.revision,
                "transition revision mismatch",
            )?;
            verify_historical(&record.token, trust, &record.request)?;
            super::ensure(
                ids.insert(record.request.id),
                "duplicate transition request id",
            )?;
            self.chain(effective.as_ref(), consumed, &record)?;
            if revision == Some(record.request.revision) {
                selected = Some(record.clone());
            }
            consumed = Some(rev);
            if pending.next_if_eq(&rev).is_some() {
                decided_abort(&aborts[&rev].abort, &record)?;
            } else {
                if record.completion.is_some() {
                    completed = Some(record.clone());
                }
                effective = Some(record);
            }
        }
        for a in pending {
            self.undecided_abort(&aborts[&a], consumed, effective.as_ref())?;
            consumed = Some(a);
        }
        let last_revision = match consumed {
            Some(r) => r,
            None => self.scope.initial_revision - 1,
        };
        let head: u64 =
            c.query_row("SELECT revision FROM transition_head WHERE id=1", [], |r| {
                r.get(0)
            })?;
        super::ensure(head == last_revision, "transition head mismatch")?;
        Ok((
            History {
                head: effective,
                completed,
                ids,
                aborts,
                consumed,
                last_revision,
            },
            selected,
        ))
    }

    /// Both directions of the one-way journal format marker.
    ///
    /// A binary that predates format 2 cannot see `transition_abort`,
    /// `transition_loss_chain` or `transition_loss_successor_abort`, so it
    /// would read a cancelled transition as live, hand out a writer proof for
    /// an aborted successor, or treat a superseded loss as current. It must
    /// therefore fail *closed* on such a journal, and the only thing every
    /// old binary already validates strictly is the stored scope row: adding
    /// a member to it breaks their `deny_unknown_fields` decode.
    ///
    /// So: state in any of the three tables ⇒ the marker must be present, and
    /// a marker is always accepted. A journal that never touches those tables
    /// keeps its scope row byte-identical and stays readable by old binaries.
    pub(super) fn ensure_journal_format(&self, c: &Connection) -> super::Result<()> {
        let (stored, format) = read_scope(c)?;
        super::ensure(stored == self.scope, "transition journal scope mismatch")?;
        super::ensure(
            format == JOURNAL_FORMAT_TWO || !format_two_state(c)?,
            "format-2 journal state without format marker",
        )
    }

    /// Bounded, digest-checked, signature-checked scan of the lazily created
    /// append-only abort table. A journal without the table yields an empty
    /// map and is therefore byte-for-byte a format-1 journal.
    fn read_aborts(
        &self,
        c: &Connection,
        trust: &Trust<'_>,
    ) -> super::Result<BTreeMap<u64, AbortRecord>> {
        if !table_exists(c, "transition_abort")? {
            return Ok(BTreeMap::new());
        }
        let rows: i64 = c.query_row("SELECT count(*) FROM main.transition_abort", [], |r| {
            r.get(0)
        })?;
        super::ensure(
            usize::try_from(rows).is_ok_and(|n| n <= MAX_ABORT_ROWS),
            "transition abort row limit",
        )?;
        ensure_row_sizes(
            c,
            "SELECT count(*) FROM main.transition_abort WHERE length(record)>?1",
            "transition abort record limit",
        )?;
        let mut aborts: BTreeMap<u64, AbortRecord> = BTreeMap::new();
        let mut ids = HashSet::new();
        let mut targets = HashSet::new();
        let mut stmt = c.prepare(
            "SELECT revision,record,digest FROM main.transition_abort ORDER BY revision",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let rev: u64 = row.get(0)?;
            let json: String = row.get(1)?;
            super::ensure(json.len() <= MAX_RECORD, "transition abort record limit")?;
            let digest: Vec<u8> = row.get(2)?;
            super::ensure(
                digest == Sha256::digest(json.as_bytes()).to_vec(),
                "transition abort record integrity",
            )?;
            let record: AbortRecord = serde_json::from_str(&json)?;
            super::ensure(record.format == 2, "transition abort record format")?;
            record.abort.validate()?;
            super::ensure(
                rev == record.abort.aborted_revision,
                "transition abort revision mismatch",
            )?;
            let a = &record.abort;
            super::ensure(
                a.install == self.scope.install
                    && a.region == self.scope.region
                    && a.scope == self.scope.scope
                    && a.schema == self.scope.schema
                    && a.membership == self.scope.membership
                    && a.source_anchor == self.scope.source_anchor
                    && a.authority_id == self.scope.authority_id,
                "maintenance abort scope binding",
            )?;
            super::ensure(
                verify_abort_historical(&record.token, trust, a)? == record.certificate_id,
                "transition abort certificate mismatch",
            )?;
            super::ensure(
                ids.insert(a.id) && targets.insert(a.aborted_request_id),
                "duplicate maintenance abort",
            )?;
            super::ensure(
                aborts.insert(rev, record).is_none(),
                "duplicate maintenance abort",
            )?;
        }
        Ok(aborts)
    }

    /// An abort with no history row at its revision. It must sit exactly at
    /// `last_revision + 1` as of the moment it was recorded, and it may not
    /// step over a decided transition that is still open: that one has to be
    /// aborted on its own revision first, otherwise the journal would carry
    /// an unfinishable record for ever with no record of why.
    fn undecided_abort(
        &self,
        record: &AbortRecord,
        consumed: Option<u64>,
        effective: Option<&Record>,
    ) -> super::Result<()> {
        let expected = match consumed {
            Some(r) => r.checked_add(1).ok_or("transition revision overflow")?,
            None => self.scope.initial_revision,
        };
        super::ensure(
            !record.abort.decided && record.abort.aborted_revision == expected,
            "transition abort sequencing",
        )?;
        super::ensure(
            effective.is_none_or(|r| r.completion.is_some()),
            "decided transition must be aborted first",
        )
    }

    fn chain(
        &self,
        effective: Option<&Record>,
        previous_revision: Option<u64>,
        r: &Record,
    ) -> super::Result<()> {
        let q = &r.request;
        super::ensure(
            q.install == self.scope.install
                && q.region == self.scope.region
                && q.scope == self.scope.scope
                && q.schema == self.scope.schema
                && q.membership == self.scope.membership
                && q.source_anchor == self.scope.source_anchor
                && q.authority_id == self.scope.authority_id,
            "transition scope binding",
        )?;
        // Revisions come from the monotonic counter, which aborts also
        // consume; the data lineage comes from the effective head. Without an
        // abort table the two are the same record, so this is unchanged.
        let expected = match previous_revision {
            Some(p) => p.checked_add(1).ok_or("transition revision overflow")?,
            None => self.scope.initial_revision,
        };
        if let Some(p) = effective {
            super::ensure(
                p.completion.is_some()
                    && q.revision == expected
                    && q.participants
                        .iter()
                        .all(|m| m.old_base.as_ref() == Some(&p.request.participants[0].target)),
                "transition chain mismatch",
            )?;
            super::ensure(
                q.id != p.request.id
                    && q.participants
                        .iter()
                        .zip(&p.request.participants)
                        .all(|(a, b)| a.member == b.member && a.generation == b.generation),
                "transition membership history mismatch",
            )?;
        } else {
            super::ensure(
                q.revision == expected,
                "initial transition revision mismatch",
            )?;
        }
        Ok(())
    }
    pub fn decide(
        &self,
        request: Request,
        token: &str,
        now: u64,
        trust: &Trust<'_>,
        policy: &impl Policy,
    ) -> super::Result<CommittedTransition> {
        request.validate()?;
        super::ensure(token.len() <= MAX_TOKEN, "token limit")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let old = self.read(&tx, trust)?;
            super::ensure(
                !loss_record_exists(&tx, trust)?,
                "transition superseded by participant loss",
            )?;
            super::ensure(
                old.head.is_some() || !successor_parent_exists(&tx)?,
                "replacement transition requires loss sequencing",
            )?;
            policy.continuity(&self.scope, &request)?;
            if let Some(r) = old.head.as_ref().filter(|r| r.request == request) {
                super::ensure(r.token == token, "immutable transition conflict")?;
                return committed(r, trust);
            }
            super::ensure(
                !old.aborts.contains_key(&request.revision),
                "transition revision aborted",
            )?;
            super::ensure(
                !old.ids.contains(&request.id) && !old.aborted_request_id(request.id),
                "duplicate transition request id",
            )?;
            self.chain(
                old.head.as_ref(),
                old.consumed,
                &Record {
                    request: request.clone(),
                    token: token.into(),
                    acknowledgements: [false; 2],
                    completion: None,
                },
            )?;
            let verified = verify_issuance(token, trust, &request, now)?;
            for m in &request.participants {
                policy.prepared(&self.scope, &request, m)?;
            }
            policy.continuity(&self.scope, &request)?;
            let r = Record {
                request,
                token: token.into(),
                acknowledgements: [false; 2],
                completion: None,
            };
            save(&tx, &r)?;
            tx.commit()?;
            Ok(CommittedTransition {
                request: r.request,
                token: r.token,
                token_digest: verified.token_digest(),
                certificate_id: verified.certificate_id(),
                acknowledgements: r.acknowledgements,
                completion: r.completion,
            })
        })
    }

    pub fn fetch(
        &self,
        request: &Request,
        trust: &Trust<'_>,
        policy: &impl Policy,
    ) -> super::Result<CommittedTransition> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let history = self.read(&tx, trust)?;
            super::ensure(
                !loss_record_exists(&tx, trust)?,
                "transition superseded by participant loss",
            )?;
            let r = history.head.as_ref().ok_or("transition missing")?;
            super::ensure(r.request == *request, "transition unavailable")?;
            policy.continuity(&self.scope, request)?;
            committed(r, trust)
        })
    }

    /// Revalidate the current durable head and external continuity, then prove
    /// that both participant ACKs and completion are present. This result is
    /// the only transition-journal value suitable for reopening write
    /// eligibility; `Status` and locally persisted completion bytes are not.
    pub fn fetch_completed(
        &self,
        request: &Request,
        trust: &Trust<'_>,
        policy: &impl Policy,
    ) -> super::Result<CompletedTransition> {
        let committed = self.fetch(request, trust, policy)?;
        super::ensure(
            committed.acknowledgements() == [true; 2],
            "transition acknowledgements incomplete",
        )?;
        let completion = committed
            .completion()
            .ok_or("transition completion missing")?;
        Ok(CompletedTransition {
            committed,
            completion,
        })
    }

    /// Revalidate the complete hash-linked journal, then return an exact
    /// completed historical revision under the caller's live external
    /// continuity and supersession policy. This is inspection evidence only;
    /// it does not grant writer or issuance authority.
    pub fn fetch_completed_revision(
        &self,
        request: &Request,
        trust: &Trust<'_>,
        policy: &impl Policy,
    ) -> super::Result<HistoricalCompletedTransition> {
        request.validate()?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let (history, selected) =
                self.read_with_revision(&tx, trust, Some(request.revision))?;
            super::ensure(
                !history.aborts.contains_key(&request.revision),
                "transition revision aborted",
            )?;
            let head = history.head.as_ref().ok_or("transition missing")?;
            let record = selected.ok_or("transition revision unavailable")?;
            super::ensure(record.request == *request, "transition request mismatch")?;
            super::ensure(
                record.acknowledgements == [true; 2],
                "transition acknowledgements incomplete",
            )?;
            let completion = record.completion.ok_or("transition completion missing")?;
            policy.continuity(&self.scope, &head.request)?;
            policy.historical_completion(&self.scope, &record.request, &head.request)?;
            let verified = verify_historical(&record.token, trust, &record.request)?;
            Ok(HistoricalCompletedTransition {
                request: record.request,
                token: record.token,
                token_digest: verified.token_digest(),
                certificate_id: verified.certificate_id(),
                completion,
            })
        })
    }

    pub fn status(&self, trust: &Trust<'_>) -> super::Result<Status> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let h = self.read(&tx, trust)?;
            let last_revision = h.last_revision;
            let aborted =
                u64::try_from(h.aborts.len()).map_err(|_| "transition abort row limit")?;
            Ok(h.head.map_or(
                Status {
                    request: None,
                    acknowledgements: [false; 2],
                    completion: None,
                    last_revision,
                    aborted,
                },
                |r| Status {
                    request: Some(r.request),
                    acknowledgements: r.acknowledgements,
                    completion: r.completion,
                    last_revision,
                    aborted,
                },
            ))
        })
    }

    pub fn acknowledge(
        &self,
        decision: &CommittedTransition,
        member: &Participant,
        trust: &Trust<'_>,
        policy: &impl Policy,
    ) -> super::Result<()> {
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let history = self.read(&tx, trust)?;
            super::ensure(
                !history.aborts.contains_key(&decision.request.revision),
                "transition revision aborted",
            )?;
            let mut r = history.head.ok_or("transition missing")?;
            super::ensure(
                !loss_record_exists(&tx, trust)?,
                "transition superseded by participant loss",
            )?;
            super::ensure(
                r.request == decision.request
                    && committed(&r, trust)?.token_digest == decision.token_digest,
                "transition handle is not current",
            )?;
            policy.continuity(&self.scope, &r.request)?;
            let index = r
                .request
                .participants
                .iter()
                .position(|p| p == member)
                .ok_or("transition member mismatch")?;
            if r.acknowledgements[index] {
                return Ok(());
            }
            policy.applied(&self.scope, decision, member)?;
            policy.continuity(&self.scope, &r.request)?;
            r.acknowledgements[index] = true;
            replace(&tx, &r)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn complete(
        &self,
        decision: &CommittedTransition,
        id: Id,
        trust: &Trust<'_>,
        policy: &impl Policy,
    ) -> super::Result<()> {
        super::ensure(id != [0; 32], "zero transition completion")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let history = self.read(&tx, trust)?;
            super::ensure(
                !history.aborts.contains_key(&decision.request.revision),
                "transition revision aborted",
            )?;
            let mut r = history.head.ok_or("transition missing")?;
            super::ensure(
                !loss_record_exists(&tx, trust)?,
                "transition superseded by participant loss",
            )?;
            super::ensure(
                r.request == decision.request
                    && committed(&r, trust)?.token_digest == decision.token_digest
                    && r.acknowledgements == [true; 2],
                "transition completion evidence missing",
            )?;
            policy.continuity(&self.scope, &r.request)?;
            if let Some(old) = r.completion {
                return super::ensure(old == id, "immutable transition completion conflict");
            }
            r.completion = Some(id);
            replace(&tx, &r)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Permanently cancel a certified maintenance attempt.
    ///
    /// This exists because `decide` is a one-way door: once a transition is
    /// decided but not completed (for example because the authority token
    /// expired before the participants could apply it) the pair can neither
    /// finish nor re-issue, and both nodes stay unopenable for ever.
    ///
    /// The abort **consumes** `abort.aborted_revision` for ever. The revision
    /// is never reused, the cancelled request id can never be decided again,
    /// and the abort is not a link in the chain: the **effective head**
    /// reverts to the last record that was actually completed, so
    /// [`Journal::fetch_completed`] on that certificate succeeds again and the
    /// nodes can reopen on evidence they already hold.
    ///
    /// Two admissible shapes, both checked inside one `Immediate`
    /// transaction:
    ///
    /// * the effective head is a decided record at `aborted_revision` with no
    ///   completion and not acknowledged by both participants, and
    ///   `abort.decided == true`;
    /// * nothing was ever decided at that revision, `aborted_revision ==
    ///   last_revision + 1`, `abort.decided == false`, and no decided
    ///   transition is still open — an open decision must be cancelled on its
    ///   own revision, never stepped over.
    ///
    /// # Validity window of a never-decided abort
    ///
    /// The second shape is only issuable while `last_revision + 1` is still
    /// the revision the abandoned request was prepared for. Nothing can
    /// consume a revision in between except a participant loss, and a loss
    /// that lands first makes this abort permanently unissuable — the pair
    /// must then use the loss's own rollback branch (`source_kind =
    /// Completed` with `abandoned_request`), which needs no node-side
    /// aborting phase and therefore no cooperation from the lost member.
    ///
    /// The abort is nonetheless bound to the *request*, never to the revision
    /// it happened to consume: [`Journal::fetch_abort`] matches on the
    /// request digest and id alone, so the node that prepared the request can
    /// always find the abort that cancelled it even if the two differ.
    ///
    /// An exact retry of an already recorded abort converges and, crucially,
    /// does **not** re-check the token's validity window: the C2 crash window
    /// (abort recorded, process died before the nodes rolled back) must be
    /// resumable with the same, by then expired, token.
    pub fn abort(
        &self,
        abort: MaintenanceAbort,
        token: &str,
        now: u64,
        trust: &Trust<'_>,
        policy: &impl Policy,
    ) -> super::Result<CommittedMaintenanceAbort> {
        abort.validate()?;
        super::ensure(token.len() <= MAX_TOKEN, "token limit")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let history = self.read(&tx, trust)?;
            // Certified maintenance never runs in a successor journal, so an
            // abort there could only ever be a confused or forged one.
            super::ensure(
                !successor_parent_exists(&tx)?,
                "maintenance abort is not available in a successor journal",
            )?;
            super::ensure(
                !loss_record_exists(&tx, trust)?,
                "maintenance abort superseded by participant loss",
            )?;
            super::ensure(
                abort.install == self.scope.install
                    && abort.region == self.scope.region
                    && abort.scope == self.scope.scope
                    && abort.schema == self.scope.schema
                    && abort.membership == self.scope.membership
                    && abort.source_anchor == self.scope.source_anchor
                    && abort.authority_id == self.scope.authority_id,
                "maintenance abort scope binding",
            )?;
            if let Some(head) = history.head.as_ref() {
                policy.continuity(&self.scope, &head.request)?;
            }
            // Exact retry first: a recorded abort is immutable and its
            // revision is already consumed, so every later shape check would
            // reject the very request that must converge.
            //
            // This branch deliberately skips `Policy::abort_applicable` and
            // the `now` check: the C2 crash window is resumed with the same,
            // by then expired, token, and the nodes it would ask about have
            // already moved on. `Policy::continuity` still runs on both sides
            // of the branch, so a revoked authority still stops the read.
            if let Some(existing) = history.aborts.get(&abort.aborted_revision) {
                super::ensure(
                    existing.abort == abort && existing.token == token,
                    "immutable maintenance abort conflict",
                )?;
                if let Some(head) = history.head.as_ref() {
                    policy.continuity(&self.scope, &head.request)?;
                }
                return committed_abort(existing, trust);
            }
            match history
                .head
                .as_ref()
                .filter(|r| r.request.revision == abort.aborted_revision)
            {
                Some(record) => decided_abort(&abort, record)?,
                None => {
                    super::ensure(
                        !abort.decided
                            && abort.aborted_revision
                                == history
                                    .last_revision
                                    .checked_add(1)
                                    .ok_or("transition revision overflow")?,
                        "maintenance abort target mismatch",
                    )?;
                    // A never-decided abort may not step over a decided
                    // transition that is still open: cancel that one on its
                    // own revision first.
                    super::ensure(
                        history.head.as_ref().is_none_or(|r| r.completion.is_some()),
                        "decided transition must be aborted first",
                    )?;
                }
            }
            super::ensure(
                history.aborts.len() < MAX_ABORT_ROWS,
                "transition abort row limit",
            )?;
            policy.abort_applicable(&self.scope, &abort)?;
            let certificate_id = verify_abort_issuance(token, trust, &abort, now)?;
            if let Some(head) = history.head.as_ref() {
                policy.continuity(&self.scope, &head.request)?;
            }
            let record = AbortRecord {
                format: 2,
                abort,
                token: token.into(),
                certificate_id,
            };
            save_abort(&tx, &record)?;
            super::ensure(
                tx.execute(
                    "UPDATE transition_head SET revision=?1 WHERE id=1",
                    [history.last_revision.max(record.abort.aborted_revision)],
                )? == 1,
                "transition head update failed",
            )?;
            tx.commit()?;
            committed_abort(&record, trust)
        })
    }

    /// Live re-read of the abort that cancelled `aborted_request`, under the
    /// caller's continuity policy. This is the value a node must match its
    /// locally persisted rollback marker against after a restart; local bytes
    /// are never authority evidence.
    ///
    /// The lookup is by request digest and request id only. A never-decided
    /// abort consumes `last_revision + 1`, which need not equal the revision
    /// the abandoned request was issued for, so binding the lookup to the
    /// revision as well would hide a recorded abort from the very node that
    /// prepared the request.
    pub fn fetch_abort(
        &self,
        aborted_request: &Request,
        trust: &Trust<'_>,
        policy: &impl Policy,
    ) -> super::Result<CommittedMaintenanceAbort> {
        let digest = aborted_request.digest()?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let history = self.read(&tx, trust)?;
            let record = history
                .aborts
                .values()
                .find(|r| {
                    r.abort.aborted_request == digest
                        && r.abort.aborted_request_id == aborted_request.id
                })
                .ok_or("maintenance abort missing")?;
            if let Some(head) = history.head.as_ref() {
                policy.continuity(&self.scope, &head.request)?;
            }
            committed_abort(record, trust)
        })
    }
}

/// Binding of an abort to the decided-but-unfinished record it cancels.
fn decided_abort(a: &MaintenanceAbort, record: &Record) -> super::Result<()> {
    super::ensure(
        a.decided
            && record.completion.is_none()
            && record.acknowledgements != [true; 2]
            && a.aborted_revision == record.request.revision
            && a.aborted_request_id == record.request.id
            && a.aborted_request == record.request.digest()?,
        "maintenance abort target mismatch",
    )
}

fn save_abort(c: &Connection, r: &AbortRecord) -> super::Result<()> {
    let json = serde_json::to_string(r)?;
    super::ensure(json.len() <= MAX_RECORD, "transition abort record limit")?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS main.transition_abort(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32));")?;
    mark_journal_format_two(c)?;
    super::ensure(
        c.execute(
            "INSERT INTO main.transition_abort VALUES(?1,?2,?3)",
            params![
                r.abort.aborted_revision,
                json,
                Sha256::digest(json.as_bytes()).as_slice()
            ],
        )? == 1,
        "transition abort write failed",
    )
}

fn committed_abort(r: &AbortRecord, trust: &Trust<'_>) -> super::Result<CommittedMaintenanceAbort> {
    let certificate_id = verify_abort_historical(&r.token, trust, &r.abort)?;
    super::ensure(
        certificate_id == r.certificate_id,
        "transition abort certificate mismatch",
    )?;
    Ok(CommittedMaintenanceAbort {
        abort: r.abort.clone(),
        token: r.token.clone(),
        token_digest: Sha256::digest(r.token.as_bytes()).into(),
        certificate_id,
    })
}

pub(super) fn table_exists(c: &Connection, name: &str) -> super::Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )?)
}

/// Reject any row whose payload exceeds the record cap *in SQL*, before a
/// single byte of it is materialised into this process. `sql` must count the
/// rows whose `record` is longer than the bound parameter.
pub(super) fn ensure_row_sizes(c: &Connection, sql: &str, message: &str) -> super::Result<()> {
    let cap = i64::try_from(MAX_RECORD).map_err(|_| "transition record limit")?;
    let oversized: i64 = c.query_row(sql, [cap], |r| r.get(0))?;
    super::ensure(oversized == 0, message)
}

/// The stored scope row, split into the journal scope and the one-way format
/// marker. A format-1 row has no marker and decodes exactly as before.
fn read_scope(c: &Connection) -> super::Result<(JournalScope, u32)> {
    let raw: String = c.query_row("SELECT record FROM transition_scope WHERE id=1", [], |r| {
        r.get(0)
    })?;
    super::ensure(raw.len() <= 64 * 1024, "transition scope limit")?;
    let mut value: serde_json::Value = serde_json::from_str(&raw)?;
    let object = value
        .as_object_mut()
        .ok_or("transition journal scope mismatch")?;
    let format = match object.remove(JOURNAL_FORMAT_MARKER) {
        None => 1,
        Some(marker) => u32::try_from(marker.as_u64().ok_or("transition journal format")?)
            .ok()
            .filter(|f| *f == JOURNAL_FORMAT_TWO)
            .ok_or("transition journal format")?,
    };
    Ok((serde_json::from_value(value)?, format))
}

/// Does this journal hold any state an old binary cannot see?
fn format_two_state(c: &Connection) -> super::Result<bool> {
    for (name, sql) in [
        (
            "transition_abort",
            "SELECT count(*) FROM main.transition_abort",
        ),
        (
            "transition_loss_chain",
            "SELECT count(*) FROM main.transition_loss_chain",
        ),
        (
            "transition_loss_successor_abort",
            "SELECT count(*) FROM main.transition_loss_successor_abort",
        ),
    ] {
        if table_exists(c, name)? {
            let rows: i64 = c.query_row(sql, [], |r| r.get(0))?;
            if rows > 0 {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Burn the one-way format marker into the stored scope row. Idempotent, and
/// always called in the same transaction as the first write to a table an old
/// binary cannot see.
pub(super) fn mark_journal_format_two(c: &Connection) -> super::Result<()> {
    let raw: String = c.query_row("SELECT record FROM transition_scope WHERE id=1", [], |r| {
        r.get(0)
    })?;
    super::ensure(raw.len() <= 64 * 1024, "transition scope limit")?;
    let mut value: serde_json::Value = serde_json::from_str(&raw)?;
    let object = value
        .as_object_mut()
        .ok_or("transition journal scope mismatch")?;
    if object.contains_key(JOURNAL_FORMAT_MARKER) {
        return Ok(());
    }
    object.insert(
        JOURNAL_FORMAT_MARKER.into(),
        serde_json::Value::from(JOURNAL_FORMAT_TWO),
    );
    let json = serde_json::to_string(&value)?;
    super::ensure(json.len() <= 64 * 1024, "transition scope limit")?;
    super::ensure(
        c.execute("UPDATE transition_scope SET record=?1 WHERE id=1", [json])? == 1,
        "transition scope marker write failed",
    )
}

fn save(c: &Connection, r: &Record) -> super::Result<()> {
    let json = serde_json::to_string(r)?;
    super::ensure(json.len() <= 256 * 1024, "transition record limit")?;
    super::ensure(
        c.execute(
            "INSERT INTO transition_history VALUES(?1,?2,?3)",
            params![
                r.request.revision,
                json,
                Sha256::digest(json.as_bytes()).as_slice()
            ],
        )? == 1,
        "transition insert failed",
    )?;
    super::ensure(
        c.execute(
            "UPDATE transition_head SET revision=?1 WHERE id=1",
            [r.request.revision],
        )? == 1,
        "transition head update failed",
    )?;
    Ok(())
}
fn replace(c: &Connection, r: &Record) -> super::Result<()> {
    let json = serde_json::to_string(r)?;
    super::ensure(json.len() <= 256 * 1024, "transition record limit")?;
    super::ensure(
        c.execute(
            "UPDATE transition_history SET record=?2,digest=?3 WHERE revision=?1",
            params![
                r.request.revision,
                json,
                Sha256::digest(json.as_bytes()).as_slice()
            ],
        )? == 1,
        "transition update failed",
    )?;
    Ok(())
}
fn committed(r: &Record, trust: &Trust<'_>) -> super::Result<CommittedTransition> {
    let v = verify_historical(&r.token, trust, &r.request)?;
    Ok(CommittedTransition {
        request: r.request.clone(),
        token: r.token.clone(),
        token_digest: v.token_digest(),
        certificate_id: v.certificate_id(),
        acknowledgements: r.acknowledgements,
        completion: r.completion,
    })
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT
}
fn valid_checkpoint(value: &Checkpoint) -> bool {
    value.sequence <= i64::MAX as u64 && value.digest != [0; 32]
}
fn valid_target(value: &Checkpoint) -> bool {
    value.sequence > 0 && valid_checkpoint(value)
}

/// Trust is supplied by the integration on every verification, never by the proof.
pub struct Trust<'a> {
    pub profile: &'a Profile,
    /// Trusted uncompressed SEC1 public-key bytes, as returned by ring's
    /// `EcdsaKeyPair::public_key`; these are not DER SPKI bytes.
    pub keys: &'a [(String, Vec<u8>)],
    pub max_lifetime: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustStore {
    pub profile: Profile,
    /// Trusted uncompressed SEC1 public-key bytes, never loaded from a proof.
    pub keys: Vec<(String, Vec<u8>)>,
    pub max_lifetime: u64,
}
impl TrustStore {
    pub fn as_trust(&self) -> Trust<'_> {
        Trust {
            profile: &self.profile,
            keys: &self.keys,
            max_lifetime: self.max_lifetime,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    version: u32,
    iss: String,
    aud: String,
    action: String,
    certificate_id: Id,
    iat: u64,
    nbf: u64,
    exp: u64,
    request: Request,
    request_digest: Id,
}

/// Fresh, time-valid signature verification. Participant evidence and authorization
/// remain obligations of the external issuing adapter.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedIssuance {
    request: Request,
    certificate_id: Id,
    token_digest: Id,
}
impl VerifiedIssuance {
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
}

/// Historical signature evidence, intentionally a distinct non-authority type.
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{VerifiedHistorical, VerifiedIssuance};
/// fn authorize(_: VerifiedIssuance) {}
/// fn historical_is_not_authority(proof: VerifiedHistorical) { authorize(proof); }
/// ```
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedHistorical {
    request: Request,
    certificate_id: Id,
    token_digest: Id,
}
impl VerifiedHistorical {
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
}

/// Issuance-time verification. This is the only API that checks `now`.
pub fn verify_issuance(
    token: &str,
    trust: &Trust<'_>,
    expected: &Request,
    now: u64,
) -> Result<VerifiedIssuance, &'static str> {
    let claims = verify_common(token, trust, expected)?;
    if claims.nbf > now || now >= claims.exp {
        return Err("time window");
    }
    Ok(VerifiedIssuance {
        request: claims.request,
        certificate_id: claims.certificate_id,
        token_digest: Sha256::digest(token.as_bytes()).into(),
    })
}

/// Durable-proof verification. Expiration is not re-applied after valid issuance.
/// The caller must separately prevent rollback to an older valid certificate.
pub fn verify_historical(
    token: &str,
    trust: &Trust<'_>,
    expected: &Request,
) -> Result<VerifiedHistorical, &'static str> {
    let claims = verify_common(token, trust, expected)?;
    Ok(VerifiedHistorical {
        request: claims.request,
        certificate_id: claims.certificate_id,
        token_digest: Sha256::digest(token.as_bytes()).into(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbortClaims {
    version: u32,
    iss: String,
    aud: String,
    action: String,
    certificate_id: Id,
    iat: u64,
    nbf: u64,
    exp: u64,
    request: MaintenanceAbort,
    request_digest: Id,
}

/// Issuance-time verification of a maintenance abort token. This is the only
/// abort API that checks `now`; it must be used exactly once, when the abort
/// is first recorded.
pub fn verify_abort_issuance(
    token: &str,
    trust: &Trust<'_>,
    expected: &MaintenanceAbort,
    now: u64,
) -> Result<Id, &'static str> {
    verify_abort(token, trust, expected, Some(now))
}

/// Durable-proof verification of a maintenance abort token. Expiration is not
/// re-applied after valid issuance: an abort is terminal, so there is nothing
/// a stale abort could roll back to.
pub fn verify_abort_historical(
    token: &str,
    trust: &Trust<'_>,
    expected: &MaintenanceAbort,
) -> Result<Id, &'static str> {
    verify_abort(token, trust, expected, None)
}

fn verify_abort(
    token: &str,
    trust: &Trust<'_>,
    expected: &MaintenanceAbort,
    now: Option<u64>,
) -> Result<Id, &'static str> {
    expected.validate()?;
    trust.profile.validate()?;
    if token.len() > MAX_TOKEN {
        return Err("token limit");
    }
    let mut parts = token.split('.');
    let h = parts.next().ok_or("header")?;
    let p = parts.next().ok_or("payload")?;
    let s = parts.next().ok_or("signature")?;
    if parts.next().is_some() || h.len() > 1024 {
        return Err("compact shape");
    }
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| "header schema")?;
    if header.alg != "ES256" || header.typ != ABORT_TOKEN_TYPE || header.kid.is_empty() {
        return Err("header purpose");
    }
    let mut keys = trust.keys.iter().filter(|(kid, _)| kid == &header.kid);
    let key = &keys.next().ok_or("untrusted key")?.1;
    if keys.next().is_some() {
        return Err("ambiguous key");
    }
    let sig = decode(s)?;
    if sig.len() != 64 {
        return Err("signature shape");
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
        .verify(&token.as_bytes()[..h.len() + 1 + p.len()], &sig)
        .map_err(|_| "signature")?;
    let c: AbortClaims = serde_json::from_slice(&decode(p)?).map_err(|_| "claim schema")?;
    let life = c.exp.checked_sub(c.iat).ok_or("time order")?;
    if c.version != 1
        || c.iss != trust.profile.issuer
        || c.aud != trust.profile.audience
        || c.action != "abort_compact_pair"
        || c.certificate_id == [0; 32]
        || life == 0
        || life > trust.max_lifetime
        || c.iat > c.nbf
        || c.nbf >= c.exp
    {
        return Err("claim purpose");
    }
    if now.is_some_and(|n| c.nbf > n || n >= c.exp) {
        return Err("time window");
    }
    if c.request != *expected || c.request_digest != expected.digest()? {
        return Err("request binding");
    }
    Ok(c.certificate_id)
}

fn verify_common(
    token: &str,
    trust: &Trust<'_>,
    expected: &Request,
) -> Result<Claims, &'static str> {
    expected.validate()?;
    trust.profile.validate()?;
    if token.len() > MAX_TOKEN {
        return Err("token limit");
    }
    let mut parts = token.split('.');
    let h = parts.next().ok_or("header")?;
    let p = parts.next().ok_or("payload")?;
    let s = parts.next().ok_or("signature")?;
    if parts.next().is_some() || h.len() > 1024 {
        return Err("compact shape");
    }
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| "header schema")?;
    if trust.profile.token_type != TOKEN_TYPE
        || header.alg != "ES256"
        || header.typ != TOKEN_TYPE
        || header.kid.is_empty()
    {
        return Err("header purpose");
    }
    let mut keys = trust.keys.iter().filter(|(kid, _)| kid == &header.kid);
    let key = &keys.next().ok_or("untrusted key")?.1;
    if keys.next().is_some() {
        return Err("ambiguous key");
    }
    let sig = decode(s)?;
    if sig.len() != 64 {
        return Err("signature shape");
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
        .verify(&token.as_bytes()[..h.len() + 1 + p.len()], &sig)
        .map_err(|_| "signature")?;
    let claims: Claims = serde_json::from_slice(&decode(p)?).map_err(|_| "claim schema")?;
    let lifetime = claims.exp.checked_sub(claims.iat).ok_or("time order")?;
    if claims.version != 1
        || claims.iss != trust.profile.issuer
        || claims.aud != trust.profile.audience
        || claims.action != "compact_pair"
        || claims.certificate_id == [0; 32]
    {
        return Err("claim purpose");
    }
    if lifetime == 0
        || lifetime > trust.max_lifetime
        || claims.iat > claims.nbf
        || claims.nbf >= claims.exp
    {
        return Err("time window");
    }
    if claims.request != *expected || claims.request_digest != expected.digest()? {
        return Err("request binding");
    }
    Ok(claims)
}

fn decode(segment: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = B64.decode(segment).map_err(|_| "encoding")?;
    if segment.is_empty() || B64.encode(&bytes) != segment {
        Err("noncanonical encoding")
    } else {
        Ok(bytes)
    }
}
