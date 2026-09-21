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
use std::{collections::HashSet, path::Path, time::Duration};
use terrapi_vesta::{KdfParams, Vesta};
mod loss;
pub use loss::*;

const MAX_TOKEN: usize = 64 * 1024;
const MAX_TEXT: usize = 512;
pub const TOKEN_TYPE: &str = "terrapi-checkpoint-transition+jwt";

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
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    request: Request,
    token: String,
    acknowledgements: [bool; 2],
    completion: Option<Id>,
}
struct History {
    head: Option<Record>,
    ids: HashSet<Id>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub request: Option<Request>,
    pub acknowledgements: [bool; 2],
    pub completion: Option<Id>,
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
        let raw: String =
            c.query_row("SELECT record FROM transition_scope WHERE id=1", [], |r| {
                r.get(0)
            })?;
        super::ensure(raw.len() <= 64 * 1024, "transition scope limit")?;
        super::ensure(
            serde_json::from_str::<JournalScope>(&raw)? == self.scope,
            "transition journal scope mismatch",
        )?;
        let mut stmt =
            c.prepare("SELECT revision,record,digest FROM transition_history ORDER BY revision")?;
        let mut rows = stmt.query([])?;
        let mut head_record: Option<Record> = None;
        let mut selected = None;
        let mut ids = HashSet::new();
        while let Some(row) = rows.next()? {
            let rev: u64 = row.get(0)?;
            let json: String = row.get(1)?;
            super::ensure(json.len() <= 256 * 1024, "transition record limit")?;
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
            self.chain(head_record.as_ref(), &record)?;
            if revision == Some(record.request.revision) {
                selected = Some(record.clone());
            }
            head_record = Some(record);
        }
        let head: u64 =
            c.query_row("SELECT revision FROM transition_head WHERE id=1", [], |r| {
                r.get(0)
            })?;
        super::ensure(
            head == head_record
                .as_ref()
                .map_or(self.scope.initial_revision - 1, |r| r.request.revision),
            "transition head mismatch",
        )?;
        Ok((
            History {
                head: head_record,
                ids,
            },
            selected,
        ))
    }
    fn chain(&self, old: Option<&Record>, r: &Record) -> super::Result<()> {
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
        if let Some(p) = old {
            super::ensure(
                p.completion.is_some()
                    && q.revision
                        == p.request
                            .revision
                            .checked_add(1)
                            .ok_or("transition revision overflow")?
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
                q.revision == self.scope.initial_revision,
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
                !old.ids.contains(&request.id),
                "duplicate transition request id",
            )?;
            self.chain(
                old.head.as_ref(),
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
            Ok(h.head.map_or(
                Status {
                    request: None,
                    acknowledgements: [false; 2],
                    completion: None,
                },
                |r| Status {
                    request: Some(r.request),
                    acknowledgements: r.acknowledgements,
                    completion: r.completion,
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
            let mut r = self.read(&tx, trust)?.head.ok_or("transition missing")?;
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
            let mut r = self.read(&tx, trust)?.head.ok_or("transition missing")?;
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
