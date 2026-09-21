//! Durable, one-plan control journal. It does not grant business write access.
//! Backend continuity, fencing and installation proofs are external obligations.
use super::{
    grant::{self, Context},
    model::{Baseline, Event, Id, Model, Plan},
};
use crate::{ensure, Result};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use terrapi_vesta::{KdfParams, Vesta};

const MAX_RECORD: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub install: String,
    pub region: String,
    /// Persisted application trust domain; historical retries cannot switch profiles.
    pub profile: grant::Profile,
    pub baseline: Baseline,
}

impl Scope {
    fn validate(&self) -> Result<()> {
        self.baseline.validate()?;
        self.profile.validate()?;
        ensure(
            !self.install.trim().is_empty()
                && !self.region.trim().is_empty()
                && self.baseline.revision < i64::MAX as u64,
            "invalid decision journal scope",
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub member: Id,
    pub generation: Id,
    pub checkpoint: Id,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: Id,
    pub plan: Plan,
    /// Canonical order: candidate, survivor.
    pub prepared: [Prepared; 2],
}

/// Implemented by the trusted management integration, never from request booleans.
/// Calls are bounded by that integration; no permissive default is provided.
pub trait Policy {
    fn continuity(&self, scope: &Scope) -> Result<()>;
    fn context(&self, scope: &Scope, request: &Request) -> Result<Context>;
    fn prepared(&self, scope: &Scope, request: &Request) -> Result<()>;
    fn applied(&self, scope: &Scope, decision: &CommittedDecision, member: &Prepared)
        -> Result<()>;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    request: Request,
    token: String,
    grant_id: Id,
    acknowledgements: [bool; 2],
    completion: Option<Id>,
}

/// Redacted observation only. It is not a grant or a runtime admission permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub request: Option<Request>,
    pub acknowledgements: [bool; 2],
    pub completion: Option<Id>,
}

/// Exact committed decision. Not deserializable: network callers cannot mint it.
/// Delivering it requires a separate authenticated member installation protocol.
#[derive(Clone)]
pub struct CommittedDecision {
    request: Request,
    token_digest: Id,
    grant_id: Id,
}
impl CommittedDecision {
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
    pub fn grant_id(&self) -> Id {
        self.grant_id
    }
}

/// Owns an encrypted DB with caller-supplied credentials; never creates on open.
pub struct Journal {
    db: Vesta,
    scope: Scope,
}

impl Request {
    /// Check structural plan and prepared-member bindings only.
    /// Success is not authorization, fencing evidence, or a committed decision.
    pub fn validate(&self, baseline: &Baseline) -> Result<()> {
        Model::new(baseline.clone()).step(&self.plan, Event::Authorize)?;
        ensure(self.id != [0; 32], "zero decision id")?;
        for (p, member) in self
            .prepared
            .iter()
            .zip([self.plan.candidate, self.plan.baseline.survivor])
        {
            ensure(
                p.member == member
                    && p.generation != [0; 32]
                    && p.checkpoint == self.plan.baseline.checkpoint,
                "prepared binding mismatch",
            )?;
        }
        ensure(
            self.prepared[1].generation == self.plan.baseline.survivor_generation
                && self.prepared[0].generation != self.prepared[1].generation,
            "survivor generation mismatch",
        )
    }
}

impl Journal {
    pub fn create(path: &Path, passphrase: &str, scope: Scope) -> Result<Self> {
        scope.validate()?;
        ensure(
            !path.exists() && !passphrase.is_empty(),
            "invalid decision journal initialization",
        )?;
        let json = serde_json::to_string(&scope)?;
        ensure(json.len() <= MAX_RECORD, "scope limit")?;
        let journal = Self {
            db: Vesta::create(path, passphrase, KdfParams::default())?,
            scope,
        };
        journal.connection(|c| {
            let tx = c.unchecked_transaction()?;
            tx.execute_batch("CREATE TABLE recovery_decision_scope(id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL,scope TEXT NOT NULL);
                CREATE TABLE recovery_decision(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32));")?;
            tx.execute("INSERT INTO recovery_decision_scope VALUES(1,2,?1)", [json])?;
            tx.commit()?;
            Ok(())
        })?;
        Ok(journal)
    }

    pub fn open(path: &Path, passphrase: &str, expected: Scope) -> Result<Self> {
        expected.validate()?;
        ensure(
            path.is_file() && !passphrase.is_empty(),
            "decision journal absent",
        )?;
        let journal = Self {
            db: Vesta::open(path, passphrase)?,
            scope: expected,
        };
        journal.status()?;
        Ok(journal)
    }

    fn connection<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.db.with_connection(|c| {
            c.busy_timeout(Duration::from_secs(5))?;
            c.pragma_update(None, "synchronous", "FULL")?;
            c.pragma_update(None, "temp_store", "MEMORY")?;
            Ok(f(c))
        })?
    }

    fn read(&self, c: &Connection) -> Result<Option<Record>> {
        use rusqlite::OptionalExtension;
        let (format, json): (u32, String) = c.query_row(
            "SELECT format,scope FROM recovery_decision_scope WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure(
            format == 2
                && json.len() <= MAX_RECORD
                && serde_json::from_str::<Scope>(&json)? == self.scope,
            "decision journal scope/format mismatch",
        )?;
        let raw: Option<(String, Vec<u8>)> = c
            .query_row(
                "SELECT record,digest FROM recovery_decision WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((json, digest)) = raw else {
            return Ok(None);
        };
        ensure(
            json.len() <= MAX_RECORD && digest == Sha256::digest(json.as_bytes()).to_vec(),
            "decision record integrity",
        )?;
        let record: Record = serde_json::from_str(&json)?;
        record.request.validate(&self.scope.baseline)?;
        ensure(
            !record.token.is_empty()
                && record.token.len() <= 16 * 1024
                && record.grant_id != [0; 32]
                && record
                    .completion
                    .is_none_or(|id| id != [0; 32] && record.acknowledgements == [true; 2]),
            "invalid decision history",
        )?;
        Ok(Some(record))
    }

    fn save(c: &Connection, record: &Record) -> Result<()> {
        let json = serde_json::to_string(record)?;
        ensure(json.len() <= MAX_RECORD, "decision record limit")?;
        let digest = Sha256::digest(json.as_bytes());
        c.execute("INSERT INTO recovery_decision VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record,digest=excluded.digest",
            params![json, digest.as_slice()])?;
        Ok(())
    }

    pub fn status(&self) -> Result<Status> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let r = self.read(&tx)?;
            Ok(Status {
                request: r.as_ref().map(|r| r.request.clone()),
                acknowledgements: r.as_ref().map_or([false; 2], |r| r.acknowledgements),
                completion: r.and_then(|r| r.completion),
            })
        })
    }

    /// Irrevocable decision variant: current grant required only for first commit.
    /// Same-content retry is historical, but always requires trusted continuity.
    pub fn decide(&self, request: Request, token: &str, policy: &impl Policy) -> Result<()> {
        request.validate(&self.scope.baseline)?;
        ensure(token.len() <= 16 * 1024, "token limit")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            policy.continuity(&self.scope)?;
            if let Some(record) = self.read(&tx)? {
                return ensure(
                    record.request == request && record.token == token,
                    "immutable decision conflict",
                );
            }
            let ctx = policy.context(&self.scope, &request)?;
            ensure(
                ctx.install_id == self.scope.install
                    && ctx.region == self.scope.region
                    && ctx.profile == self.scope.profile,
                "policy scope mismatch",
            )?;
            let grant = grant::verify(token, &ctx)?;
            ensure(grant.plan == request.plan, "decision/grant mismatch")?;
            policy.prepared(&self.scope, &request)?;
            policy.continuity(&self.scope)?;
            Self::save(
                &tx,
                &Record {
                    request,
                    token: token.into(),
                    grant_id: grant.grant_id,
                    acknowledgements: [false; 2],
                    completion: None,
                },
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn fetch(&self, request: &Request, policy: &impl Policy) -> Result<CommittedDecision> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            policy.continuity(&self.scope)?;
            let r = self.read(&tx)?.ok_or("decision missing")?;
            ensure(
                r.request == *request && r.completion.is_none(),
                "decision unavailable for delivery",
            )?;
            Ok(CommittedDecision {
                request: r.request,
                token_digest: Sha256::digest(r.token.as_bytes()).into(),
                grant_id: r.grant_id,
            })
        })
    }

    /// Must be backed by authenticated, durable member evidence, not broker ACK.
    pub fn acknowledge(
        &self,
        decision: &CommittedDecision,
        member: &Prepared,
        policy: &impl Policy,
    ) -> Result<()> {
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            policy.continuity(&self.scope)?;
            let mut r = self.read(&tx)?.ok_or("decision missing")?;
            ensure(
                r.request == decision.request
                    && r.grant_id == decision.grant_id
                    && <[u8; 32]>::from(Sha256::digest(r.token.as_bytes()))
                        == decision.token_digest,
                "ack decision mismatch",
            )?;
            let index = r
                .request
                .prepared
                .iter()
                .position(|p| p == member)
                .ok_or("ack member mismatch")?;
            if r.acknowledgements[index] {
                return Ok(());
            }
            policy.applied(&self.scope, decision, member)?;
            policy.continuity(&self.scope)?;
            r.acknowledgements[index] = true;
            Self::save(&tx, &r)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn complete(&self, request: &Request, id: Id, policy: &impl Policy) -> Result<()> {
        ensure(id != [0; 32], "zero completion id")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            policy.continuity(&self.scope)?;
            let mut r = self.read(&tx)?.ok_or("decision missing")?;
            ensure(
                r.request == *request && r.acknowledgements == [true; 2],
                "completion evidence missing",
            )?;
            if let Some(previous) = r.completion {
                return ensure(previous == id, "immutable completion conflict");
            }
            r.completion = Some(id);
            Self::save(&tx, &r)?;
            tx.commit()?;
            Ok(())
        })
    }
}
