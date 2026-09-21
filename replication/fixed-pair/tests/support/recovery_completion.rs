//! Historical completion fixture only. Evidence collection and installation
//! assertions are trusted local inputs, not authenticated remote attestation.
use super::{
    model::{Event, Id, Model, Plan},
    peers::{Local, Phase},
    recovery_grant::{verify, Context},
    recovery_registry::{Crash, Registry, Result},
    store::Store,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn token_digest(token: &str) -> Id {
    Sha256::digest(token.as_bytes()).into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub member: Id,
    pub request_id: Id,
    pub checkpoint: Id,
    pub token_digest: Id,
    pub activation_revision: u64,
}
impl Evidence {
    /// `installed` is an explicit fixture assertion, not a verified manifest.
    pub fn capture(
        store: &Store,
        plan: &Plan,
        member: Id,
        request_id: Id,
        installed: Option<Id>,
    ) -> Result<Self> {
        if request_id == [0; 32] || installed != Some(plan.baseline.checkpoint) {
            return Err("missing completion challenge or installation assertion".into());
        }
        let expected = Local::prepared(plan.clone(), member, [1; 32])?.saved();
        let (record, token) = store.diagnostic_snapshot(&expected)?;
        if record.saved.phase() != Phase::Active || record.revision == 0 {
            return Err("member is not durably active".into());
        }
        let token = token.ok_or("missing activation grant")?;
        Ok(Self {
            member,
            request_id,
            checkpoint: plan.baseline.checkpoint,
            token_digest: token_digest(&token),
            activation_revision: record.revision,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub request_id: Id,
    pub plan: Plan,
    pub grant_id: Id,
    pub token_digest: Id,
    /// Canonical roles: replacement primary, survivor. Never a multiset.
    pub evidence: [Evidence; 2],
}
impl Completion {
    fn validate(&self) -> Result {
        Model::new(self.plan.baseline.clone()).step(&self.plan, Event::Authorize)?;
        if self.request_id == [0; 32] || self.grant_id == [0; 32] || self.token_digest == [0; 32] {
            return Err("empty completion identity".into());
        }
        for (e, member) in self
            .evidence
            .iter()
            .zip([self.plan.candidate, self.plan.baseline.survivor])
        {
            if e.member != member
                || e.request_id != self.request_id
                || e.checkpoint != self.plan.baseline.checkpoint
                || e.token_digest != self.token_digest
                || e.activation_revision == 0
                || e.activation_revision > i64::MAX as u64
            {
                return Err("completion evidence binding".into());
            }
        }
        Ok(())
    }
}

impl Registry {
    pub(super) fn completion_record(c: &Connection) -> Result<Option<Completion>> {
        let (baseline, _, _, registry) = Self::read(c)?;
        let raw: Option<(u32, String, Vec<u8>)> = c
            .query_row(
                "SELECT format,record,digest FROM completion WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((format, json, digest)) = raw else {
            return Ok(None);
        };
        if format != 1
            || json.len() > 32 * 1024
            || Sha256::digest(json.as_bytes()).as_slice() != digest
        {
            return Err("invalid completion format or checksum".into());
        }
        let completion: Completion = serde_json::from_str(&json)?;
        completion.validate()?;
        let token = registry.token.ok_or("completion without publication")?;
        if completion.plan.baseline != baseline
            || completion.plan.revision != registry.allocated_revision
            || completion.token_digest != token_digest(&token)
        {
            return Err("completion registry binding".into());
        }
        Ok(Some(completion))
    }
    /// Historical read: does not require unexpired keys or live member probes.
    /// Not proof against rollback or a consistent rewrite of trusted storage.
    pub fn load_completion(&self) -> Result<Option<Completion>> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            Self::completion_record(&tx)
        })
    }
    /// Collector must only read member snapshots. It must not invoke activation
    /// or acquire member write locks while this registry write lock is held.
    pub fn complete(
        &self,
        request: &Completion,
        context: impl FnOnce() -> Context,
        collect: impl FnOnce() -> Result<[Evidence; 2]>,
        crash: Crash,
    ) -> Result<Completion> {
        request.validate()?;
        let json = serde_json::to_string(request)?;
        if json.len() > 32 * 1024 || matches!(crash, Crash::AfterSign) {
            return Err("completion limit or crash mode".into());
        }
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            if let Some(existing) = Self::completion_record(&tx)? {
                return if existing == *request {
                    Ok(existing)
                } else {
                    Err("conflicting immutable completion".into())
                };
            }
            let ctx = context();
            let registry = Self::bound(&tx, &ctx)?;
            let token = registry.token.ok_or("no published grant")?;
            let verified = verify(&token, &ctx)?;
            if verified.plan != request.plan
                || verified.grant_id != request.grant_id
                || token_digest(&token) != request.token_digest
            {
                return Err("completion does not match published grant".into());
            }
            if collect()? != request.evidence {
                return Err("completion differs from collected evidence".into());
            }
            let digest: Id = Sha256::digest(json.as_bytes()).into();
            tx.execute(
                "INSERT INTO completion VALUES(1,1,?1,?2)",
                params![json, digest.as_slice()],
            )?;
            Self::commit(tx, crash)?;
            Ok(request.clone())
        })
    }
}
