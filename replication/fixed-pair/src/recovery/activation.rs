//! Explicit experimental bridge to the fixed-pair data path.
//! Member IDs are SHA-256 leaf certificate pins in this bridge. Policy must
//! attest their mapping, physical fencing and continuity before deciding.
#[cfg(feature = "experimental-recovery")]
use super::decision::{Journal, Policy};
use super::{
    decision::{CommittedDecision, Request},
    installation,
    model::{Event, Id, Model, Plan},
};
use crate::{checkpoint, ensure, Checkpoint, Connection, Identity, Node, Result, Role};
#[cfg(feature = "experimental-recovery")]
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Active {
    format: u32,
    request: Request,
    token_digest: Id,
    grant_id: Id,
    checkpoint: Checkpoint,
    member: Id,
}

fn table(c: &Connection, name: &str) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )?)
}
fn seal(c: &Connection) -> Result<Option<Plan>> {
    if !table(c, "recovery_seal")? {
        return Ok(None);
    }
    let json: String = c.query_row("SELECT plan FROM recovery_seal WHERE id=1", [], |r| {
        r.get(0)
    })?;
    ensure(json.len() <= 32 * 1024, "seal limit")?;
    Ok(Some(serde_json::from_str(&json)?))
}
fn active(c: &Connection) -> Result<Option<Active>> {
    if !table(c, "recovery_active")? {
        return Ok(None);
    }
    let json: String = c.query_row("SELECT record FROM recovery_active WHERE id=1", [], |r| {
        r.get(0)
    })?;
    ensure(json.len() <= 64 * 1024, "active record limit")?;
    Ok(Some(serde_json::from_str(&json)?))
}
pub(super) fn save_seal(c: &Connection, plan: &Plan) -> Result<()> {
    if let Some(old) = seal(c)? {
        let version: u32 = c.query_row(
            "SELECT version FROM checkpoint_format WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure(version == 2, "recovery compatibility marker missing")?;
        return ensure(old == *plan, "another recovery plan sealed");
    }
    let json = serde_json::to_string(plan)?;
    ensure(json.len() <= 32 * 1024, "seal limit")?;
    c.execute_batch(
        "CREATE TABLE recovery_seal(id INTEGER PRIMARY KEY CHECK(id=1),plan TEXT NOT NULL);",
    )?;
    c.execute("INSERT INTO recovery_seal VALUES(1,?1)", [json])?;
    ensure(
        c.execute(
            "UPDATE checkpoint_format SET version=2 WHERE id=1 AND version=1",
            [],
        )? == 1,
        "recovery compatibility marker conflict",
    )?;
    Ok(())
}
fn validate(c: &Connection, role: Role, identity: &Identity, a: &Active) -> Result<()> {
    ensure(
        cfg!(feature = "experimental-recovery"),
        "recovered node requires experimental-recovery build",
    )?;
    let plan = &a.request.plan;
    a.request.validate(&plan.baseline)?;
    ensure(
        a.format == 1 && a.token_digest != [0; 32] && a.grant_id != [0; 32],
        "active record format/identity",
    )?;
    Model::new(plan.baseline.clone()).step(plan, Event::Authorize)?;
    ensure(
        seal(c)?.as_ref() == Some(plan)
            && installation::data_scope(identity)? == plan.baseline.scope,
        "active membership scope/seal mismatch",
    )?;
    let index = if a.member == plan.candidate {
        0
    } else if a.member == plan.baseline.survivor {
        1
    } else {
        return Err("active member mismatch".into());
    };
    ensure(
        role == if index == 0 {
            Role::Primary
        } else {
            Role::Secondary
        } && a.request.prepared[index].member == a.member
            && a.request.prepared[index].generation == checkpoint::generation(c)?
            && a.request.prepared[index].checkpoint == plan.baseline.checkpoint
            && a.checkpoint.identity == *identity
            && <Id>::from(Sha256::digest(serde_json::to_vec(&a.checkpoint)?))
                == plan.baseline.checkpoint
            && checkpoint::calculate(c, identity, true, Some(a.checkpoint.sequence))?
                == a.checkpoint,
        "active membership/data mismatch",
    )
}

pub(crate) fn verified_seal(c: &Connection, node: &Node) -> Result<()> {
    let plan = seal(c)?.ok_or("recovery export requires persistent source seal")?;
    installation::inspect(c, node, &plan, plan.baseline.survivor)?;
    Ok(())
}

/// All legacy data mutations stop at a seal; only a validated active membership
/// can pass it. This is local enforcement, not protection against disk rollback.
pub(crate) fn admission(c: &Connection, role: Role, identity: &Identity) -> Result<()> {
    match (seal(c)?, active(c)?) {
        (None, None) => Ok(()),
        (Some(_), Some(a)) => validate(c, role, identity, &a),
        _ => Err("recovery sealed; data mutations disabled".into()),
    }
}

pub(crate) fn bootstrap(c: &Connection) -> Result<()> {
    ensure(
        seal(c)?.is_none() && active(c)?.is_none(),
        "bootstrap forbidden for recovery-bound node",
    )
}

pub(crate) fn pair_digest(c: &Connection, role: Role, identity: &Identity) -> Result<Option<Id>> {
    admission(c, role, identity)?;
    active(c)?
        .map(|a| {
            Ok(Sha256::digest(serde_json::to_vec(&(
                a.request,
                a.token_digest,
                a.grant_id,
                a.checkpoint,
            ))?)
            .into())
        })
        .transpose()
}

pub(crate) fn validate_primary_base(
    c: &Connection,
    role: Role,
    identity: &Identity,
) -> Result<bool> {
    if let Some(a) = active(c)? {
        validate(c, role, identity, &a)?;
        if role == Role::Primary {
            ensure(
                checkpoint::base(c)?.as_ref() == Some(&a.checkpoint),
                "recovered primary base changed",
            )?;
            return Ok(true);
        }
    }
    Ok(false)
}

impl Node {
    pub(crate) fn recovery_member_identity(&self) -> Result<Option<Id>> {
        self.connection(|c| {
            if let Some(a) = active(c)? {
                validate(c, self.role, &self.identity, &a)?;
                Ok(Some(a.member))
            } else {
                ensure(seal(c)?.is_none(), "sealed member not active")?;
                Ok(None)
            }
        })
    }
    /// Irreversible restriction in this foundation; no general unseal shortcut.
    /// Call only under authenticated operator maintenance after external fencing.
    pub fn seal_recovery_source(&mut self, plan: &Plan) -> Result<()> {
        ensure(self.role == Role::Secondary, "source must be secondary")?;
        Model::new(plan.baseline.clone()).step(plan, Event::Authorize)?;
        self.connection(|c| {
            let tx =
                rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            ensure(
                checkpoint::verified_view(&tx, &self.identity)?.is_some(),
                "source not verified",
            )?;
            crate::snapshot_staging::ensure_idle(&tx)?;
            crate::publication::ensure_idle(&tx)?;
            installation::inspect(&tx, self, plan, plan.baseline.survivor)?;
            save_seal(&tx, plan)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// SHA-256 client leaf pin required after replacement; legacy nodes return None.
    pub fn required_recovery_peer(&self) -> Result<Option<Id>> {
        self.connection(|c| {
            if let Some(a) = active(c)? {
                validate(c, self.role, &self.identity, &a)?;
                Ok(Some(if a.member == a.request.plan.candidate {
                    a.request.plan.baseline.survivor
                } else {
                    a.request.plan.candidate
                }))
            } else {
                ensure(seal(c)?.is_none(), "sealed node has no active peer")?;
                Ok(None)
            }
        })
    }

    pub fn verify_recovery_active(
        &self,
        decision: &CommittedDecision,
        member: &super::decision::Prepared,
    ) -> Result<()> {
        self.verify_recovery_decision(decision, member)?;
        self.connection(|c| {
            let a = active(c)?.ok_or("member not active")?;
            validate(c, self.role, &self.identity, &a)?;
            ensure(
                a.request == *decision.request()
                    && a.member == member.member
                    && a.token_digest == decision.token_digest()
                    && a.grant_id == decision.grant_id(),
                "active decision mismatch",
            )
        })
    }
}

/// Local/offline pair bridge. Both Node handles exclusively own their files.
/// Survivor commits first; a partial transition cannot pair with the legacy primary.
/// Transport deployment and physical fencing are separate mandatory obligations.
#[cfg(feature = "experimental-recovery")]
pub fn activate_pair(
    candidate: &mut Node,
    survivor: &mut Node,
    journal: &Journal,
    request: &Request,
    policy: &impl Policy,
) -> Result<()> {
    let decision = journal.fetch(request, policy)?;
    ensure(
        candidate.identity == survivor.identity,
        "activation data identity mismatch",
    )?;
    candidate.verify_recovery_decision(&decision, &request.prepared[0])?;
    survivor.verify_recovery_decision(&decision, &request.prepared[1])?;
    activate_one(survivor, &decision, 1)?;
    activate_one(candidate, &decision, 0)?;
    Ok(())
}

#[cfg(feature = "experimental-recovery")]
fn activate_one(node: &mut Node, decision: &CommittedDecision, index: usize) -> Result<()> {
    let role = if index == 0 {
        Role::Primary
    } else {
        Role::Secondary
    };
    node.connection(|c| {
        let tx=rusqlite::Transaction::new_unchecked(c,rusqlite::TransactionBehavior::Immediate)?;
        let plan=&decision.request().plan;
        let actual=installation::inspect(&tx,node,plan,decision.request().prepared[index].member)?;
        ensure(actual==decision.request().prepared[index],"activation installation changed")?;
        let record=Active {format:1,request:decision.request().clone(),token_digest:decision.token_digest(),grant_id:decision.grant_id(),checkpoint:checkpoint::current(&tx,&node.identity,true)?.0,member:actual.member};
        if index==0 {ensure(checkpoint::base(&tx)?.as_ref()==Some(&record.checkpoint),"candidate requires installed materialized base")?;}
        let json=serde_json::to_string(&record)?;
        ensure(json.len()<=64*1024,"active record limit")?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS recovery_active(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL);")?;
        let old: Option<String>=tx.query_row("SELECT record FROM recovery_active WHERE id=1",[],|r|r.get(0)).optional()?;
        if let Some(old)=old {ensure(old==json,"active record conflict")?;} else {
            ensure(node.role==Role::Secondary,"new activation requires restricted secondary role")?;
            save_seal(&tx,plan)?;
            tx.execute("INSERT INTO recovery_active VALUES(1,?1)",[&json])?;
            tx.execute("UPDATE node_identity SET value=?1",[serde_json::to_string(&(&node.identity,role))?])?;
        }
        validate(&tx,role,&node.identity,&record)?;
        tx.commit()?;Ok(())
    })?;
    node.role = role;
    Ok(())
}
