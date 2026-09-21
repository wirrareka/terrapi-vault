//! Typed data-plane bridge to the existing neutral recovery authority. No default
//! policy, election, fencing substitute or single-copy writes are provided.
use super::*;
mod cycles;

pub(super) fn verify_history(c: &Connection, format: u32) -> Result<()> {
    cycles::verify_history(c, format)
}
#[cfg(all(test, feature = "experimental-recovery"))]
pub(crate) mod tests;
#[cfg(feature = "experimental-recovery")]
use crate::recovery::decision::{Journal, Policy};
use crate::recovery::{
    decision::{CommittedDecision, Prepared, Request as DecisionRequest},
    model::{Event, Id, Model, Plan},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Active {
    format: u32,
    request: DecisionRequest,
    token_digest: Id,
    grant_id: Id,
    checkpoint: Prefix,
    member: Id,
}
fn table(c: &Connection, name: &str) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
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
    ensure(json.len() <= 32768, "seal too large")?;
    Ok(Some(serde_json::from_str(&json)?))
}
fn active(c: &Connection) -> Result<Option<Active>> {
    if !table(c, "recovery_active")? {
        return Ok(None);
    }
    let json: String = c.query_row("SELECT record FROM recovery_active WHERE id=1", [], |r| {
        r.get(0)
    })?;
    ensure(json.len() <= 65536, "active record too large")?;
    Ok(Some(serde_json::from_str(&json)?))
}
pub(super) fn is_active(c: &Connection) -> Result<bool> {
    Ok(active(c)?.is_some())
}
fn save_seal(c: &Connection, plan: &Plan) -> Result<()> {
    Model::new(plan.baseline.clone()).step(plan, Event::Authorize)?;
    if let Some(old) = seal(c)? {
        return ensure(old == *plan, "recovery plan conflict");
    }
    let json = serde_json::to_string(plan)?;
    ensure(json.len() <= 32768, "seal too large")?;
    c.execute_batch(
        "CREATE TABLE recovery_seal(id INTEGER PRIMARY KEY CHECK(id=1),plan TEXT NOT NULL)",
    )?;
    c.execute("INSERT INTO recovery_seal VALUES(1,?1)", [json])?;
    ensure(
        c.execute(
            "UPDATE checkpoint_format SET version=2 WHERE id=1 AND version=1",
            [],
        )? == 1,
        "recovery marker conflict",
    )?;
    Ok(())
}
fn digest<T: Serialize>(value: &T) -> Result<Id> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).into())
}
fn delivery(decision: &CommittedDecision, member: &Prepared) -> Result<String> {
    Ok(serde_json::to_string(&(
        1u32,
        decision.request(),
        decision.token_digest(),
        decision.grant_id(),
        member,
    ))?)
}

impl<A: ReplicatedSchema> Node<A> {
    fn inspect_in(&self, c: &Connection, plan: &Plan, member: Id) -> Result<Prepared> {
        self.verify_owner(c)?;
        Model::new(plan.baseline.clone()).step(plan, Event::Authorize)?;
        ensure(
            serde_json::to_string(&self.identity)? == plan.baseline.scope
                && [plan.candidate, plan.baseline.survivor].contains(&member),
            "recovery scope/member mismatch",
        )?;
        let restoring: bool =
            c.query_row("SELECT EXISTS(SELECT 1 FROM node_restore)", [], |r| {
                r.get(0)
            })?;
        ensure(!restoring, "snapshot incomplete")?;
        let checkpoint = digest(&self.current(c, true)?.0)?;
        let generation = checkpoint::generation(c)?;
        ensure(
            checkpoint == plan.baseline.checkpoint
                && (member != plan.baseline.survivor
                    || generation == plan.baseline.survivor_generation),
            "recovery checkpoint/generation mismatch",
        )?;
        if let Some(old) = seal(c)? {
            ensure(old == *plan, "another plan sealed")?;
        }
        Ok(Prepared {
            member,
            generation,
            checkpoint,
        })
    }
    pub fn inspect_recovery(&self, plan: &Plan, member: Id) -> Result<Prepared> {
        self.connection(|c| self.inspect_in(c, plan, member))
    }
    pub fn recovery_checkpoint_digest(&self) -> Result<Id> {
        self.connection(|c| {
            self.verify_owner(c)?;
            digest(&self.current(c, true)?.0)
        })
    }
    /// Explicit maintenance restriction. The authority integration still proves
    /// fencing independently before it can create a CommittedDecision.
    pub fn seal_recovery_source(&mut self, plan: &Plan) -> Result<()> {
        ensure(self.role == Role::Secondary, "survivor must be secondary")?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            ensure(
                self.verified_view_in(&tx)?.is_some(),
                "survivor is not verified",
            )?;
            if let Some(a) = active(&tx)? {
                self.advance_cycle(&tx, &a, plan)?;
            }
            self.inspect_in(&tx, plan, plan.baseline.survivor)?;
            save_seal(&tx, plan)?;
            tx.commit()?;
            Ok(())
        })
    }
    pub(super) fn recovery_export_admission(&self, c: &Connection) -> Result<()> {
        self.verify_owner(c)?;
        let plan = seal(c)?.ok_or("recovery export requires sealed survivor")?;
        ensure(
            self.role == Role::Secondary && active(c)?.is_none(),
            "recovery export requires inactive survivor",
        )?;
        self.inspect_in(c, &plan, plan.baseline.survivor)?;
        Ok(())
    }
    pub fn publish_recovery_snapshot(&mut self) -> Result<snapshot::Manifest> {
        self.publish_snapshot_inner(true)
    }
    pub(super) fn export_checkpoint_admission(
        &self,
        c: &Connection,
        checkpoint: &Prefix,
    ) -> Result<()> {
        if let Some(plan) = seal(c)? {
            if active(c)?.is_some() {
                self.recovery_admission(c)?;
            } else {
                self.recovery_export_admission(c)?;
                ensure(
                    digest(checkpoint)? == plan.baseline.checkpoint,
                    "publication differs from sealed recovery checkpoint",
                )?;
            }
        }
        Ok(())
    }
    pub fn record_recovery_decision(
        &mut self,
        decision: &CommittedDecision,
        member: Id,
    ) -> Result<()> {
        self.connection(|c|{
            let tx=c.unchecked_transaction()?;
            let actual=self.inspect_in(&tx,&decision.request().plan,member)?;
            ensure(decision.request().prepared.contains(&actual),"stale installation")?;
            let expected=delivery(decision,&actual)?;
            save_seal(&tx,&decision.request().plan)?;
            tx.execute_batch("CREATE TABLE IF NOT EXISTS recovery_delivery(id INTEGER PRIMARY KEY CHECK(id=1),receipt TEXT NOT NULL)")?;
            let old:Option<String>=tx.query_row("SELECT receipt FROM recovery_delivery WHERE id=1",[],|r|r.get(0)).optional()?;
            if let Some(old)=old {ensure(old==expected,"delivery conflict")?;} else {tx.execute("INSERT INTO recovery_delivery VALUES(1,?1)",[expected])?;}
            tx.commit()?;Ok(())
        })
    }
    pub fn verify_recovery_decision(
        &self,
        decision: &CommittedDecision,
        member: &Prepared,
    ) -> Result<()> {
        self.connection(|c| {
            ensure(
                self.inspect_in(c, &decision.request().plan, member.member)? == *member
                    && decision.request().prepared.contains(member),
                "installation changed",
            )?;
            let actual: String = c.query_row(
                "SELECT receipt FROM recovery_delivery WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            ensure(actual == delivery(decision, member)?, "delivery mismatch")
        })
    }
    fn validate_active(&self, c: &Connection, a: &Active) -> Result<()> {
        self.validate_active_as(c, self.role, a)
    }
    fn validate_active_as(&self, c: &Connection, role: Role, a: &Active) -> Result<()> {
        ensure(
            cfg!(feature = "experimental-recovery"),
            "recovered node requires experimental-recovery",
        )?;
        self.verify_owner_as(c, role)?;
        let plan = &a.request.plan;
        a.request.validate(&plan.baseline)?;
        let index = if a.member == plan.candidate {
            0
        } else if a.member == plan.baseline.survivor {
            1
        } else {
            return Err("active member mismatch".into());
        };
        ensure(
            a.format == 1
                && a.token_digest != [0; 32]
                && a.grant_id != [0; 32]
                && seal(c)?.as_ref() == Some(plan)
                && serde_json::to_string(&self.identity)? == plan.baseline.scope
                && role
                    == if index == 0 {
                        Role::Primary
                    } else {
                        Role::Secondary
                    }
                && a.request.prepared[index].member == a.member
                && a.request.prepared[index].generation == checkpoint::generation(c)?
                && a.checkpoint.identity == self.identity
                && digest(&a.checkpoint)? == plan.baseline.checkpoint,
            "active membership/data mismatch",
        )?;
        let base = checkpoint::base_for::<SchemaId>(c)?;
        let certified: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='node_compaction_certificates')",
            [],
            |r| r.get(0),
        )?;
        if !certified {
            ensure(
                checkpoint::calculate_for(
                    c,
                    &self.adapter,
                    &self.identity,
                    &self.initial,
                    true,
                    Some(a.checkpoint.sequence),
                )? == a.checkpoint,
                "active recovery anchor mismatch",
            )?;
        } else {
            let lineage =
                maintenance::certified::verify_metadata(c, 3, self.transition_trust.as_ref())?
                    .ok_or("active certified lineage missing")?;
            ensure(
                lineage.source_anchor == a.checkpoint && Some(lineage.current_base) == base,
                "active certified lineage mismatch",
            )?;
        }
        if index == 0 && !certified {
            ensure(
                base.as_ref() == Some(&a.checkpoint),
                "candidate base mismatch",
            )?;
        }
        let delivered: String = c.query_row(
            "SELECT receipt FROM recovery_delivery WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure(
            delivered
                == serde_json::to_string(&(
                    1u32,
                    &a.request,
                    a.token_digest,
                    a.grant_id,
                    &a.request.prepared[index],
                ))?,
            "active delivery mismatch",
        )
    }
    pub fn verify_recovery_active(
        &self,
        decision: &CommittedDecision,
        member: &Prepared,
    ) -> Result<()> {
        self.verify_recovery_decision(decision, member)?;
        self.connection(|c| {
            let a = active(c)?.ok_or("member not active")?;
            self.validate_active(c, &a)?;
            ensure(
                a.request == *decision.request()
                    && a.member == member.member
                    && a.token_digest == decision.token_digest()
                    && a.grant_id == decision.grant_id(),
                "active decision mismatch",
            )
        })
    }
    pub(super) fn recovery_admission(&self, c: &Connection) -> Result<()> {
        match (seal(c)?, active(c)?) {
            (None, None) => ensure(
                !table(c, "recovery_completion")? && !table(c, "recovery_delivery")?,
                "orphan recovery metadata",
            ),
            (Some(_), Some(a)) => {
                self.validate_active(c, &a)?;
                let json: String = c.query_row(
                    "SELECT receipt FROM recovery_completion WHERE id=1",
                    [],
                    |r| r.get(0),
                )?;
                let (version, request, token, grant, completion): (
                    u32,
                    DecisionRequest,
                    Id,
                    Id,
                    Id,
                ) = serde_json::from_str(&json)?;
                ensure(
                    version == 1
                        && request == a.request
                        && token == a.token_digest
                        && grant == a.grant_id
                        && completion != [0; 32],
                    "completion receipt mismatch",
                )
            }
            _ => Err("recovery not complete; data admission closed".into()),
        }
    }
    pub(super) fn recovery_membership(&self, c: &Connection) -> Result<Option<Id>> {
        self.recovery_admission(c)?;
        active(c)?
            .map(|a| digest(&(a.request, a.token_digest, a.grant_id, a.checkpoint)))
            .transpose()
    }
    pub(super) fn recovery_anchor(&self, c: &Connection) -> Result<Option<Prefix>> {
        Ok(active(c)?.map(|a| a.checkpoint))
    }
    pub fn required_recovery_peer(&self) -> Result<Option<Id>> {
        self.connection(|c| {
            self.recovery_admission(c)?;
            Ok(active(c)?.map(|a| {
                if a.member == a.request.plan.candidate {
                    a.request.plan.baseline.survivor
                } else {
                    a.request.plan.candidate
                }
            }))
        })
    }
    pub fn recovery_member_identity(&self) -> Result<Option<Id>> {
        self.connection(|c| {
            self.recovery_admission(c)?;
            Ok(active(c)?.map(|a| a.member))
        })
    }
    #[cfg(feature = "experimental-recovery")]
    fn activate_member(&mut self, decision: &CommittedDecision, index: usize) -> Result<()> {
        self.verify_recovery_decision(decision, &decision.request().prepared[index])?;
        let role = if index == 0 {
            Role::Primary
        } else {
            Role::Secondary
        };
        self.connection(|c|{
            let tx=c.unchecked_transaction()?;
            let member=&decision.request().prepared[index];
            ensure(self.inspect_in(&tx,&decision.request().plan,member.member)?==*member,"installation changed")?;
            let record=Active {format:1,request:decision.request().clone(),token_digest:decision.token_digest(),grant_id:decision.grant_id(),checkpoint:self.current(&tx,true)?.0,member:member.member};
            if index==0 {ensure(checkpoint::base_for::<SchemaId>(&tx)?.as_ref()==Some(&record.checkpoint),"candidate requires snapshot base")?;}
            let json=serde_json::to_string(&record)?;ensure(json.len()<=65536,"active record too large")?;
            tx.execute_batch("CREATE TABLE IF NOT EXISTS recovery_active(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)")?;
            let old:Option<String>=tx.query_row("SELECT record FROM recovery_active WHERE id=1",[],|r|r.get(0)).optional()?;
            if let Some(old)=old {ensure(old==json,"activation conflict")?;} else {
                ensure(self.role==Role::Secondary,"activation requires restricted role")?;
                tx.execute("INSERT INTO recovery_active VALUES(1,?1)",[json])?;
                tx.execute("UPDATE node_identity SET value=?1",[serde_json::to_string(&(&self.identity,role))?])?;
            }
            self.validate_active_as(&tx,role,&record)?;
            tx.commit()?;Ok(())
        })?;
        self.role = role;
        Ok(())
    }
    #[cfg(feature = "experimental-recovery")]
    fn complete_member(&mut self, request: &DecisionRequest, completion: Id) -> Result<()> {
        self.connection(|c|{
            let tx=c.unchecked_transaction()?;
            let a=active(&tx)?.ok_or("inactive member")?;self.validate_active(&tx,&a)?;
            ensure(a.request==*request,"completion request mismatch")?;
            let json=serde_json::to_string(&(1u32,request,a.token_digest,a.grant_id,completion))?;
            tx.execute_batch("CREATE TABLE IF NOT EXISTS recovery_completion(id INTEGER PRIMARY KEY CHECK(id=1),receipt TEXT NOT NULL)")?;
            let old:Option<String>=tx.query_row("SELECT receipt FROM recovery_completion WHERE id=1",[],|r|r.get(0)).optional()?;
            if let Some(old)=old {ensure(old==json,"completion conflict")?;} else {tx.execute("INSERT INTO recovery_completion VALUES(1,?1)",[json])?;}
            self.recovery_admission(&tx)?;tx.commit()?;Ok(())
        })
    }
}

/// Local/offline maintenance bridge; survivor activates before candidate.
/// Both remain closed to data traffic until complete_pair succeeds.
#[cfg(feature = "experimental-recovery")]
pub fn activate_pair<A: ReplicatedSchema>(
    candidate: &mut Node<A>,
    survivor: &mut Node<A>,
    journal: &Journal,
    request: &DecisionRequest,
    policy: &impl Policy,
) -> Result<()> {
    ensure(
        candidate.identity == survivor.identity,
        "pair data identity mismatch",
    )?;
    let decision = journal.fetch(request, policy)?;
    candidate.verify_recovery_decision(&decision, &request.prepared[0])?;
    survivor.verify_recovery_decision(&decision, &request.prepared[1])?;
    survivor.activate_member(&decision, 1)?;
    candidate.activate_member(&decision, 0)
}
/// Verifies both local installations and persists both authority ACKs before the
/// authority completion. Interrupted local completion resumes with the same ID.
#[cfg(feature = "experimental-recovery")]
pub fn complete_pair<A: ReplicatedSchema>(
    candidate: &mut Node<A>,
    survivor: &mut Node<A>,
    journal: &Journal,
    request: &DecisionRequest,
    completion: Id,
    policy: &impl Policy,
) -> Result<()> {
    ensure(completion != [0; 32], "zero completion")?;
    let status = journal.status()?;
    ensure(
        status.request.as_ref() == Some(request),
        "authority request mismatch",
    )?;
    for (node, member) in [
        (&*candidate, &request.prepared[0]),
        (&*survivor, &request.prepared[1]),
    ] {
        node.connection(|c| {
            let a = active(c)?.ok_or("inactive member")?;
            node.validate_active(c, &a)?;
            ensure(
                a.request == *request
                    && a.member == member.member
                    && node.inspect_in(c, &request.plan, member.member)? == *member,
                "completion installation mismatch",
            )
        })?;
    }
    if status.completion.is_none() {
        let decision = journal.fetch(request, policy)?;
        candidate.verify_recovery_active(&decision, &request.prepared[0])?;
        survivor.verify_recovery_active(&decision, &request.prepared[1])?;
        for member in &request.prepared {
            journal.acknowledge(&decision, member, policy)?;
        }
    }
    journal.complete(request, completion, policy)?;
    survivor.complete_member(request, completion)?;
    candidate.complete_member(request, completion)
}
