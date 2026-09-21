//! Binds recovery control receipts to real, quiescent Vesta data and generation.
//! These receipts deliberately do not change Role or enable business writes.
use super::{
    decision::{CommittedDecision, Prepared},
    model::{Id, Plan},
};
use crate::{checkpoint, ensure, Connection, Identity, Node, Result};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

/// Stable full data identity representation for new recovery plans.
pub fn data_scope(identity: &Identity) -> Result<String> {
    Ok(serde_json::to_string(identity)?)
}

/// Digest of the complete checkpoint, including data, history and receipts.
pub fn checkpoint_digest(node: &Node) -> Result<Id> {
    Ok(Sha256::digest(serde_json::to_vec(&node.checkpoint()?)?).into())
}

pub(super) fn inspect(c: &Connection, node: &Node, plan: &Plan, member: Id) -> Result<Prepared> {
    ensure(
        member == plan.candidate || member == plan.baseline.survivor,
        "wrong recovery member",
    )?;
    ensure(
        data_scope(&node.identity)? == plan.baseline.scope,
        "recovery data scope mismatch",
    )?;
    let cp = checkpoint::current(c, &node.identity, true)?.0;
    let digest: Id = Sha256::digest(serde_json::to_vec(&cp)?).into();
    ensure(
        digest == plan.baseline.checkpoint,
        "recovery installation checkpoint mismatch",
    )?;
    let generation = checkpoint::generation(c)?;
    if member == plan.baseline.survivor {
        ensure(
            generation == plan.baseline.survivor_generation,
            "recovery survivor generation mismatch",
        )?;
    }
    Ok(Prepared {
        member,
        generation,
        checkpoint: digest,
    })
}

fn receipt(decision: &CommittedDecision, member: &Prepared) -> Result<String> {
    Ok(serde_json::to_string(&(
        1u32,
        decision.request(),
        decision.token_digest(),
        decision.grant_id(),
        member,
    ))?)
}

impl Node {
    /// Inspection is not source fencing or a persistent source pin.
    pub fn inspect_recovery(&self, plan: &Plan, member: Id) -> Result<Prepared> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            inspect(&tx, self, plan, member)
        })
    }

    /// Persist the control-plane delivery receipt with checkpoint/generation checks
    /// in the same transaction. No activation of the data-plane writer occurs.
    pub fn record_recovery_decision(
        &mut self,
        decision: &CommittedDecision,
        member: Id,
    ) -> Result<()> {
        self.connection(|c| {
            let tx = rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            let actual = inspect(&tx, self, &decision.request().plan, member)?;
            ensure(decision.request().prepared.contains(&actual), "stale installation generation")?;
            let expected = receipt(decision, &actual)?;
            super::activation::save_seal(&tx, &decision.request().plan)?;
            tx.execute_batch("CREATE TABLE IF NOT EXISTS recovery_delivery(id INTEGER PRIMARY KEY CHECK(id=1),receipt TEXT NOT NULL);")?;
            let old: Option<String> = tx.query_row("SELECT receipt FROM recovery_delivery WHERE id=1", [], |r| r.get(0)).optional()?;
            if let Some(old) = old { ensure(old == expected, "immutable recovery delivery conflict")?; }
            else { tx.execute("INSERT INTO recovery_delivery VALUES(1,?1)", [&expected])?; }
            tx.commit()?;
            Ok(())
        })
    }

    /// Fresh local evidence for Policy::applied. No caller-supplied applied flag.
    pub fn verify_recovery_decision(
        &self,
        decision: &CommittedDecision,
        member: &Prepared,
    ) -> Result<()> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            ensure(
                inspect(&tx, self, &decision.request().plan, member.member)? == *member
                    && decision.request().prepared.contains(member),
                "recovery member changed",
            )?;
            let actual: String = tx.query_row(
                "SELECT receipt FROM recovery_delivery WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            ensure(
                actual == receipt(decision, member)?,
                "recovery receipt mismatch",
            )
        })
    }
}
