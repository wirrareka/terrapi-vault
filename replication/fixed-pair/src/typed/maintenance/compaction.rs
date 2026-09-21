//! Receipt-preserving local pair maintenance. No member replacement or TTL.
use super::*;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairPlan {
    pub id: [u8; 32],
    pub primary: CompactionPlan,
    pub secondary: CompactionPlan,
}
impl PairPlan {
    pub(super) fn local(&self, role: Role) -> &CompactionPlan {
        if role == Role::Primary {
            &self.primary
        } else {
            &self.secondary
        }
    }
    pub(super) fn validate_structural(&self) -> Result<()> {
        let (p, s) = (&self.primary, &self.secondary);
        ensure(
            self.id != [0; 32]
                && p.role == Role::Primary
                && s.role == Role::Secondary
                && p.format == 1
                && s.format == 1
                && p.contract == s.contract
                && p.checkpoint == s.checkpoint
                && p.membership == s.membership
                && p.recovery_anchor == s.recovery_anchor
                && p.membership.is_some() == p.recovery_anchor.is_some()
                && !p.unresolved_tail
                && !s.unresolved_tail
                && p.checkpoint.sequence > 0,
            "invalid pair compaction plan",
        )?;
        for n in [p, s] {
            let m = n
                .publication
                .as_ref()
                .ok_or("compaction requires frozen publication")?;
            m.encode()?;
            ensure(
                m.checkpoint == n.checkpoint
                    && m.contract == n.contract
                    && n.head.identity == n.checkpoint.identity
                    && n.head.length == n.checkpoint.sequence
                    && n.retained_receipts == n.checkpoint.sequence
                    && n.head
                        .base
                        .as_ref()
                        .is_none_or(|b| b.sequence < n.checkpoint.sequence),
                "compaction publication/base mismatch",
            )?;
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        self.validate_structural()?;
        ensure(
            self.primary.membership.is_none()
                && self.secondary.membership.is_none()
                && self.primary.recovery_anchor.is_none()
                && self.secondary.recovery_anchor.is_none(),
            "compaction of recovered membership is not supported",
        )
    }

    pub(super) fn validate_certified(&self) -> Result<()> {
        self.validate_structural()?;
        ensure(
            self.primary.membership.is_some()
                && self.primary.recovery_anchor.is_some()
                && self.secondary.membership.is_some()
                && self.secondary.recovery_anchor.is_some(),
            "certified compaction requires recovered membership",
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Decided,
    Applied,
    Complete,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub plan: PairPlan,
    pub phase: Phase,
}

fn has_state(c: &Connection) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='node_compaction')",
        [],
        |r| r.get(0),
    )?)
}
fn state(c: &Connection) -> Result<Option<Progress>> {
    if !has_state(c)? {
        return Ok(None);
    }
    let row: Option<(String, String)> = c
        .query_row(
            "SELECT record,digest FROM node_compaction WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(json, digest)| {
        ensure(json.len() <= 128 * 1024, "compaction record too large")?;
        let record: Progress = serde_json::from_str(&json)?;
        record.plan.validate()?;
        ensure(
            hash(&record)? == digest,
            "compaction record checksum mismatch",
        )?;
        Ok(record)
    })
    .transpose()
}
fn save(c: &Connection, record: &Progress) -> Result<()> {
    record.plan.validate()?;
    let json = serde_json::to_string(record)?;
    ensure(json.len() <= 128 * 1024, "compaction record too large")?;
    c.execute("INSERT INTO node_compaction VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET record=excluded.record,digest=excluded.digest", params![json,hash(record)?])?;
    Ok(())
}

pub(in crate::typed) fn require_idle(c: &Connection) -> Result<()> {
    ensure(
        state(c)?.is_none_or(|r| r.phase == Phase::Complete),
        "compaction requires completion",
    )
}

fn history(c: &Connection, mut visit: impl FnMut(&PairPlan) -> Result<()>) -> Result<()> {
    let owner: String = c.query_row("SELECT value FROM node_identity", [], |r| r.get(0))?;
    let (identity, role): (Identity<SchemaId>, Role) = serde_json::from_str(&owner)?;
    let root: String = c.query_row(
        "SELECT base FROM node_compaction_root WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let mut previous: Option<Prefix> = serde_json::from_str(&root)?;
    let mut stmt =
        c.prepare("SELECT sequence,plan,digest FROM node_compaction_history ORDER BY sequence")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let json: String = row.get(1)?;
        ensure(json.len() <= 128 * 1024, "compaction history too large")?;
        let plan: PairPlan = serde_json::from_str(&json)?;
        plan.validate()?;
        let local = plan.local(role);
        ensure(
            row.get::<_, u64>(0)? == local.checkpoint.sequence
                && row.get::<_, String>(2)? == hash(&plan)?
                && local.checkpoint.identity == identity
                && local.head.base == previous,
            "compaction history chain mismatch",
        )?;
        visit(&plan)?;
        previous = Some(local.checkpoint.clone());
    }
    ensure(
        checkpoint::base_for::<SchemaId>(c)? == previous,
        "compaction history/base mismatch",
    )?;
    Ok(())
}

pub(super) fn verify_metadata(c: &Connection, version: u32) -> Result<()> {
    let count: u32=c.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('node_compaction','node_compaction_history','node_compaction_root')",[],|r|r.get(0))?;
    if version < 2 {
        return ensure(count == 0, "orphan compaction metadata");
    }
    ensure(count == 3, "incomplete compaction metadata")?;
    let record = state(c)?.ok_or("missing compaction state")?;
    history(c, |_| Ok(()))?;
    let owner: String = c.query_row("SELECT value FROM node_identity", [], |r| r.get(0))?;
    let (_, role): (Identity<SchemaId>, Role) = serde_json::from_str(&owner)?;
    let local = record.plan.local(role);
    if matches!(record.phase, Phase::Applied | Phase::Complete) {
        let json: String = c.query_row(
            "SELECT plan FROM node_compaction_history WHERE sequence=?1",
            [local.checkpoint.sequence],
            |r| r.get(0),
        )?;
        ensure(
            serde_json::from_str::<PairPlan>(&json)? == record.plan,
            "compaction history head mismatch",
        )?;
    }
    let base = checkpoint::base_for::<SchemaId>(c)?;
    ensure(
        base == if matches!(record.phase, Phase::Applied | Phase::Complete) {
            Some(local.checkpoint.clone())
        } else {
            local.head.base.clone()
        },
        "compaction phase/base mismatch",
    )
}

impl<A: ReplicatedSchema> Node<A> {
    pub fn compaction_progress(&self) -> Result<Option<Progress>> {
        self.connection(|c| {
            self.verify_owner(c)?;
            state(c)
        })
    }
    fn prepare_compaction(&mut self, plan: &PairPlan) -> Result<()> {
        plan.validate()?;
        self.connection(super::loss::require_no_loss_recovery)?;
        if let Some(old) = self.compaction_progress()? {
            if old.plan == *plan {
                return Ok(());
            }
            ensure(
                old.phase == Phase::Complete,
                "another compaction is pending",
            )?;
        }
        ensure(
            self.plan_compaction()? == *plan.local(self.role),
            "stale compaction plan",
        )?;
        self.connection(|c| {
            super::loss::require_no_loss_recovery(c)?;
            self.admission(c)?;
            ensure(present(c)?,"enable maintenance before compaction")?;
            let tx=c.unchecked_transaction()?;
            require_unpinned(&tx)?;
            Node::<A>::verify_publication_in(&tx, plan.local(self.role).publication.as_ref().ok_or("missing publication")?, &self.identity, &self.contract)?;
            tx.execute_batch("CREATE TABLE IF NOT EXISTS node_compaction(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL,digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS node_compaction_history(sequence INTEGER PRIMARY KEY,plan TEXT NOT NULL,digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS node_compaction_root(id INTEGER PRIMARY KEY CHECK(id=1),base TEXT NOT NULL);
                UPDATE node_maintenance_format SET version=2 WHERE id=1;
                DELETE FROM replication_readiness;")?;
            tx.execute("INSERT OR IGNORE INTO node_compaction_root VALUES(1,?1)",[serde_json::to_string(&plan.local(self.role).head.base)?])?;
            save(&tx,&Progress{plan:plan.clone(),phase:Phase::Prepared})?;
            tx.commit()?;
            Ok(())
        })
    }
    fn compaction_step(&mut self, plan: &PairPlan, target: Phase) -> Result<()> {
        self.connection(|c| {
            super::loss::require_no_loss_recovery(c)?;
            self.verify_owner(c)?;
            let tx=c.unchecked_transaction()?;
            let mut r=state(&tx)?.ok_or("compaction not prepared")?;
            ensure(r.plan==*plan,"compaction plan mismatch")?;
            if r.phase==target || r.phase==Phase::Complete {return Ok(());}
            match (r.phase,target) {
                (Phase::Prepared,Phase::Decided) => {},
                (Phase::Decided,Phase::Applied) => {
                    self.recovery_admission(&tx)?;
                    let local=plan.local(self.role);
                    ensure(self.current(&tx,true)?.0==local.checkpoint && journal::head_for(&tx,&self.identity)?==local.head,"compaction cut changed")?;
                    require_unpinned(&tx)?;
                    Node::<A>::verify_publication_in(&tx, local.publication.as_ref().ok_or("missing publication")?, &self.identity, &self.contract)?;
                    tx.execute("INSERT INTO replication_base VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint",[serde_json::to_string(&local.checkpoint)?])?;
                    tx.execute("DELETE FROM replication_log WHERE sequence<=?1",[local.checkpoint.sequence])?;
                    tx.execute("UPDATE replication_revision SET value=?1 WHERE id=1",[checkpoint::fresh_generation()?.as_slice()])?;
                    tx.execute("INSERT INTO node_compaction_history VALUES(?1,?2,?3)",params![local.checkpoint.sequence,serde_json::to_string(plan)?,hash(plan)?])?;
                    ensure(self.current(&tx,true)?.0==local.checkpoint,"compaction changed checkpoint")?;
                },
                (Phase::Applied,Phase::Complete) => {},
                (Phase::Applied,Phase::Decided) => return Ok(()),
                _ => return Err("invalid compaction transition".into()),
            }
            r.phase=target;
            save(&tx,&r)?;
            tx.commit()?;
            Ok(())
        })
    }
}

/// Call with both exclusively owned local handles. This is an operator control
/// operation, not an unauthenticated remote endpoint or a new leader election.
pub fn plan_pair<A: ReplicatedSchema>(p: &Node<A>, s: &Node<A>) -> Result<PairPlan> {
    let plan = PairPlan {
        id: checkpoint::fresh_generation()?,
        primary: p.plan_compaction()?,
        secondary: s.plan_compaction()?,
    };
    plan.validate()?;
    Ok(plan)
}

/// Idempotently resume the exact plan after a lost reply or process exit. Both
/// local admissions remain closed until their durable completion phases.
pub fn compact_pair<A: ReplicatedSchema>(
    p: &mut Node<A>,
    s: &mut Node<A>,
    plan: &PairPlan,
) -> Result<()> {
    plan.validate()?;
    ensure(
        p.role == Role::Primary
            && s.role == Role::Secondary
            && p.identity == s.identity
            && p.identity == plan.primary.checkpoint.identity,
        "compaction pair mismatch",
    )?;
    // Validate both unprepared participants before closing either admission.
    for n in [&*p, &*s] {
        let old = n.compaction_progress()?;
        if old.as_ref().is_none_or(|r| r.plan != *plan) {
            ensure(
                n.plan_compaction()? == *plan.local(n.role),
                "stale compaction participant",
            )?;
            n.connection(|c| {
                require_unpinned(c)?;
                Node::<A>::verify_publication_in(
                    c,
                    plan.local(n.role)
                        .publication
                        .as_ref()
                        .ok_or("missing publication")?,
                    &n.identity,
                    &n.contract,
                )
            })?;
        }
    }
    p.prepare_compaction(plan)?;
    s.prepare_compaction(plan)?;
    p.compaction_step(plan, Phase::Decided)?;
    s.compaction_step(plan, Phase::Decided)?;
    s.compaction_step(plan, Phase::Applied)?;
    p.compaction_step(plan, Phase::Applied)?;
    s.compaction_step(plan, Phase::Complete)?;
    p.compaction_step(plan, Phase::Complete)?;
    recover(p, s)?;
    Ok(())
}
