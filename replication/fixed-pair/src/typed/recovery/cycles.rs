//! Local recovery lineage. This is not an external rollback witness or authority.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retired {
    parent: Option<String>,
    active: Active,
    delivery: String,
    completion: String,
    next: Plan,
}

fn successor(a: &Active, next: &Plan) -> Result<()> {
    Model::new(next.baseline.clone()).step(next, Event::Authorize)?;
    ensure(
        a.member == a.request.plan.baseline.survivor
            && next.baseline.scope == a.request.plan.baseline.scope
            && next.baseline.revision == a.request.plan.revision
            && next.baseline.digest
                == digest(&(&a.request, a.token_digest, a.grant_id, &a.checkpoint))?
            && next.baseline.old_primary == a.request.plan.candidate
            && next.baseline.survivor == a.member
            && next.candidate != a.request.plan.baseline.old_primary
            && next.recovery_id != a.request.plan.recovery_id,
        "recovery cycle does not extend completed membership",
    )
}

fn visit_history(c: &Connection, mut visit: impl FnMut(&Retired) -> Result<()>) -> Result<String> {
    let mut parent = None;
    let mut next = None;
    let mut stmt =
        c.prepare("SELECT revision,record,digest FROM recovery_cycles ORDER BY revision")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let json: String = row.get(1)?;
        ensure(
            json.len() <= 256 * 1024,
            "recovery history record too large",
        )?;
        let r: Retired = serde_json::from_str(&json)?;
        let hash: String = row.get(2)?;
        ensure(
            hash == crate::hash(&r)?
                && r.parent == parent
                && row.get::<_, u64>(0)? == r.active.request.plan.revision
                && next.as_ref().is_none_or(|p| *p == r.active.request.plan),
            "recovery history chain mismatch",
        )?;
        let a = &r.active;
        a.request.validate(&a.request.plan.baseline)?;
        successor(a, &r.next)?;
        ensure(
            a.format == 1
                && a.token_digest != [0; 32]
                && a.grant_id != [0; 32]
                && a.checkpoint.identity == serde_json::from_str(&a.request.plan.baseline.scope)?
                && digest(&a.checkpoint)? == a.request.plan.baseline.checkpoint
                && a.request.prepared[1].member == a.member
                && r.delivery
                    == serde_json::to_string(&(
                        1u32,
                        &a.request,
                        a.token_digest,
                        a.grant_id,
                        &a.request.prepared[1],
                    ))?,
            "invalid retired recovery evidence",
        )?;
        let (version, request, token, grant, completion): (u32, DecisionRequest, Id, Id, Id) =
            serde_json::from_str(&r.completion)?;
        ensure(
            version == 1
                && request == a.request
                && token == a.token_digest
                && grant == a.grant_id
                && completion != [0; 32],
            "invalid retired completion",
        )?;
        visit(&r)?;
        parent = Some(hash);
        next = Some(r.next);
    }
    ensure(
        next.is_some() && next == seal(c)?,
        "recovery history head mismatch",
    )?;
    parent.ok_or_else(|| "empty recovery history".into())
}

pub(super) fn verify_history(c: &Connection, format: u32) -> Result<()> {
    match format {
        1 => ensure(!table(c, "recovery_cycles")?, "orphan recovery history"),
        2 => visit_history(c, |_| Ok(())).map(|_| ()),
        _ => Err("unsupported typed lifecycle format".into()),
    }
}

impl<A: ReplicatedSchema> Node<A> {
    pub(super) fn advance_cycle(
        &self,
        c: &rusqlite::Transaction<'_>,
        a: &Active,
        plan: &Plan,
    ) -> Result<()> {
        // The enclosing transaction preserves the old admission if any check fails.
        self.recovery_admission(c)?;
        successor(a, plan)?;
        let parent = if table(c, "recovery_cycles")? {
            Some(visit_history(c, |r| {
                ensure(
                    ![
                        r.active.request.plan.baseline.old_primary,
                        r.active.request.plan.candidate,
                    ]
                    .contains(&plan.candidate)
                        && r.active.request.plan.recovery_id != plan.recovery_id,
                    "retired incarnation or recovery ID reused",
                )
            })?)
        } else {
            None
        };
        let record = Retired {
            parent,
            active: a.clone(),
            next: plan.clone(),
            delivery: c.query_row(
                "SELECT receipt FROM recovery_delivery WHERE id=1",
                [],
                |r| r.get(0),
            )?,
            completion: c.query_row(
                "SELECT receipt FROM recovery_completion WHERE id=1",
                [],
                |r| r.get(0),
            )?,
        };
        let json = serde_json::to_string(&record)?;
        ensure(
            json.len() <= 256 * 1024,
            "recovery history record too large",
        )?;
        let plan_json = serde_json::to_string(plan)?;
        ensure(plan_json.len() <= 32768, "seal too large")?;
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS recovery_cycles(
            revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest TEXT NOT NULL)",
        )?;
        c.execute(
            "INSERT INTO recovery_cycles VALUES(?1,?2,?3)",
            params![a.request.plan.revision, json, crate::hash(&record)?],
        )?;
        c.execute_batch(
            "DROP TABLE recovery_active; DROP TABLE recovery_delivery;
            DROP TABLE recovery_completion; UPDATE node_runtime SET format=CASE WHEN format=3 OR format=4 THEN 4 ELSE 2 END WHERE id=1;",
        )?;
        ensure(
            c.execute("UPDATE recovery_seal SET plan=?1 WHERE id=1", [plan_json])? == 1,
            "missing recovery seal",
        )?;
        // Checks the actual current data and generation after replacing the old seal.
        // A failure rolls the archive, seal and format change back together.
        self.inspect_in(c, plan, plan.baseline.survivor)?;
        Ok(())
    }
}
