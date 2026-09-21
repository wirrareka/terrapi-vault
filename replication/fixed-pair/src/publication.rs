//! One immutable local recovery artifact per node, coordinated across the fixed pair.
//! Confirmation is not a compaction permit or a membership/fencing protocol.
use crate::*;
use rusqlite::OptionalExtension;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proposal {
    pub checkpoint: Checkpoint,
    pub token: [u8; 32],
    pub primary_generation: [u8; 32],
    pub secondary_generation: [u8; 32],
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Captured,
    Confirmed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub proposal: Proposal,
    pub phase: Phase,
}

fn stored(c: &Connection) -> Result<Option<Record>> {
    let json: Option<String> = c
        .query_row("SELECT record FROM published_base WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    json.map(|s| Ok(serde_json::from_str(&s)?)).transpose()
}
pub(super) fn ensure_idle(c: &Connection) -> Result<()> {
    ensure(
        stored(c)?.is_none_or(|r| r.phase == Phase::Confirmed),
        "base publication in progress",
    )
}
pub(super) fn ensure_absent(c: &Connection) -> Result<()> {
    ensure(stored(c)?.is_none(), "bootstrap target has published base")
}
fn artifact_view(c: &Connection) -> Result<View> {
    let places = c
        .prepare("SELECT id,name FROM published_places ORDER BY id")?
        .query_map([], |r| {
            Ok(Place {
                id: r.get(0)?,
                name: r.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let features = c
        .prepare("SELECT id,place_id,geojson FROM published_features ORDER BY id")?
        .query_map([], |r| {
            Ok(Feature {
                id: r.get(0)?,
                place_id: r.get(1)?,
                geojson: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(View { places, features })
}
pub(super) fn validate(c: &Connection, identity: &Identity) -> Result<Option<Record>> {
    let record = stored(c)?;
    let counts: (u64,u64,u64) = c.query_row("SELECT (SELECT count(*) FROM published_places),(SELECT count(*) FROM published_features),(SELECT count(*) FROM published_receipts)",[],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    if let Some(r) = &record {
        let cp = &r.proposal.checkpoint;
        ensure(
            cp.identity == *identity && cp.format == 1 && cp.sequence == counts.2,
            "invalid published base metadata",
        )?;
        ensure(
            hash(&artifact_view(c)?)? == cp.view_digest
                && checkpoint::receipt_digest_from(c, cp.sequence, true)? == cp.receipt_digest,
            "published base content mismatch",
        )?;
        ensure(
            checkpoint::calculate(c, identity, true, Some(cp.sequence))? == *cp,
            "published base history mismatch",
        )?;
    } else {
        ensure(counts == (0, 0, 0), "orphan published base rows")?;
    }
    Ok(record)
}
pub(super) fn initialize(c: &Connection, identity: &Identity) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS published_base(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS published_places(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS published_features(id TEXT PRIMARY KEY NOT NULL,place_id TEXT NOT NULL REFERENCES published_places(id),geojson TEXT NOT NULL CHECK(json_valid(geojson)));
        CREATE TABLE IF NOT EXISTS published_receipts(operation_id TEXT PRIMARY KEY NOT NULL,sequence INTEGER UNIQUE NOT NULL,receipt TEXT NOT NULL);")?;
    validate(c, identity)?;
    Ok(())
}
fn bind(c: &Connection, role: Role, identity: &Identity, p: &Proposal) -> Result<()> {
    ensure(
        p.checkpoint.identity == *identity && p.checkpoint.format == 1,
        "publication identity/format mismatch",
    )?;
    let expected = match role {
        Role::Primary => p.primary_generation,
        Role::Secondary => p.secondary_generation,
    };
    ensure(
        checkpoint::generation(c)? == expected,
        "stale publication generation",
    )
}
pub(super) fn validate_primary_base(c: &Connection, role: Role, identity: &Identity) -> Result<()> {
    if recovery::activation::validate_primary_base(c, role, identity)? {
        return Ok(());
    }
    if role == Role::Primary {
        if let Some(base) = checkpoint::base(c)? {
            let r = validate(c, identity)?.ok_or("primary base has no publication")?;
            ensure(
                r.phase == Phase::Confirmed && r.proposal.checkpoint == base,
                "primary base not confirmed locally",
            )?;
            bind(c, role, identity, &r.proposal)?;
        }
    }
    Ok(())
}
#[cfg(feature = "test-support")]
fn crash(point: &str, code: i32) {
    if std::env::var("VESTA_PROTOTYPE_CRASH_PUBLICATION").as_deref() == Ok(point) {
        std::process::exit(code);
    }
}
#[cfg(not(feature = "test-support"))]
fn crash(_point: &str, _code: i32) {}
impl Node {
    /// Logical activation only. All physical journal rows remain untouched.
    pub fn activate_published_base(&mut self, proposal: Proposal) -> Result<()> {
        self.connection(|c| {
            recovery::activation::admission(c, self.role, &self.identity)?;
            ensure(recovery::activation::pair_digest(c,self.role,&self.identity)?.is_none(), "recovered base rotation not supported")?;
            let tx = c.unchecked_transaction()?;
            bind(&tx, self.role, &self.identity, &proposal)?;
            let r = validate(&tx, &self.identity)?.ok_or("no published base")?;
            ensure(r.phase == Phase::Confirmed && r.proposal == proposal, "activation requires matching confirmed publication")?;
            let old = checkpoint::base(&tx)?;
            if old.as_ref() == Some(&proposal.checkpoint) { return Ok(()); }
            ensure(old.as_ref().is_none_or(|b| b.sequence < proposal.checkpoint.sequence), "base cannot move backwards")?;
            snapshot_staging::ensure_idle(&tx)?;
            let before = checkpoint::current(&tx, &self.identity, true)?.0;
            tx.execute("INSERT INTO replication_base VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint", [serde_json::to_string(&proposal.checkpoint)?])?;
            ensure(checkpoint::current(&tx, &self.identity, true)?.0 == before, "activation changed current checkpoint")?;
            tx.execute("UPDATE replication_revision SET value=?1 WHERE id=1", [checkpoint::fresh_generation()?.as_slice()])?;
            crash("activate_before_commit", 95);
            tx.commit()?;
            crash("activate_after_commit", 96);
            Ok(())
        })
    }
    pub fn base_status(&self) -> Result<Option<Record>> {
        self.connection(|c| validate(c, &self.identity))
    }
    /// Private/operator inspection; not a public plaintext export endpoint.
    pub fn published_view(&self) -> Result<Option<View>> {
        self.connection(|c| {
            validate(c, &self.identity)?
                .map(|_| artifact_view(c))
                .transpose()
        })
    }
    pub fn capture_base(&mut self, proposal: Proposal) -> Result<Record> {
        self.connection(|c| {
            recovery::activation::admission(c, self.role, &self.identity)?;
            let tx = c.unchecked_transaction()?;
            bind(&tx,self.role,&self.identity,&proposal)?;
            if let Some(r) = validate(&tx,&self.identity)? {
                ensure(r.proposal == proposal, "published base slot already occupied")?;
                return Ok(r);
            }
            snapshot_staging::ensure_idle(&tx)?;
            ensure(checkpoint::current(&tx,&self.identity,true)?.0 == proposal.checkpoint, "publication requires matching quiescent checkpoint")?;
            let (rows,bytes): (u64,u64) = tx.query_row("SELECT
                (SELECT count(*) FROM places)+(SELECT count(*) FROM features)+(SELECT count(*) FROM operation_receipts),
                coalesce((SELECT sum(length(CAST(id AS BLOB))+length(CAST(name AS BLOB))) FROM places),0)+
                coalesce((SELECT sum(length(CAST(id AS BLOB))+length(CAST(place_id AS BLOB))+length(CAST(geojson AS BLOB))) FROM features),0)+
                coalesce((SELECT sum(length(CAST(operation_id AS BLOB))+length(CAST(receipt AS BLOB))) FROM operation_receipts),0)",[],|r| Ok((r.get(0)?,r.get(1)?)))?;
            ensure(rows <= materialized::MAX_ROWS && bytes <= materialized::MAX_BYTES, "published base logical quota exceeded")?;
            tx.execute_batch("INSERT INTO published_places SELECT * FROM places;
                INSERT INTO published_features SELECT * FROM features;
                INSERT INTO published_receipts SELECT * FROM operation_receipts;")?;
            let r = Record {proposal,phase:Phase::Captured};
            tx.execute("INSERT INTO published_base VALUES(1,?1)",[serde_json::to_string(&r)?])?;
            validate(&tx,&self.identity)?;
            crash("capture_before_commit",91);
            tx.commit()?;
            crash("capture_after_commit",92);
            Ok(r)
        })
    }
    /// Low-level trusted coordinator operation. Never call as an independent GC grant.
    pub fn confirm_base(&mut self, proposal: Proposal) -> Result<Record> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            bind(&tx, self.role, &self.identity, &proposal)?;
            let mut r = validate(&tx, &self.identity)?.ok_or("base not captured")?;
            ensure(r.proposal == proposal, "publication proposal mismatch")?;
            r.phase = Phase::Confirmed;
            tx.execute(
                "UPDATE published_base SET record=?1 WHERE id=1",
                [serde_json::to_string(&r)?],
            )?;
            crash("confirm_before_commit", 93);
            tx.commit()?;
            crash("confirm_after_commit", 94);
            Ok(r)
        })
    }
}
pub trait BaseReplica: Replica {
    fn activate_published_base(&mut self, _p: Proposal) -> Result<()> {
        Err("replica does not support base activation".into())
    }
    fn base_status(&mut self) -> Result<Option<Record>>;
    fn capture_base(&mut self, p: Proposal) -> Result<Record>;
    fn confirm_base(&mut self, p: Proposal) -> Result<Record>;
}
impl BaseReplica for Node {
    fn activate_published_base(&mut self, p: Proposal) -> Result<()> {
        Node::activate_published_base(self, p)
    }
    fn base_status(&mut self) -> Result<Option<Record>> {
        Node::base_status(self)
    }
    fn capture_base(&mut self, p: Proposal) -> Result<Record> {
        Node::capture_base(self, p)
    }
    fn confirm_base(&mut self, p: Proposal) -> Result<Record> {
        Node::confirm_base(self, p)
    }
}
pub fn activate_base(p: &mut Node, s: &mut impl BaseReplica) -> Result<()> {
    let r = p.base_status()?.ok_or("no published base to activate")?;
    ensure(
        r.phase == Phase::Confirmed && s.base_status()? == Some(r.clone()),
        "pair publication not confirmed",
    )?;
    ensure(
        p.journal_head()?.read_generation == r.proposal.primary_generation
            && s.summary()?.head.read_generation == r.proposal.secondary_generation,
        "activation pair generation changed",
    )?;
    recover(p, s)?;
    s.activate_published_base(r.proposal.clone())?;
    let head = s.summary()?.head;
    ensure(
        head.base.as_ref() == Some(&r.proposal.checkpoint)
            && head.read_generation == r.proposal.secondary_generation,
        "peer activation not confirmed",
    )?;
    p.activate_published_base(r.proposal)
}
pub fn publish_base(p: &mut Node, s: &mut impl BaseReplica) -> Result<Record> {
    recover(p, s)?;
    let proposal = if let Some(r) = p.base_status()? {
        r.proposal
    } else {
        ensure(
            s.base_status()?.is_none(),
            "secondary has unmatched publication",
        )?;
        Proposal {
            checkpoint: p.checkpoint()?,
            token: checkpoint::fresh_generation()?,
            primary_generation: p.journal_head()?.read_generation,
            secondary_generation: s.summary()?.head.read_generation,
        }
    };
    ensure(
        p.journal_head()?.read_generation == proposal.primary_generation
            && s.summary()?.head.read_generation == proposal.secondary_generation,
        "publication pair generation changed",
    )?;
    ensure(
        p.checkpoint_at(proposal.checkpoint.sequence)? == proposal.checkpoint,
        "published base not in primary history",
    )?;
    p.capture_base(proposal.clone())?;
    let peer = s.capture_base(proposal.clone())?;
    ensure(peer.proposal == proposal, "peer captured different base")?;
    let peer = s.confirm_base(proposal.clone())?;
    ensure(
        peer.proposal == proposal && peer.phase == Phase::Confirmed,
        "peer has not confirmed base",
    )?;
    ensure(
        s.summary()?.head.read_generation == proposal.secondary_generation,
        "publication peer generation changed",
    )?;
    p.confirm_base(proposal)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            cluster: "pair".into(),
            tenant: "tenant".into(),
            epoch: 1,
            schema: 1,
        }
    }
    fn populated(path: &std::path::Path) -> (Node, Proposal) {
        let mut p = Node::open(path, Role::Primary, identity(), "fixture").unwrap();
        p.prepare(Batch {
            identity: identity(),
            operation_id: "one".into(),
            changes: vec![Change::PutPlace {
                id: "p".into(),
                name: "name".into(),
            }],
        })
        .unwrap();
        let e = p.decide("one").unwrap();
        p.apply(e).unwrap();
        let proposal = Proposal {
            checkpoint: p.checkpoint().unwrap(),
            token: [1; 32],
            primary_generation: p.journal_head().unwrap().read_generation,
            secondary_generation: [2; 32],
        };
        (p, proposal)
    }
    #[test]
    fn corrupted_artifact_data_receipts_and_history_fail_status_and_reopen() {
        for sql in [
            "UPDATE published_places SET name='corrupt'",
            "DELETE FROM published_receipts",
            "UPDATE published_base SET record=json_set(record,'$.proposal.checkpoint.journal_digest','corrupt')",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p");
            let (mut p, proposal) = populated(&path);
            p.capture_base(proposal).unwrap();
            p.connection(|c| { c.execute_batch(sql)?; Ok(()) }).unwrap();
            assert!(p.base_status().is_err());
            assert!(p.published_view().is_err());
            drop(p);
            assert!(Node::open(&path, Role::Primary, identity(), "fixture").is_err());
        }
    }
    #[test]
    fn failed_copy_rolls_back_artifact_and_does_not_lock_writes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut p, proposal) = populated(&dir.path().join("p"));
        p.connection(|c| { c.execute_batch("CREATE TRIGGER reject_copy BEFORE INSERT ON published_receipts BEGIN SELECT RAISE(ABORT,'injected copy failure'); END;")?; Ok(()) }).unwrap();
        assert!(p.capture_base(proposal.clone()).is_err());
        assert!(p.base_status().unwrap().is_none());
        assert_eq!(p.checkpoint().unwrap(), proposal.checkpoint);
        p.connection(|c| {
            ensure_idle(c)?;
            c.execute_batch("DROP TRIGGER reject_copy")?;
            Ok(())
        })
        .unwrap();
        p.capture_base(proposal).unwrap();
    }

    #[test]
    fn primary_and_secondary_recover_without_prefix_and_keep_receipt_admission() {
        let dir = tempfile::tempdir().unwrap();
        let pp = dir.path().join("p");
        let sp = dir.path().join("s");
        let (mut p, _) = populated(&pp);
        let mut s = Node::open(&sp, Role::Secondary, identity(), "fixture").unwrap();
        recover(&mut p, &mut s).unwrap();
        publish_base(&mut p, &mut s).unwrap();
        activate_base(&mut p, &mut s).unwrap();
        let before = p.checkpoint().unwrap();
        // Fault injection in disposable test databases only. No production GC API exists.
        for node in [&p, &s] {
            node.connection(|c| {
                c.execute("DELETE FROM replication_log WHERE sequence<=1", [])?;
                Ok(())
            })
            .unwrap();
        }
        drop(p);
        drop(s);
        let mut p = Node::open(&pp, Role::Primary, identity(), "fixture").unwrap();
        let mut s = Node::open(&sp, Role::Secondary, identity(), "fixture").unwrap();
        assert_eq!(p.checkpoint().unwrap(), before);
        assert_eq!(s.checkpoint().unwrap(), before);
        assert!(p.status().unwrap().entries.is_empty());
        let first = Batch {
            identity: identity(),
            operation_id: "one".into(),
            changes: vec![Change::PutPlace {
                id: "p".into(),
                name: "name".into(),
            }],
        };
        assert!(p.prepare(first.clone()).is_err());
        assert_eq!(commit(&mut p, &mut s, first.clone()).unwrap().sequence, 1);
        let mut gate = coordinator::Coordinator::new(p, s).unwrap();
        let mut conflict = first.clone();
        conflict.changes.clear();
        assert_eq!(gate.write(conflict).unwrap_err().status_code, 400);
        assert_eq!(gate.write(first.clone()).unwrap().sequence, 1);
        let mut second = first.clone();
        second.operation_id = "two".into();
        assert_eq!(gate.write(second).unwrap().sequence, 2);
        assert_eq!(gate.local_status().unwrap().entries.len(), 1);
        drop(gate);
        let p = Node::open(&pp, Role::Primary, identity(), "fixture").unwrap();
        let s = Node::open(&sp, Role::Secondary, identity(), "fixture").unwrap();
        // A failed reconciliation must not relabel an old applied receipt as NotAccepted.
        s.connection(|c| {
            c.execute("UPDATE places SET name='diverged'", [])?;
            Ok(())
        })
        .unwrap();
        let mut gate = coordinator::Coordinator::new(p, s).unwrap();
        let failure = gate.write(first).unwrap_err();
        assert_eq!(failure.status_code, 503);
        assert_eq!(failure.outcome, coordinator::Outcome::Unknown);
    }

    #[test]
    fn primary_base_requires_matching_local_publication_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p");
        let (p, proposal) = populated(&path);
        p.connection(|c| {
            c.execute(
                "INSERT INTO replication_base VALUES(1,?1)",
                [serde_json::to_string(&proposal.checkpoint)?],
            )?;
            Ok(())
        })
        .unwrap();
        drop(p);
        assert!(Node::open(&path, Role::Primary, identity(), "fixture").is_err());
    }

    #[test]
    fn base_floor_must_not_hide_nonpositive_journal_keys() {
        for sequence in [0, -1] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("p");
            let (p, _) = populated(&path);
            p.connection(|c| {
                c.execute(
                    "INSERT INTO replication_log VALUES(?1,'invalid','{}')",
                    [sequence],
                )?;
                Ok(())
            })
            .unwrap();
            assert!(p.checkpoint().is_err());
            assert!(p.journal_head().is_err());
            drop(p);
            assert!(Node::open(&path, Role::Primary, identity(), "fixture").is_err());
        }
    }
}
