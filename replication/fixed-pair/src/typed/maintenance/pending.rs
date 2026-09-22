//! Restricted opener for a certified-maintenance operation which has already
//! closed ordinary node admission. It never creates, migrates, or repairs data.
use super::*;
use sha2::{Digest, Sha256};
use std::path::Path;

const MARKER: &str = "node_pending_certified_maintenance";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Marker {
    format: u32,
    identity: Identity<SchemaId>,
    role: Role,
    previous_runtime: u32,
    request_digest: [u8; 32],
    plan_digest: [u8; 32],
}

/// Local record of a signed maintenance abort. Its presence is the durable,
/// one-way proof that this node will never roll the transition forward.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AbortLocal {
    abort_id: [u8; 32],
    abort_token_digest: [u8; 32],
    aborted_revision: u64,
    decided: bool,
}

/// Format 1 rows serialise byte-identically: `abort` is skipped when absent, so
/// a node that never aborts writes exactly the bytes it wrote before.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Prepared {
    format: u32,
    phase: String,
    plan: compaction::PairPlan,
    request: crate::recovery::transition::Request,
    token: String,
    decision: Option<[u8; 32]>,
    completion: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    abort: Option<AbortLocal>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Active {
    format: u32,
    request: crate::recovery::decision::Request,
    token_digest: [u8; 32],
    grant_id: [u8; 32],
    checkpoint: Prefix,
    member: [u8; 32],
}

fn digest<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).into())
}

/// Is a certified maintenance transaction durably in progress here?
fn pending_present(c: &Connection) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' \
         AND name='node_pending_certified_maintenance')",
        [],
        |r| r.get(0),
    )?)
}

/// Read-only summary of a pending certified maintenance transaction: what the
/// authority was asked for, how far this node got, and the role the durable
/// marker records. The role is never taken from the caller.
///
/// This performs no authority verification: it proves only that the marker and
/// the progress record agree with each other and with the owner row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingSummary {
    pub role: Role,
    pub phase: String,
    pub request: crate::recovery::transition::Request,
}

pub(crate) fn peek_pending(
    path: impl AsRef<Path>,
    identity: &Identity<SchemaId>,
    passphrase: &str,
) -> Result<PendingSummary> {
    let path = path.as_ref();
    let path = path
        .parent()
        .ok_or("missing parent")?
        .canonicalize()?
        .join(path.file_name().ok_or("missing filename")?);
    ensure(
        path.is_file() && !path.is_symlink(),
        "pending database absent",
    )?;
    let _lock = crate::typed::open_node_lock(&path)?;
    let db = Vesta::open_read_only_with_passphrase(&path, passphrase)?;
    db.with_connection(|c| {
        Ok((|| -> Result<PendingSummary> {
            c.pragma_update(None, "query_only", true)?;
            ensure(
                pending_present(c)?,
                "node has no pending certified maintenance",
            )?;
            let marker: Marker = serde_json::from_str(&singleton_text(
                c,
                "node_pending_certified_maintenance",
                "record",
                64 * 1024,
            )?)?;
            let prepared: Prepared = serde_json::from_str(&singleton_text(
                c,
                "node_pending_certified_progress",
                "record",
                256 * 1024,
            )?)?;
            let owner: Vec<String> = c
                .prepare("SELECT value FROM node_identity")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            ensure(
                marker.format == 1
                    && marker.identity == *identity
                    && owner == [serde_json::to_string(&(identity, marker.role))?]
                    && marker.request_digest == digest(&prepared.request)?
                    && marker.plan_digest == digest(&prepared.plan)?,
                "pending marker mismatch",
            )?;
            Ok(PendingSummary {
                role: marker.role,
                phase: prepared.phase.clone(),
                request: prepared.request,
            })
        })())
    })?
}

/// Connection-level read of the pending progress, for callers that already
/// hold their own read-only connection and must not take the node lock.
/// Returns `None` when this node has no pending certified maintenance.
pub(super) fn progress_of(
    c: &Connection,
    identity: &Identity<SchemaId>,
) -> Result<
    Option<(
        Role,
        String,
        crate::recovery::transition::Request,
        Option<[u8; 32]>,
    )>,
> {
    if !pending_present(c)? {
        return Ok(None);
    }
    let marker: Marker = serde_json::from_str(&singleton_text(
        c,
        "node_pending_certified_maintenance",
        "record",
        64 * 1024,
    )?)?;
    let prepared: Prepared = serde_json::from_str(&singleton_text(
        c,
        "node_pending_certified_progress",
        "record",
        256 * 1024,
    )?)?;
    let owner: Vec<String> = c
        .prepare("SELECT value FROM main.node_identity")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        marker.format == 1
            && marker.identity == *identity
            && owner == [serde_json::to_string(&(identity, marker.role))?]
            && marker.request_digest == digest(&prepared.request)?
            && marker.plan_digest == digest(&prepared.plan)?
            && matches!(marker.previous_runtime, 3 | 4),
        "pending marker mismatch",
    )?;
    let runtime: u32 = c.query_row("SELECT format FROM main.node_runtime WHERE id=1", [], |r| {
        r.get(0)
    })?;
    ensure(runtime == 5, "pending runtime mismatch")?;
    Ok(Some((
        marker.role,
        prepared.phase.clone(),
        prepared.request,
        prepared.decision,
    )))
}

fn singleton_text(c: &Connection, table: &str, column: &str, limit: usize) -> Result<String> {
    let rows: Vec<(u32, String)> = c
        .prepare(&format!("SELECT id,{column} FROM {table} ORDER BY id"))?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        rows.len() == 1 && rows[0].0 == 1 && rows[0].1.len() <= limit,
        "pending singleton mismatch",
    )?;
    Ok(rows.into_iter().next().unwrap().1)
}

/// Every precondition `apply_decided` later asserts about pre-existing durable
/// state. `prepare_pair` is a one-way door, so a node that could never reach
/// APPLY must be refused before the marker is written, not after.
fn require_appliable(c: &Connection) -> Result<()> {
    require_unpinned(c)?;
    let table = |name: &str| -> Result<bool> {
        Ok(c.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [name],
            |r| r.get(0),
        )?)
    };
    let version = super::maintenance_version(c)?;
    if table("node_compaction_certificates")? {
        // A certified node continues its own lineage.
        ensure(
            version == 3,
            "certified maintenance requires certified maintenance format",
        )?;
    } else {
        // A fresh certified lineage is created by APPLY with plain CREATE
        // TABLE and a version 1 -> 3 transition, so neither may pre-exist.
        ensure(
            version == 1 && !table("node_compaction_root")? && !table("node_compaction_history")?,
            "certified maintenance requires a node without legacy compaction",
        )?;
    }
    Ok(())
}

pub(crate) fn prepare_pair<A: ReplicatedSchema>(
    p: &mut Node<A>,
    s: &mut Node<A>,
    plan: &compaction::PairPlan,
    request: &crate::recovery::transition::Request,
    token: &str,
    now: u64,
    trust: &crate::recovery::transition::TrustStore,
) -> Result<()> {
    let (p, s) = (&*p, &*s);
    plan.validate_certified()?;
    crate::recovery::transition::verify_issuance(token, &trust.as_trust(), request, now)?;
    ensure(
        p.role() == Role::Primary && s.role() == Role::Secondary && p.identity() == s.identity(),
        "pending pair mismatch",
    )?;
    let prepared = Prepared {
        format: 1,
        phase: "prepared".into(),
        plan: plan.clone(),
        request: request.clone(),
        token: token.into(),
        decision: None,
        completion: None,
        abort: None,
    };
    let expected_json = serde_json::to_string(&prepared)?;
    ensure(
        expected_json.len() <= 256 * 1024 && token.len() <= 64 * 1024,
        "pending record limit",
    )?;
    let scratch = Connection::open_in_memory()?;
    schema::initialize(&scratch, &p.adapter)?;
    let contract = schema_contract::describe(&scratch, &p.adapter)?;
    let initial = hash(&p.adapter.view(&scratch)?)?;
    let mut existing = [false; 2];
    for (i, n) in [p, s].into_iter().enumerate() {
        existing[i]=n.connection(|c|{
            super::loss::require_no_loss_recovery(c)?;
            let present:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='node_pending_certified_maintenance')",[],|r|r.get(0))?;
            if !present { return Ok(false); }
            validate_pending(c,&n.adapter,&contract,&initial,n.identity(),n.role(),request,trust,n.certified_authority.as_deref(),Some(&prepared))?;
            Ok(true)
        })?;
    }
    for (i, n) in [p, s].into_iter().enumerate() {
        if existing[i] {
            continue;
        }
        ensure(
            n.plan_compaction()? == *plan.local(n.role()),
            "stale pending participant",
        )?;
        n.connection(|c| {
            n.recovery_admission(c)?;
            require_appliable(c)?;
            let previous = if c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='node_compaction_certificates')",
                [],
                |r| r.get::<_, bool>(0),
            )? {
                let json: String = c.query_row(
                    "SELECT record FROM node_compaction_certificates ORDER BY sequence DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )?;
                ensure(json.len() <= 256 * 1024, "previous certificate limit")?;
                Some(serde_json::from_str::<certified::CertificateRecord>(&json)?)
            } else {
                None
            };
            certified::validate_record(
                &certified::CertificateRecord {
                    format: 1,
                    plan: plan.clone(),
                    request: request.clone(),
                    token: token.into(),
                },
                n.identity(),
                n.role(),
                previous.as_ref(),
            )?;
            Node::<A>::verify_publication_in(
                c,
                plan.local(n.role())
                    .publication
                    .as_ref()
                    .ok_or("pending publication missing")?,
                n.identity(),
                &n.contract,
            )
        })?;
    }
    // Only after every non-prepared participant passed read-only preflight.
    for (i, n) in [p, s].into_iter().enumerate() {
        if existing[i] {
            continue;
        }
        n.connection(|c|{
            let tx=c.unchecked_transaction()?;
            let previous_runtime:u32=tx.query_row("SELECT format FROM node_runtime WHERE id=1",[],|r|r.get(0))?;
            ensure(matches!(previous_runtime,3|4),"unsupported pending previous runtime")?;
            let marker=Marker{format:1,identity:n.identity().clone(),role:n.role(),previous_runtime,request_digest:digest(request)?,plan_digest:digest(plan)?};
            tx.execute_batch("CREATE TABLE node_pending_certified_maintenance(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL); CREATE TABLE node_pending_certified_progress(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL,digest TEXT NOT NULL);")?;
            ensure(tx.execute("DELETE FROM replication_readiness",[])?<=1,"pending readiness transition failed")?;
            ensure(tx.execute("UPDATE node_runtime SET format=5 WHERE id=1 AND format=?1",[previous_runtime])?==1,"pending runtime transition failed")?;
            ensure(tx.execute("INSERT INTO node_pending_certified_maintenance VALUES(1,?1)",[serde_json::to_string(&marker)?])?==1,"pending marker write failed")?;
            ensure(tx.execute("INSERT INTO node_pending_certified_progress VALUES(1,?1,?2)",params![&expected_json,hash(&prepared)?])?==1,"pending progress write failed")?;
            ensure(tx.query_row("SELECT count(*)=0 FROM replication_readiness",[],|r|r.get::<_,bool>(0))?,"pending readiness remained")?;
            tx.commit()?; Ok(())
        })?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingInspection {
    pub role: Role,
    pub identity: Identity<SchemaId>,
    pub checkpoint: Prefix,
    pub base: Option<Prefix>,
}

/// Deliberately does not contain a `Node`, implement `Deref`, or expose a
/// connection callback. Dropping it releases the ordinary node lock.
pub(crate) struct PendingMaintenanceHandle<A: ReplicatedSchema> {
    db: Vesta,
    adapter: A,
    contract: schema_contract::Contract,
    initial: String,
    identity: Identity<SchemaId>,
    role: Role,
    inspection: PendingInspection,
    prepared: Prepared,
    finalized: bool,
    certified_authority: Option<std::sync::Arc<dyn crate::typed::CertifiedAuthority>>,
    _lock: File,
}

impl<A: ReplicatedSchema> PendingMaintenanceHandle<A> {
    pub(crate) fn open_existing(
        path: impl AsRef<Path>,
        role: Role,
        identity: Identity<SchemaId>,
        passphrase: &str,
        adapter: A,
        expected: &crate::recovery::transition::Request,
        trust: &crate::recovery::transition::TrustStore,
    ) -> Result<Self> {
        Self::open_existing_with_authority(
            path, role, identity, passphrase, adapter, expected, trust, None,
        )
    }

    pub(crate) fn open_existing_with_authority(
        path: impl AsRef<Path>,
        role: Role,
        identity: Identity<SchemaId>,
        passphrase: &str,
        adapter: A,
        expected: &crate::recovery::transition::Request,
        trust: &crate::recovery::transition::TrustStore,
        certified_authority: Option<std::sync::Arc<dyn crate::typed::CertifiedAuthority>>,
    ) -> Result<Self> {
        ensure(
            identity.schema == adapter.identity()
                && identity.epoch > 0
                && !identity.cluster.is_empty()
                && !identity.tenant.is_empty(),
            "invalid pending identity",
        )?;
        let path = path.as_ref();
        let path = path
            .parent()
            .ok_or("missing parent")?
            .canonicalize()?
            .join(path.file_name().ok_or("missing filename")?);
        ensure(
            path.is_file() && !path.is_symlink(),
            "pending database absent",
        )?;
        let lock = crate::typed::open_node_lock(&path)?;
        let scratch = Connection::open_in_memory()?;
        schema::initialize(&scratch, &adapter)?;
        let contract = schema_contract::describe(&scratch, &adapter)?;
        let initial = hash(&adapter.view(&scratch)?)?;
        let readonly = Vesta::open_read_only_with_passphrase(&path, passphrase)?;
        readonly.with_connection(|c| {
            Ok((|| -> Result<()> {
                ensure(
                    pending_present(c)?,
                    "node has no pending certified maintenance",
                )
            })())
        })??;
        let (inspection, prepared) = readonly.with_connection(|c| {
            c.pragma_update(None, "query_only", true)?;
            Ok(validate_pending(
                c,
                &adapter,
                &contract,
                &initial,
                &identity,
                role,
                expected,
                trust,
                certified_authority.as_deref(),
                None,
            ))
        })??;
        drop(readonly);
        let db = Vesta::open_existing_read_write_with_passphrase(&path, passphrase)?;
        db.with_connection(|c| {
            validate_pending(
                c,
                &adapter,
                &contract,
                &initial,
                &identity,
                role,
                expected,
                trust,
                certified_authority.as_deref(),
                Some(&prepared),
            )
            .map(|_| ())
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
        })?;
        Ok(Self {
            db,
            adapter,
            contract,
            initial,
            identity,
            role,
            inspection,
            prepared,
            finalized: false,
            certified_authority,
            _lock: lock,
        })
    }

    pub(crate) fn inspect(&self) -> &PendingInspection {
        &self.inspection
    }

    /// Re-read and re-validate the durable progress row. Used as live
    /// participant evidence, so it never trusts the cached copy.
    fn live_progress(&self, trust: &crate::recovery::transition::TrustStore) -> Result<Prepared> {
        self.db.with_connection(|c| {
            Ok(validate_pending(
                c,
                &self.adapter,
                &self.contract,
                &self.initial,
                &self.identity,
                self.role,
                &self.prepared.request,
                trust,
                self.certified_authority.as_deref(),
                None,
            )
            .map(|(_, prepared)| prepared))
        })?
    }

    fn replace_progress(
        &mut self,
        trust: &crate::recovery::transition::TrustStore,
        next: Prepared,
        authorize: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.db.with_connection(|c| {
            let run = || -> Result<()> {
                let tx = rusqlite::Transaction::new_unchecked(
                    c,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                validate_pending(
                    &tx,
                    &self.adapter,
                    &self.contract,
                    &self.initial,
                    &self.identity,
                    self.role,
                    &self.prepared.request,
                    trust,
                    self.certified_authority.as_deref(),
                    Some(&self.prepared),
                )?;
                authorize()?;
                let old_json = serde_json::to_string(&self.prepared)?;
                let next_json = serde_json::to_string(&next)?;
                ensure(
                    tx.execute(
                        "UPDATE node_pending_certified_progress SET record=?1,digest=?2 WHERE id=1 AND record=?3 AND digest=?4",
                        params![next_json, hash(&next)?, old_json, hash(&self.prepared)?],
                    )? == 1,
                    "pending progress transition failed",
                )?;
                tx.commit()?;
                Ok(())
            };
            run().map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
        })?;
        self.prepared = next;
        Ok(())
    }
}

struct PreparedPolicy<'a, P> {
    external: &'a P,
    request: &'a crate::recovery::transition::Request,
    participants: [&'a crate::recovery::transition::Participant; 2],
}

struct AppliedPolicy<'a, P> {
    external: &'a P,
    participant: &'a crate::recovery::transition::Participant,
}

impl<P: crate::recovery::transition::Policy> crate::recovery::transition::Policy
    for AppliedPolicy<'_, P>
{
    fn continuity(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        request: &crate::recovery::transition::Request,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.external.continuity(scope, request)
    }

    fn prepared(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        request: &crate::recovery::transition::Request,
        member: &crate::recovery::transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.external.prepared(scope, request, member)
    }

    fn applied(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        decision: &crate::recovery::transition::CommittedTransition,
        member: &crate::recovery::transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        ensure(
            member == self.participant,
            "pending ACK participant mismatch",
        )?;
        self.external.applied(scope, decision, member)
    }
}

impl<P: crate::recovery::transition::Policy> crate::recovery::transition::Policy
    for PreparedPolicy<'_, P>
{
    fn continuity(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        request: &crate::recovery::transition::Request,
    ) -> terrapi_vesta_recovery::Result<()> {
        ensure(request == self.request, "pending decision request mismatch")?;
        self.external.continuity(scope, request)
    }

    fn prepared(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        request: &crate::recovery::transition::Request,
        member: &crate::recovery::transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        ensure(
            request == self.request && self.participants.contains(&member),
            "pending decision participant mismatch",
        )?;
        self.external.prepared(scope, request, member)
    }

    fn applied(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        decision: &crate::recovery::transition::CommittedTransition,
        member: &crate::recovery::transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.external.applied(scope, decision, member)
    }
}

/// Persist only the authority decision. Both restricted handles remain in the
/// PREPARED phase; this does not mutate either node or record an ACK.
pub(crate) fn decide_prepared<A: ReplicatedSchema>(
    primary: &PendingMaintenanceHandle<A>,
    secondary: &PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    now: u64,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<crate::recovery::transition::CommittedTransition> {
    ensure(
        primary.role == Role::Primary
            && secondary.role == Role::Secondary
            && primary.identity == secondary.identity
            && primary.prepared == secondary.prepared,
        "pending decision pair mismatch",
    )?;
    let prepared = &primary.prepared;
    ensure(
        prepared.phase == "prepared"
            && primary.inspection.role == Role::Primary
            && secondary.inspection.role == Role::Secondary
            && primary.inspection.checkpoint == prepared.plan.primary.checkpoint
            && secondary.inspection.checkpoint == prepared.plan.secondary.checkpoint,
        "unsupported pending decision state",
    )?;
    // This is deliberately fresh even though Journal::decide verifies again
    // inside its immediate transaction.
    crate::recovery::transition::verify_issuance(
        &prepared.token,
        &trust.as_trust(),
        &prepared.request,
        now,
    )?;
    let guarded = PreparedPolicy {
        external: policy,
        request: &prepared.request,
        participants: [
            &prepared.request.participants[0],
            &prepared.request.participants[1],
        ],
    };
    journal.decide(
        prepared.request.clone(),
        &prepared.token,
        now,
        &trust.as_trust(),
        &guarded,
    )
}

pub(crate) fn record_decided<A: ReplicatedSchema>(
    handle: &mut PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    let verified = crate::recovery::transition::verify_historical(
        &handle.prepared.token,
        &trust.as_trust(),
        &handle.prepared.request,
    )?;
    if handle.prepared.phase == "decided" {
        let decision = journal.fetch(&handle.prepared.request, &trust.as_trust(), policy)?;
        return ensure(
            handle.prepared.decision == Some(decision.token_digest()),
            "pending decided conflict",
        );
    }
    ensure(
        handle.prepared.phase == "prepared" && handle.prepared.decision.is_none(),
        "invalid pending decision transition",
    )?;
    let mut next = handle.prepared.clone();
    next.phase = "decided".into();
    next.decision = Some(verified.token_digest());
    let request = handle.prepared.request.clone();
    let expected_digest = verified.token_digest();
    handle.replace_progress(trust, next, || {
        let decision = journal.fetch(&request, &trust.as_trust(), policy)?;
        ensure(
            decision.token_digest() == expected_digest,
            "pending decision token mismatch",
        )
    })
}

pub(crate) fn apply_decided<A: ReplicatedSchema>(
    handle: &mut PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    if handle.prepared.phase == "applied" {
        journal.fetch(&handle.prepared.request, &trust.as_trust(), policy)?;
        return Ok(());
    }
    ensure(
        handle.prepared.phase == "decided" && handle.prepared.decision.is_some(),
        "invalid pending apply transition",
    )?;
    let mut next = handle.prepared.clone();
    next.phase = "applied".into();
    let old = handle.prepared.clone();
    handle.db.with_connection(|c| {
        let run = || -> Result<()> {
            let tx = rusqlite::Transaction::new_unchecked(
                c,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            validate_pending(
                &tx,
                &handle.adapter,
                &handle.contract,
                &handle.initial,
                &handle.identity,
                handle.role,
                &old.request,
                trust,
                handle.certified_authority.as_deref(),
                Some(&old),
            )?;
            let decision = journal.fetch(&old.request, &trust.as_trust(), policy)?;
            ensure(
                Some(decision.token_digest()) == old.decision,
                "pending apply decision mismatch",
            )?;
            require_unpinned(&tx)?;
            let local = old.plan.local(handle.role);
            ensure(
                checkpoint::current_for(
                    &tx,
                    &handle.adapter,
                    &handle.identity,
                    &handle.initial,
                    true,
                )?
                .0 == local.checkpoint
                    && journal::head_for(&tx, &handle.identity)? == local.head,
                "pending apply cut changed",
            )?;
            let prior: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='node_compaction_certificates')",
                [],
                |r| r.get(0),
            )?;
            if !prior {
                tx.execute_batch(
                    "CREATE TABLE node_compaction_root(id INTEGER PRIMARY KEY CHECK(id=1),base TEXT NOT NULL);
                     CREATE TABLE node_compaction_history(sequence INTEGER PRIMARY KEY,plan TEXT NOT NULL,digest TEXT NOT NULL);
                     CREATE TABLE node_compaction_certificates(sequence INTEGER PRIMARY KEY,record TEXT NOT NULL);",
                )?;
                ensure(
                    tx.execute(
                        "INSERT INTO node_compaction_root VALUES(1,?1)",
                        [serde_json::to_string(&local.head.base)?],
                    )? == 1,
                    "pending compaction root write failed",
                )?;
            }
            ensure(
                tx.execute(
                    "INSERT INTO node_compaction_history VALUES(?1,?2,?3)",
                    params![local.checkpoint.sequence, serde_json::to_string(&old.plan)?, hash(&old.plan)?],
                )? == 1,
                "pending compaction history write failed",
            )?;
            let certificate = certified::CertificateRecord {
                format: 1,
                plan: old.plan.clone(),
                request: old.request.clone(),
                token: old.token.clone(),
            };
            ensure(
                tx.execute(
                    "INSERT INTO node_compaction_certificates VALUES(?1,?2)",
                    params![local.checkpoint.sequence, serde_json::to_string(&certificate)?],
                )? == 1,
                "pending certificate write failed",
            )?;
            ensure(
                tx.execute(
                    "INSERT INTO replication_base VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint",
                    [serde_json::to_string(&local.checkpoint)?],
                )? == 1,
                "pending base write failed",
            )?;
            tx.execute(
                "DELETE FROM replication_log WHERE sequence<=?1",
                [local.checkpoint.sequence],
            )?;
            if prior {
                ensure(
                    tx.query_row(
                        "SELECT version=3 FROM node_maintenance_format WHERE id=1",
                        [],
                        |r| r.get::<_, bool>(0),
                    )?,
                    "pending maintenance format mismatch",
                )?;
            } else {
                ensure(
                    tx.execute(
                        "UPDATE node_maintenance_format SET version=3 WHERE id=1 AND version=1",
                        [],
                    )? == 1,
                    "pending maintenance format transition failed",
                )?;
            }
            let old_json = serde_json::to_string(&old)?;
            let next_json = serde_json::to_string(&next)?;
            ensure(
                tx.execute(
                    "UPDATE node_pending_certified_progress SET record=?1,digest=?2 WHERE id=1 AND record=?3 AND digest=?4",
                    params![next_json, hash(&next)?, old_json, hash(&old)?],
                )? == 1,
                "pending apply progress transition failed",
            )?;
            validate_pending(
                &tx,
                &handle.adapter,
                &handle.contract,
                &handle.initial,
                &handle.identity,
                handle.role,
                &old.request,
                trust,
                handle.certified_authority.as_deref(),
                Some(&next),
            )?;
            tx.commit()?;
            Ok(())
        };
        run().map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    })?;
    handle.prepared = next;
    Ok(())
}

pub(crate) fn acknowledge_applied<A: ReplicatedSchema>(
    handle: &PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    ensure(
        handle.prepared.phase == "applied",
        "pending node is not applied",
    )?;
    let participant =
        &handle.prepared.request.participants[if handle.role == Role::Primary { 0 } else { 1 }];
    handle.db.with_connection(|c| {
        let run = || -> Result<()> {
            let tx =
                rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            validate_pending(
                &tx,
                &handle.adapter,
                &handle.contract,
                &handle.initial,
                &handle.identity,
                handle.role,
                &handle.prepared.request,
                trust,
                handle.certified_authority.as_deref(),
                Some(&handle.prepared),
            )?;
            let decision = journal.fetch(&handle.prepared.request, &trust.as_trust(), policy)?;
            ensure(
                Some(decision.token_digest()) == handle.prepared.decision,
                "pending ACK decision mismatch",
            )?;
            journal.acknowledge(
                &decision,
                participant,
                &trust.as_trust(),
                &AppliedPolicy {
                    external: policy,
                    participant,
                },
            )?;
            tx.commit()?;
            Ok(())
        };
        run().map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    })?;
    Ok(())
}

fn validate_retained<A: ReplicatedSchema>(
    handle: &PendingMaintenanceHandle<A>,
    trust: &crate::recovery::transition::TrustStore,
) -> Result<()> {
    handle.db.with_connection(|c| {
        validate_pending(
            c,
            &handle.adapter,
            &handle.contract,
            &handle.initial,
            &handle.identity,
            handle.role,
            &handle.prepared.request,
            trust,
            handle.certified_authority.as_deref(),
            Some(&handle.prepared),
        )
        .map(|_| ())
        .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    })?;
    Ok(())
}

/// The completion id is derived, never chosen: it is a function of the exact
/// request, the exact issued token and the acknowledgements that authorised it.
/// Two different transitions can never share one, and a retry always recomputes
/// the same value.
pub(crate) fn completion_id(
    request: &crate::recovery::transition::Request,
    token_digest: [u8; 32],
    acknowledgements: [bool; 2],
) -> Result<[u8; 32]> {
    digest(&(
        "terrapi-certified-completion",
        request.id,
        token_digest,
        acknowledgements,
    ))
}

pub(crate) fn complete_authority<A: ReplicatedSchema>(
    primary: &PendingMaintenanceHandle<A>,
    secondary: &PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    ensure(
        primary.role == Role::Primary
            && secondary.role == Role::Secondary
            && primary.identity == secondary.identity
            && primary.prepared == secondary.prepared
            && primary.prepared.phase == "applied",
        "pending completion pair mismatch",
    )?;
    validate_retained(primary, trust)?;
    validate_retained(secondary, trust)?;
    let decision = journal.fetch(&primary.prepared.request, &trust.as_trust(), policy)?;
    ensure(
        decision.acknowledgements() == [true; 2],
        "pending completion acknowledgements incomplete",
    )?;
    let completion = completion_id(
        decision.request(),
        decision.token_digest(),
        decision.acknowledgements(),
    )?;
    journal.complete(&decision, completion, &trust.as_trust(), policy)?;
    Ok(())
}

pub(crate) fn record_complete<A: ReplicatedSchema>(
    handle: &mut PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    let completed = journal.fetch_completed(&handle.prepared.request, &trust.as_trust(), policy)?;
    if handle.prepared.phase == "complete" {
        return ensure(
            handle.prepared.completion == Some(completed.completion()),
            "pending node completion conflict",
        );
    }
    ensure(
        handle.prepared.phase == "applied" && handle.prepared.completion.is_none(),
        "invalid pending completion transition",
    )?;
    let mut next = handle.prepared.clone();
    next.phase = "complete".into();
    next.completion = Some(completed.completion());
    let request = handle.prepared.request.clone();
    let completion = completed.completion();
    handle.replace_progress(trust, next, || {
        let current = journal.fetch_completed(&request, &trust.as_trust(), policy)?;
        ensure(
            current.completion() == completion,
            "pending completion changed",
        )
    })
}

/// Finalize exactly one node. Restartable: if the process dies between the two
/// nodes, the survivor of that crash finalizes on its own with this call.
pub(crate) fn finalize_node<A: ReplicatedSchema>(
    handle: &mut PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    if handle.finalized {
        journal.fetch_completed(&handle.prepared.request, &trust.as_trust(), policy)?;
        return Ok(());
    }
    ensure(
        handle.prepared.phase == "complete" && handle.prepared.completion.is_some(),
        "pending node is not complete",
    )?;
    handle.db.with_connection(|c| {
        let run = || -> Result<()> {
            let tx = rusqlite::Transaction::new_unchecked(
                c,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            validate_pending(
                &tx,
                &handle.adapter,
                &handle.contract,
                &handle.initial,
                &handle.identity,
                handle.role,
                &handle.prepared.request,
                trust,
                handle.certified_authority.as_deref(),
                Some(&handle.prepared),
            )?;
            let completed = journal.fetch_completed(
                &handle.prepared.request,
                &trust.as_trust(),
                policy,
            )?;
            ensure(
                Some(completed.completion()) == handle.prepared.completion
                    && completed.token_digest() == handle.prepared.decision.unwrap(),
                "pending finalization proof mismatch",
            )?;
            let marker_json = singleton_text(
                &tx,
                "node_pending_certified_maintenance",
                "record",
                64 * 1024,
            )?;
            let marker: Marker = serde_json::from_str(&marker_json)?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS node_compaction_completion(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL);",
            )?;
            ensure(
                tx.execute(
                    "INSERT INTO node_compaction_completion VALUES(1,?1)
                     ON CONFLICT(id) DO UPDATE SET record=excluded.record",
                    [serde_json::to_string(&(
                        1u32,
                        completed.request().id,
                        completed.token_digest(),
                        completed.completion(),
                    ))?],
                )? == 1,
                "pending completion archive failed",
            )?;
            tx.execute_batch(
                "DROP TABLE node_pending_certified_progress;
                 DROP TABLE node_pending_certified_maintenance;",
            )?;
            ensure(
                tx.execute(
                    "UPDATE node_runtime SET format=?1 WHERE id=1 AND format=5",
                    [marker.previous_runtime],
                )? == 1,
                "pending runtime finalization failed",
            )?;
            ensure(
                tx.execute(
                    "INSERT INTO replication_readiness VALUES(1,?1)",
                    [serde_json::to_string(&handle.prepared.plan.local(handle.role).checkpoint)?],
                )? == 1,
                "pending readiness finalization failed",
            )?;
            tx.commit()?;
            Ok(())
        };
        run().map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    })?;
    handle.finalized = true;
    Ok(())
}

pub(crate) fn finalize_pair<A: ReplicatedSchema>(
    primary: &mut PendingMaintenanceHandle<A>,
    secondary: &mut PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    ensure(
        primary.prepared == secondary.prepared
            && primary.prepared.phase == "complete"
            && secondary.prepared.phase == "complete",
        "pending finalization pair mismatch",
    )?;
    finalize_node(secondary, journal, trust, policy)?;
    finalize_node(primary, journal, trust, policy)
}

// ---------------------------------------------------------------------------
// C1: maintenance abort. `prepare_pair` is a one-way door only as far as the
// ordinary lifecycle is concerned; a signed abort is the way back out.
// ---------------------------------------------------------------------------

/// Durably mark this node as aborting. One-way: from here no lifecycle call can
/// ever reach apply, acknowledge or complete, which is exactly the evidence the
/// authority needs before it records the abort (race R2).
pub(crate) fn begin_abort<A: ReplicatedSchema>(
    handle: &mut PendingMaintenanceHandle<A>,
    abort: &crate::recovery::transition::MaintenanceAbort,
    token: &str,
    now: u64,
    trust: &crate::recovery::transition::TrustStore,
) -> Result<()> {
    let request = handle.prepared.request.clone();
    // The token is verified freshly, then again against the durable record, the
    // same double-check the decision path uses.
    let certificate =
        crate::recovery::transition::verify_abort_issuance(token, &trust.as_trust(), abort, now)?;
    ensure(
        abort.aborted_request == digest(&request)?
            && abort.aborted_request_id == request.id
            && abort.aborted_revision == request.revision
            && abort.authority_id == request.authority_id
            && abort.install == request.install
            && abort.region == request.region
            && abort.scope == request.scope
            && abort.schema == request.schema
            && abort.membership == request.membership
            && abort.source_anchor == request.source_anchor,
        "pending abort binding mismatch",
    )?;
    let local = AbortLocal {
        abort_id: abort.id,
        abort_token_digest: digest_of_token(token),
        aborted_revision: abort.aborted_revision,
        decided: abort.decided,
    };
    let _ = certificate;
    if handle.prepared.phase == "aborting" {
        // Exact retry only; a different abort is a conflict, never a repair.
        return ensure(
            handle.prepared.abort.as_ref() == Some(&local),
            "pending abort conflict",
        );
    }
    ensure(
        matches!(handle.prepared.phase.as_str(), "prepared" | "decided")
            && abort.decided == (handle.prepared.phase == "decided")
            && handle.prepared.completion.is_none(),
        "invalid pending abort transition",
    )?;
    let mut next = handle.prepared.clone();
    next.format = 2;
    next.phase = "aborting".into();
    next.abort = Some(local);
    handle.replace_progress(trust, next, || Ok(()))
}

fn digest_of_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Live participant evidence for [`crate::recovery::transition::Policy::abort_applicable`]:
/// both nodes must already be durably aborting on exactly this abort, with the
/// pending runtime still in place. The external policy's own decision runs
/// first, so the authority's live-head check still gates.
struct AbortingPolicy<'a, A: ReplicatedSchema, P> {
    external: &'a P,
    primary: &'a PendingMaintenanceHandle<A>,
    secondary: &'a PendingMaintenanceHandle<A>,
    trust: &'a crate::recovery::transition::TrustStore,
}

impl<A: ReplicatedSchema, P: crate::recovery::transition::Policy>
    crate::recovery::transition::Policy for AbortingPolicy<'_, A, P>
{
    fn continuity(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        request: &crate::recovery::transition::Request,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.external.continuity(scope, request)
    }
    fn prepared(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        request: &crate::recovery::transition::Request,
        member: &crate::recovery::transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.external.prepared(scope, request, member)
    }
    fn applied(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        decision: &crate::recovery::transition::CommittedTransition,
        member: &crate::recovery::transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.external.applied(scope, decision, member)
    }
    fn historical_completion(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        historical: &crate::recovery::transition::Request,
        head: &crate::recovery::transition::Request,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.external.historical_completion(scope, historical, head)
    }
    fn abort_applicable(
        &self,
        scope: &crate::recovery::transition::JournalScope,
        abort: &crate::recovery::transition::MaintenanceAbort,
    ) -> terrapi_vesta_recovery::Result<()> {
        self.external.abort_applicable(scope, abort)?;
        for handle in [self.primary, self.secondary] {
            let progress = handle.live_progress(self.trust)?;
            let local = progress
                .abort
                .as_ref()
                .ok_or("pending node is not aborting")?;
            ensure(
                progress.phase == "aborting"
                    && progress.format == 2
                    && digest(&progress.request)? == abort.aborted_request
                    && progress.request.id == abort.aborted_request_id
                    && progress.request.revision == abort.aborted_revision
                    && local.abort_id == abort.id
                    && local.decided == abort.decided
                    && local.aborted_revision == abort.aborted_revision,
                "pending node is not aborting",
            )?;
        }
        Ok(())
    }
}

/// Record the abort at the authority, but only once both nodes are durably
/// aborting. Exact retry converges on the journal's own retry branch.
pub(crate) fn abort_authority<A: ReplicatedSchema>(
    primary: &PendingMaintenanceHandle<A>,
    secondary: &PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    abort: &crate::recovery::transition::MaintenanceAbort,
    token: &str,
    now: u64,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    ensure(
        primary.role == Role::Primary
            && secondary.role == Role::Secondary
            && primary.identity == secondary.identity
            && primary.prepared.request == secondary.prepared.request,
        "pending abort pair mismatch",
    )?;
    let evidence = AbortingPolicy {
        external: policy,
        primary,
        secondary,
        trust,
    };
    journal.abort(abort.clone(), token, now, &trust.as_trust(), &evidence)?;
    Ok(())
}

/// Roll this node back to the ordinary state it had before PREPARE. Restartable
/// and per node, like `finalize_node`.
pub(crate) fn finish_abort<A: ReplicatedSchema>(
    handle: &mut PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    if handle.finalized {
        journal.fetch_abort(&handle.prepared.request, &trust.as_trust(), policy)?;
        return Ok(());
    }
    let local = handle
        .prepared
        .abort
        .clone()
        .ok_or("pending node is not aborting")?;
    ensure(
        handle.prepared.phase == "aborting",
        "pending node is not aborting",
    )?;
    handle.db.with_connection(|c| {
        let run = || -> Result<()> {
            let tx =
                rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            validate_pending(
                &tx,
                &handle.adapter,
                &handle.contract,
                &handle.initial,
                &handle.identity,
                handle.role,
                &handle.prepared.request,
                trust,
                handle.certified_authority.as_deref(),
                Some(&handle.prepared),
            )?;
            let committed =
                journal.fetch_abort(&handle.prepared.request, &trust.as_trust(), policy)?;
            ensure(
                committed.abort().id == local.abort_id
                    && committed.token_digest() == local.abort_token_digest
                    && committed.aborted_revision() == local.aborted_revision
                    && committed.abort().decided == local.decided
                    && committed.aborted_request() == digest(&handle.prepared.request)?,
                "pending abort proof mismatch",
            )?;
            let marker_json = singleton_text(
                &tx,
                "node_pending_certified_maintenance",
                "record",
                64 * 1024,
            )?;
            let marker: Marker = serde_json::from_str(&marker_json)?;
            // Exactly the PREPARE transaction undone: the pending tables and
            // the runtime marker, nothing else. Readiness is deliberately not
            // restored; the secondary re-confirms its checkpoint.
            tx.execute_batch(
                "DROP TABLE main.node_pending_certified_progress;
                 DROP TABLE main.node_pending_certified_maintenance;",
            )?;
            ensure(
                tx.execute(
                    "UPDATE node_runtime SET format=?1 WHERE id=1 AND format=5",
                    [marker.previous_runtime],
                )? == 1,
                "pending abort runtime restoration failed",
            )?;
            let runtime: u32 =
                tx.query_row("SELECT format FROM node_runtime WHERE id=1", [], |r| {
                    r.get(0)
                })?;
            ensure(
                matches!(runtime, 3 | 4)
                    && runtime == marker.previous_runtime
                    && !pending_present(&tx)?
                    && !tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' \
                         AND name='node_pending_certified_progress')",
                        [],
                        |r| r.get::<_, bool>(0),
                    )?,
                "pending abort post-state mismatch",
            )?;
            // The restored node must pass the ordinary owner-level validation
            // again, inside the same transaction that rolled it back.
            verify_restored(&tx, handle, trust)?;
            tx.commit()?;
            Ok(())
        };
        run().map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    })?;
    handle.finalized = true;
    Ok(())
}

/// The owner-level checks an ordinary `Node::open` performs, re-run on the
/// rolled-back state before the abort transaction commits.
fn verify_restored<A: ReplicatedSchema>(
    c: &Connection,
    handle: &PendingMaintenanceHandle<A>,
    trust: &crate::recovery::transition::TrustStore,
) -> Result<()> {
    let owner: Vec<String> = c
        .prepare("SELECT value FROM node_identity")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        owner == [serde_json::to_string(&(&handle.identity, handle.role))?],
        "pending abort owner mismatch",
    )?;
    let runtime: Vec<(u32, String)> = c
        .prepare("SELECT format,initial_digest FROM node_runtime")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        runtime.len() == 1 && runtime[0].1 == handle.initial,
        "pending abort runtime mismatch",
    )?;
    let derived = history_format(c, runtime[0].0)?;
    recovery::verify_history(c, derived)?;
    super::verify_certified(c, Some(trust))?;
    capacity::verify_schema(c)?;
    capacity::verify_accounting(c)?;
    schema_contract::verify(c, &handle.adapter, &handle.contract)?;
    sql_snapshot::verify_binding(c, &handle.adapter, &snapshot::scope(&handle.identity))
}

// ---------------------------------------------------------------------------
// S11: an in-flight certified maintenance terminated by a participant loss.
//
// A maintenance abort needs proof that *both* nodes are durably rolling back
// (R2). A lost member can never give it, so when a participant is lost mid
// maintenance the signed loss decision itself has to end the transition. Which
// way it ends is not a caller's choice and not a flag: it follows from the
// survivor's own durable phase.
//
//   phase `prepared`/`decided` — nothing was applied, so the transition rolls
//   **back**; data, base, log, receipts and lineage are untouched.
//   phase `applied`            — history is already pruned, so rolling back is
//   impossible and the transition is finished **forward**: the decided
//   certificate stays, and a format-2 completion archive records that it was
//   never completed and that a signed loss is its provenance.
//
// Both write the same durable trace first. Nothing else authorises the shape
// the node is left in, and `verify_certified` refuses a format-2 archive that
// this trace does not account for.
// ---------------------------------------------------------------------------

const TERMINATED: &str = "node_maintenance_terminated";
const TERMINATED_DDL: &str = "CREATE TABLE IF NOT EXISTS main.node_maintenance_terminated(\
     id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)";
/// Branch A: nothing was applied and the transition was rolled back.
/// The trace carries a whole `Request`, a whole `LossRequest` and the issued
/// loss token, so the cap is the old 256 KiB plus room for a maximal token.
const TERMINATED_LIMIT: usize = 384 * 1024;
/// Mirror of the recovery crate's private `MAX_TOKEN`.
const MAX_TOKEN: usize = 64 * 1024;
const ROLLED_BACK: &str = "rolled_back";
/// Branch B: the decided transition was applied and is finished forward.
const FINISHED_FORWARD: &str = "finished_forward";

/// Durable local proof that a signed participant loss terminated an in-flight
/// certified maintenance, and of exactly which way it was terminated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Terminated {
    format: u32,
    kind: String,
    /// The abandoned request in full, so every binding below is checkable on
    /// this file alone, with no journal and no authority.
    request: crate::recovery::transition::Request,
    request_digest: [u8; 32],
    /// The loss decision that terminated it, its certificate, and the exact
    /// token the authority issued for it. L3: the trace is an unsigned local
    /// row, so the token is what actually authenticates it — every reader
    /// re-verifies the signature before the trace is allowed to mean anything.
    loss: crate::recovery::transition::LossRequest,
    loss_certificate: [u8; 32],
    loss_token_digest: [u8; 32],
    loss_token: String,
    /// Branch B only: the certificate APPLY durably stored for `request`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificate: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_digest: Option<[u8; 32]>,
}

impl Terminated {
    /// Internal consistency, independent of anything outside the record.
    fn validate(&self) -> Result<()> {
        ensure(
            self.format == 2
                && self.request_digest == digest(&self.request)?
                && self.loss_certificate != [0; 32]
                && self.loss_token_digest != [0; 32]
                && self.loss.abandoned_request == Some(self.request_digest),
            "maintenance termination trace mismatch",
        )?;
        // The loss must fence one of the two participants of exactly this
        // request and leave the other standing. Role is never read from here.
        let fenced = self
            .request
            .participants
            .iter()
            .position(|p| {
                p.member == self.loss.lost_member && p.generation == self.loss.lost_generation
            })
            .ok_or("maintenance termination participant mismatch")?;
        let survivor = &self.request.participants[1 - fenced];
        ensure(
            survivor.member == self.loss.survivor.member
                && survivor.generation == self.loss.survivor.generation,
            "maintenance termination participant mismatch",
        )?;
        match self.kind.as_str() {
            ROLLED_BACK => ensure(
                self.certificate.is_none()
                    && self.token_digest.is_none()
                    && self.loss.kind() == crate::recovery::transition::SourceKind::Completed,
                "maintenance rollback trace mismatch",
            ),
            FINISHED_FORWARD => ensure(
                self.loss.kind() == crate::recovery::transition::SourceKind::Decided
                    && self.certificate == Some(self.loss.source_certificate)
                    && self.token_digest == Some(self.loss.source_token_digest)
                    && self.loss.source_cut == self.request.participants[0].target,
                "maintenance finish-forward trace mismatch",
            ),
            _ => Err("maintenance termination trace mismatch".into()),
        }
    }

    pub(super) fn is_finished_forward(&self) -> bool {
        self.kind == FINISHED_FORWARD
    }

    /// The digest of the request this node abandoned.
    pub(super) fn abandoned(&self) -> [u8; 32] {
        self.request_digest
    }

    /// The loss decision this node was terminated by.
    pub(super) fn loss(&self) -> &crate::recovery::transition::LossRequest {
        &self.loss
    }

    /// Does this trace account for exactly the format-2 completion archive
    /// `(2, id, token_digest, loss_certificate)`?
    /// Re-verify the loss token under `trust` and bind it to the record.
    /// Returns `false` for a trace that is well-formed but not signed by the
    /// authority this node trusts.
    pub(super) fn authentic(&self, trust: &crate::recovery::transition::TrustStore) -> bool {
        self.loss_token.len() <= MAX_TOKEN
            && crate::recovery::transition::verify_loss_historical(
                &self.loss_token,
                &trust.as_trust(),
                &self.loss,
            )
            .is_ok_and(|certificate| {
                certificate == self.loss_certificate
                    && <[u8; 32]>::from(Sha256::digest(self.loss_token.as_bytes()))
                        == self.loss_token_digest
            })
    }

    pub(super) fn accounts_for(&self, id: [u8; 32], token: [u8; 32], loss: [u8; 32]) -> bool {
        self.kind == FINISHED_FORWARD
            && self.request.id == id
            && self.token_digest == Some(token)
            && self.certificate.is_some()
            && self.loss_certificate == loss
    }
}

/// The singleton termination trace, bounded, structurally validated and
/// signature-anchored before use. A row that does not verify under `trust` is
/// treated as absent: it can then never authenticate a format-2 archive or
/// found a loss, and every consumer of an absent trace fails closed.
pub(super) fn terminated(
    c: &Connection,
    trust: &crate::recovery::transition::TrustStore,
) -> Result<Option<Terminated>> {
    let present: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name=?1)",
        [TERMINATED],
        |r| r.get(0),
    )?;
    if !present {
        return Ok(None);
    }
    // A view or trigger under this name is never acceptable evidence.
    let shadows: u64 = c.query_row(
        "SELECT count(*) FROM main.sqlite_schema WHERE type<>'table' AND name=?1",
        [TERMINATED],
        |r| r.get(0),
    )?;
    ensure(shadows == 0, "maintenance termination trace shadowed")?;
    let json = singleton_text(c, TERMINATED, "record", TERMINATED_LIMIT)?;
    let record: Terminated = serde_json::from_str(&json)?;
    record.validate()?;
    if !record.authentic(trust) {
        return Ok(None);
    }
    Ok(Some(record))
}

/// Terminate an in-flight certified maintenance under a signed participant
/// loss. One `IMMEDIATE` transaction; the branch is decided by this node's own
/// durable phase and the loss must agree with it.
pub(crate) fn terminate_by_loss<A: ReplicatedSchema, P: crate::recovery::transition::LossPolicy>(
    handle: &mut PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &P,
) -> Result<()> {
    if handle.finalized {
        // Exact resume: the pending state is already gone and the trace is
        // durable. The live loss is re-read so a revoked authority still
        // refuses, and the trace must still be the one this loss wrote.
        let committed = journal.fetch_loss(&trust.as_trust(), policy)?;
        let durable = handle
            .db
            .with_connection(|c| Ok(terminated(c, trust)))??
            .ok_or("maintenance termination trace missing")?;
        return ensure(
            durable.loss() == committed.request()
                && durable.loss_certificate == committed.certificate_id()
                && durable.loss_token_digest == committed.token_digest(),
            "maintenance termination conflict",
        );
    }
    let request = handle.prepared.request.clone();
    let phase = handle.prepared.phase.clone();
    let local = if handle.role == Role::Primary { 0 } else { 1 };
    handle.db.with_connection(|c| {
        let run = || -> Result<()> {
            let tx =
                rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            validate_pending(
                &tx,
                &handle.adapter,
                &handle.contract,
                &handle.initial,
                &handle.identity,
                handle.role,
                &request,
                trust,
                handle.certified_authority.as_deref(),
                Some(&handle.prepared),
            )?;
            let committed = journal.fetch_loss(&trust.as_trust(), policy)?;
            let loss = committed.request();
            ensure(
                loss.abandoned_request == Some(digest(&request)?),
                "loss does not abandon this maintenance",
            )?;
            ensure(
                loss.survivor.member == request.participants[local].member
                    && loss.survivor.generation == request.participants[local].generation
                    && loss.lost_member == request.participants[1 - local].member
                    && loss.lost_generation == request.participants[1 - local].generation,
                "loss participants are not this maintenance pair",
            )?;
            // L5: certified maintenance is closed on a loss-recovered pair, so
            // a loss founded on a successor can never terminate one. Say that
            // instead of offering a branch that does not apply.
            ensure(
                loss.kind() != crate::recovery::transition::SourceKind::LossSuccessor,
                "certified maintenance cannot be pending on a loss-recovered pair",
            )?;
            // The branch follows the durable phase. A loss that names the other
            // branch is refused with the step the operator actually owes.
            let (kind, certificate, token_digest) = match (phase.as_str(), loss.kind()) {
                ("prepared" | "decided", crate::recovery::transition::SourceKind::Completed) => {
                    (ROLLED_BACK, None, None)
                }
                ("prepared" | "decided", _) => {
                    return Err("loss survivor must roll back abandoned maintenance instead".into())
                }
                ("applied", crate::recovery::transition::SourceKind::Decided) => {
                    // The certificate APPLY committed for this very request is
                    // the loss's signed provenance; it is re-verified here.
                    let json: String = tx.query_row(
                        "SELECT record FROM main.node_compaction_certificates \
                         ORDER BY sequence DESC LIMIT 1",
                        [],
                        |r| r.get(0),
                    )?;
                    ensure(json.len() <= 256 * 1024, "certificate record limit")?;
                    let stored: certified::CertificateRecord = serde_json::from_str(&json)?;
                    let verified = crate::recovery::transition::verify_historical(
                        &stored.token,
                        &trust.as_trust(),
                        &stored.request,
                    )?;
                    ensure(
                        stored.request == request
                            && verified.certificate_id() == loss.source_certificate
                            && verified.token_digest() == loss.source_token_digest
                            && loss.source_cut == request.participants[0].target,
                        "loss finish-forward certificate mismatch",
                    )?;
                    (
                        FINISHED_FORWARD,
                        Some(verified.certificate_id()),
                        Some(verified.token_digest()),
                    )
                }
                ("applied", _) => {
                    return Err(
                        "loss survivor must finish forward abandoned maintenance instead".into(),
                    )
                }
                _ => return Err("invalid pending termination transition".into()),
            };
            ensure(
                !committed.token().is_empty() && committed.token().len() <= MAX_TOKEN,
                "loss token limit",
            )?;
            let trace = Terminated {
                format: 2,
                kind: kind.into(),
                request_digest: digest(&request)?,
                request: request.clone(),
                loss: loss.clone(),
                loss_certificate: committed.certificate_id(),
                loss_token_digest: committed.token_digest(),
                loss_token: committed.token().to_owned(),
                certificate,
                token_digest,
            };
            trace.validate()?;
            ensure(
                trace.authentic(trust),
                "maintenance termination trace unsigned",
            )?;
            let json = serde_json::to_string(&trace)?;
            ensure(
                json.len() <= TERMINATED_LIMIT,
                "maintenance termination trace too large",
            )?;
            let marker_json = singleton_text(
                &tx,
                "node_pending_certified_maintenance",
                "record",
                64 * 1024,
            )?;
            let marker: Marker = serde_json::from_str(&marker_json)?;
            // The trace is written before anything depends on it: the format-2
            // archive below is only acceptable because this row exists.
            tx.execute_batch(TERMINATED_DDL)?;
            ensure(
                tx.execute(
                    "INSERT INTO main.node_maintenance_terminated VALUES(1,?1)",
                    [&json],
                )? == 1,
                "maintenance termination trace write failed",
            )?;
            if kind == FINISHED_FORWARD {
                // Not a completion: a statement that this certificate was never
                // completed and that a signed loss authenticates it instead. No
                // acknowledgement and no completion id is ever fabricated.
                tx.execute_batch(
                    "CREATE TABLE IF NOT EXISTS main.node_compaction_completion(\
                     id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)",
                )?;
                // The archive is the archive *of the current certificate*, and
                // that is now the decided one this loss authenticates. The
                // previous completion is superseded exactly as a completion
                // would supersede it.
                ensure(
                    tx.execute(
                        "INSERT INTO main.node_compaction_completion VALUES(1,?1)
                         ON CONFLICT(id) DO UPDATE SET record=excluded.record",
                        [serde_json::to_string(&(
                            2u32,
                            request.id,
                            token_digest.ok_or("finish-forward token digest")?,
                            committed.certificate_id(),
                        ))?],
                    )? == 1,
                    "loss finish-forward archive failed",
                )?;
            }
            // Exactly the PREPARE transaction undone. Readiness is deliberately
            // not restored; the peer re-confirms its checkpoint.
            tx.execute_batch(
                "DROP TABLE main.node_pending_certified_progress;
                 DROP TABLE main.node_pending_certified_maintenance;",
            )?;
            ensure(
                tx.execute(
                    "UPDATE node_runtime SET format=?1 WHERE id=1 AND format=5",
                    [marker.previous_runtime],
                )? == 1,
                "pending termination runtime restoration failed",
            )?;
            let runtime: u32 =
                tx.query_row("SELECT format FROM node_runtime WHERE id=1", [], |r| {
                    r.get(0)
                })?;
            ensure(
                matches!(runtime, 3 | 4)
                    && runtime == marker.previous_runtime
                    && !pending_present(&tx)?
                    && terminated(&tx, trust)?.as_ref() == Some(&trace),
                "pending termination post-state mismatch",
            )?;
            // The restored node must pass the ordinary owner-level validation
            // inside the same transaction that terminated the maintenance.
            verify_restored(&tx, handle, trust)?;
            tx.commit()?;
            Ok(())
        };
        run().map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    })?;
    handle.finalized = true;
    Ok(())
}

/// Secondary first, mirroring `finalize_pair`.
pub(crate) fn abort_pair<A: ReplicatedSchema>(
    primary: &mut PendingMaintenanceHandle<A>,
    secondary: &mut PendingMaintenanceHandle<A>,
    journal: &crate::recovery::transition::Journal,
    trust: &crate::recovery::transition::TrustStore,
    policy: &impl crate::recovery::transition::Policy,
) -> Result<()> {
    finish_abort(secondary, journal, trust, policy)?;
    finish_abort(primary, journal, trust, policy)
}

fn validate_pending<A: ReplicatedSchema>(
    c: &Connection,
    adapter: &A,
    contract: &schema_contract::Contract,
    initial: &str,
    identity: &Identity<SchemaId>,
    role: Role,
    expected: &crate::recovery::transition::Request,
    trust: &crate::recovery::transition::TrustStore,
    certified_authority: Option<&dyn crate::typed::CertifiedAuthority>,
    exact: Option<&Prepared>,
) -> Result<(PendingInspection, Prepared)> {
    let marker_rows: Vec<(u32, String)> = c
        .prepare(&format!("SELECT id,record FROM {MARKER} ORDER BY id"))?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        marker_rows.len() == 1 && marker_rows[0].0 == 1 && marker_rows[0].1.len() <= 64 * 1024,
        "pending marker row mismatch",
    )?;
    let marker: Marker = serde_json::from_str(&marker_rows[0].1)?;
    ensure(
        marker.format == 1
            && marker.identity == *identity
            && marker.role == role
            && matches!(marker.previous_runtime, 3 | 4),
        "pending marker owner mismatch",
    )?;
    let runtime: Vec<(u32, u32, String)> = c
        .prepare("SELECT id,format,initial_digest FROM node_runtime")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        runtime == [(1, 5, initial.to_owned())],
        "unsupported pending runtime",
    )?;
    ensure(
        c.query_row("SELECT count(*)=0 FROM replication_readiness", [], |r| {
            r.get::<_, bool>(0)
        })?,
        "pending readiness present",
    )?;
    let owner: Vec<(i64, String)> = c
        .prepare("SELECT rowid,value FROM node_identity")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        owner == [(1, serde_json::to_string(&(&identity, role))?)],
        "pending node owner mismatch",
    )?;
    let progress_rows: Vec<(u32, String, String)> = c
        .prepare("SELECT id,record,digest FROM node_pending_certified_progress ORDER BY id")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        progress_rows.len() == 1
            && progress_rows[0].0 == 1
            && progress_rows[0].1.len() <= 256 * 1024
            && progress_rows[0].2.len() <= 128,
        "pending progress row mismatch",
    )?;
    let progress: Prepared = serde_json::from_str(&progress_rows[0].1)?;
    if let Some(exact) = exact {
        ensure(&progress == exact, "pending maintenance conflict")?;
    }
    ensure(
        hash(&progress)? == progress_rows[0].2,
        "pending progress integrity",
    )?;
    ensure(
        matches!(progress.format, 1 | 2)
            && matches!(
                progress.phase.as_str(),
                "prepared" | "decided" | "applied" | "complete" | "aborting"
            )
            && &progress.request == expected,
        "unsupported pending phase",
    )?;
    // Format 1 is exactly what it always was: no abort, never aborting.
    ensure(
        progress.format != 1 || (progress.abort.is_none() && progress.phase != "aborting"),
        "unsupported pending phase",
    )?;
    // An aborting node is one-way: it carries a signed abort, has no completion
    // and its decision state must match what the abort was issued against.
    ensure(
        progress.phase != "aborting"
            || (progress.format == 2
                && progress.completion.is_none()
                && progress
                    .abort
                    .as_ref()
                    .is_some_and(|a| progress.decision.is_some() == a.decided)),
        "pending abort state mismatch",
    )?;
    schema_contract::verify(c, adapter, contract)?;
    sql_snapshot::verify_binding(c, adapter, &snapshot::scope(identity))?;
    if matches!(progress.phase.as_str(), "applied" | "complete") {
        recovery::verify_history(c, marker.previous_runtime - 2)?;
        let lineage = certified::verify_metadata(c, 3, Some(trust))?
            .ok_or("pending certified lineage missing")?;
        ensure(
            lineage.source_anchor
                == progress
                    .plan
                    .local(role)
                    .recovery_anchor
                    .clone()
                    .ok_or("pending recovery anchor missing")?
                && lineage.current_base == progress.plan.local(role).checkpoint,
            "pending certified lineage mismatch",
        )?;
    } else {
        let derived = history_format(c, marker.previous_runtime)?;
        recovery::verify_history(c, derived)?;
    }
    let receipt_format: Vec<(u32, u32)> = c
        .prepare("SELECT id,version FROM receipt_format ORDER BY id")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        receipt_format.len() == 1
            && receipt_format[0].0 == 1
            && matches!(receipt_format[0].1, 1 | 2),
        "pending receipt format mismatch",
    )?;
    let checkpoint_format: Vec<(u32, u32)> = c
        .prepare("SELECT id,version FROM checkpoint_format ORDER BY id")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(
        checkpoint_format == [(1, 2)],
        "pending checkpoint format mismatch",
    )?;
    capacity::verify_schema(c)?;
    capacity::verify_accounting(c)?;
    ensure(
        marker.request_digest == digest(&progress.request)?
            && marker.plan_digest == digest(&progress.plan)?,
        "pending marker/progress mismatch",
    )?;
    ensure(progress.token.len() <= 64 * 1024, "pending token limit")?;
    progress.plan.validate_certified()?;
    let previous_certificate = if c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='node_compaction_certificates')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        let json: Option<String> = if matches!(progress.phase.as_str(), "applied" | "complete") {
            c.query_row(
                "SELECT record FROM node_compaction_certificates WHERE sequence<?1 ORDER BY sequence DESC LIMIT 1",
                [progress.plan.local(role).checkpoint.sequence],
                |r| r.get(0),
            ).optional()?
        } else {
            c.query_row(
                "SELECT record FROM node_compaction_certificates ORDER BY sequence DESC LIMIT 1",
                [],
                |r| r.get(0),
            ).optional()?
        };
        json.map(|json| -> Result<certified::CertificateRecord> {
            ensure(json.len() <= 256 * 1024, "previous certificate limit")?;
            Ok(serde_json::from_str::<certified::CertificateRecord>(&json)?)
        })
        .transpose()?
    } else {
        None
    };
    certified::validate_record(
        &certified::CertificateRecord {
            format: 1,
            plan: progress.plan.clone(),
            request: progress.request.clone(),
            token: progress.token.clone(),
        },
        identity,
        role,
        previous_certificate.as_ref(),
    )?;
    let local = progress.plan.local(role);
    ensure(
        local.checkpoint.identity == *identity,
        "pending checkpoint identity mismatch",
    )?;
    let checkpoint = checkpoint::current_for(c, adapter, identity, initial, true)?.0;
    ensure(
        checkpoint == local.checkpoint,
        "pending physical checkpoint mismatch",
    )?;
    ensure(
        checkpoint::base_for::<SchemaId>(c)?
            == if matches!(progress.phase.as_str(), "applied" | "complete") {
                Some(local.checkpoint.clone())
            } else {
                local.head.base.clone()
            },
        "pending base mismatch",
    )?;
    let publication_json = singleton_text(c, "node_publication", "manifest", 256 * 1024)?;
    ensure(
        snapshot::Manifest::decode(publication_json.as_bytes())?
            == *local
                .publication
                .as_ref()
                .ok_or("pending publication missing")?,
        "pending publication mismatch",
    )?;
    Node::<A>::verify_publication_in(
        c,
        local
            .publication
            .as_ref()
            .ok_or("pending publication missing")?,
        identity,
        contract,
    )?;
    // This authenticates inspection bytes only. It is deliberately historical:
    // starting/deciding the operation still requires fresh issuance after BOTH
    // durable Prepared records. An expired proposal must be aborted/replaced;
    // this handle cannot renew it or authorize Journal::decide.
    let verified = crate::recovery::transition::verify_historical(
        &progress.token,
        &trust.as_trust(),
        expected,
    )?;
    ensure(
        if progress.phase == "prepared" {
            progress.decision.is_none() && progress.completion.is_none()
        } else if progress.phase == "complete" {
            progress.decision == Some(verified.token_digest())
                && progress.completion.is_some_and(|id| id != [0; 32])
        } else if progress.phase == "aborting" {
            // An abort may cancel a transition that was never decided, so the
            // decision is present exactly when the abort says it was.
            progress.completion.is_none()
                && progress.decision
                    == progress
                        .abort
                        .as_ref()
                        .and_then(|a| a.decided.then_some(verified.token_digest()))
        } else {
            progress.decision == Some(verified.token_digest()) && progress.completion.is_none()
        },
        "pending phase evidence mismatch",
    )?;
    let active_json = singleton_text(c, "recovery_active", "record", 64 * 1024)?;
    let active: Active = serde_json::from_str(&active_json)?;
    let plan = &active.request.plan;
    active.request.validate(&plan.baseline)?;
    let index = if active.member == plan.candidate {
        0
    } else if active.member == plan.baseline.survivor {
        1
    } else {
        return Err("active member mismatch".into());
    };
    let generation: Vec<u8> = c.query_row(
        "SELECT value FROM replication_generation WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let participant = &expected.participants[if role == Role::Primary { 0 } else { 1 }];
    ensure(
        active.format == 1
            && active.token_digest != [0; 32]
            && active.grant_id != [0; 32]
            && serde_json::to_string(identity)? == plan.baseline.scope
            && index == if role == Role::Primary { 0 } else { 1 }
            && active.request.prepared[index].member == active.member
            && active.request.prepared[index].generation.as_slice() == generation.as_slice()
            && active.checkpoint.identity == *identity
            && digest(&active.checkpoint)? == plan.baseline.checkpoint,
        "pending active recovery mismatch",
    )?;
    let certified_history: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='node_compaction_certificates')",
        [],
        |r| r.get(0),
    )?;
    if certified_history && matches!(progress.phase.as_str(), "prepared" | "decided") {
        maintenance::verify_certified(c, Some(trust))?;
        maintenance::verify_historical_certified(c, certified_authority)?;
    }
    if !certified_history {
        let anchored = checkpoint::calculate_for(
            c,
            adapter,
            identity,
            initial,
            true,
            Some(active.checkpoint.sequence),
        )?;
        ensure(
            anchored == active.checkpoint,
            "pending recovery anchor mismatch",
        )?;
        if role == Role::Primary {
            ensure(
                checkpoint::base_for::<SchemaId>(c)?.as_ref() == Some(&active.checkpoint),
                "pending candidate anchor base mismatch",
            )?;
        }
    }
    ensure(
        certified_history || matches!(progress.phase.as_str(), "prepared" | "decided" | "aborting"),
        "pending certified segment mismatch",
    )?;
    let seal_json = singleton_text(c, "recovery_seal", "plan", 32 * 1024)?;
    ensure(
        serde_json::from_str::<crate::recovery::model::Plan>(&seal_json)? == *plan,
        "pending seal mismatch",
    )?;
    let delivery = singleton_text(c, "recovery_delivery", "receipt", 256 * 1024)?;
    ensure(
        delivery
            == serde_json::to_string(&(
                1u32,
                &active.request,
                active.token_digest,
                active.grant_id,
                &active.request.prepared[index],
            ))?,
        "pending delivery mismatch",
    )?;
    let completion = singleton_text(c, "recovery_completion", "receipt", 256 * 1024)?;
    let (v, request, token, grant, done): (
        u32,
        crate::recovery::decision::Request,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) = serde_json::from_str(&completion)?;
    ensure(
        v == 1
            && request == active.request
            && token == active.token_digest
            && grant == active.grant_id
            && done != [0; 32],
        "pending completion mismatch",
    )?;
    ensure(
        participant.member == active.member
            && participant.generation.as_slice() == generation.as_slice(),
        "pending live member/generation mismatch",
    )?;
    ensure(
        expected.membership
            == digest(&(
                &active.request,
                active.token_digest,
                active.grant_id,
                &active.checkpoint,
            ))?
            && Some(expected.membership) == local.membership,
        "pending membership mismatch",
    )?;
    let inspection = PendingInspection {
        role,
        identity: identity.clone(),
        checkpoint,
        base: checkpoint::base_for::<SchemaId>(c)?,
    };
    Ok((inspection, progress))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{envelope_tests::StockSchema, typed::recovery::tests::recovered_pair_for_pending};
    use std::cell::Cell;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    struct Authority {
        current: Cell<bool>,
        revoke_on_check: Cell<bool>,
    }

    impl crate::recovery::transition::Policy for Authority {
        fn continuity(
            &self,
            _: &crate::recovery::transition::JournalScope,
            _: &crate::recovery::transition::Request,
        ) -> terrapi_vesta_recovery::Result<()> {
            if self.revoke_on_check.replace(false) {
                self.current.set(false);
            }
            ensure(self.current.get(), "stale pending authority")
        }

        fn prepared(
            &self,
            _: &crate::recovery::transition::JournalScope,
            _: &crate::recovery::transition::Request,
            _: &crate::recovery::transition::Participant,
        ) -> terrapi_vesta_recovery::Result<()> {
            Ok(())
        }

        fn applied(
            &self,
            _: &crate::recovery::transition::JournalScope,
            _: &crate::recovery::transition::CommittedTransition,
            _: &crate::recovery::transition::Participant,
        ) -> terrapi_vesta_recovery::Result<()> {
            Ok(())
        }

        fn abort_applicable(
            &self,
            _: &crate::recovery::transition::JournalScope,
            _: &crate::recovery::transition::MaintenanceAbort,
        ) -> terrapi_vesta_recovery::Result<()> {
            if self.revoke_on_check.replace(false) {
                self.current.set(false);
            }
            ensure(self.current.get(), "stale pending authority")
        }
    }

    struct WriterAuthority {
        journal: Mutex<crate::recovery::transition::Journal>,
        trust: crate::recovery::transition::TrustStore,
        current: AtomicBool,
    }

    impl crate::recovery::transition::Policy for WriterAuthority {
        fn continuity(
            &self,
            _: &crate::recovery::transition::JournalScope,
            _: &crate::recovery::transition::Request,
        ) -> terrapi_vesta_recovery::Result<()> {
            ensure(
                self.current.load(Ordering::SeqCst),
                "stale writer authority",
            )
        }
        fn prepared(
            &self,
            _: &crate::recovery::transition::JournalScope,
            _: &crate::recovery::transition::Request,
            _: &crate::recovery::transition::Participant,
        ) -> terrapi_vesta_recovery::Result<()> {
            Ok(())
        }
        fn applied(
            &self,
            _: &crate::recovery::transition::JournalScope,
            _: &crate::recovery::transition::CommittedTransition,
            _: &crate::recovery::transition::Participant,
        ) -> terrapi_vesta_recovery::Result<()> {
            Ok(())
        }

        fn historical_completion(
            &self,
            _: &crate::recovery::transition::JournalScope,
            historical: &crate::recovery::transition::Request,
            current_head: &crate::recovery::transition::Request,
        ) -> terrapi_vesta_recovery::Result<()> {
            ensure(
                self.current.load(Ordering::SeqCst)
                    && (current_head == historical || current_head.revision > historical.revision)
                    && current_head.authority_id == historical.authority_id
                    && current_head.install == historical.install
                    && current_head.region == historical.region
                    && current_head.scope == historical.scope
                    && current_head.schema == historical.schema
                    && current_head.membership == historical.membership
                    && current_head.source_anchor == historical.source_anchor,
                "stale historical writer authority",
            )
        }
    }

    impl crate::typed::CertifiedAuthority for WriterAuthority {
        fn fetch_completed(
            &self,
            request: &crate::recovery::transition::Request,
        ) -> terrapi_vesta_recovery::Result<crate::recovery::transition::CompletedTransition>
        {
            self.journal
                .lock()
                .map_err(|_| "writer authority poisoned")?
                .fetch_completed(request, &self.trust.as_trust(), self)
        }

        fn fetch_completed_revision(
            &self,
            request: &crate::recovery::transition::Request,
        ) -> terrapi_vesta_recovery::Result<
            crate::recovery::transition::HistoricalCompletedTransition,
        > {
            self.journal
                .lock()
                .map_err(|_| "writer authority poisoned")?
                .fetch_completed_revision(request, &self.trust.as_trust(), self)
        }
    }

    fn pending_evidence<A: ReplicatedSchema>(
        h: &PendingMaintenanceHandle<A>,
    ) -> Result<(u32, u64, String, String, u64, u64, u64)> {
        Ok(h.db.with_connection(|c| {
            Ok((
                c.query_row("SELECT format FROM node_runtime WHERE id=1", [], |r| r.get(0))?,
                c.query_row("SELECT count(*) FROM replication_readiness", [], |r| r.get(0))?,
                c.query_row(
                    "SELECT record FROM node_pending_certified_maintenance WHERE id=1",
                    [],
                    |r| r.get(0),
                )?,
                c.query_row(
                    "SELECT record || ':' || digest FROM node_pending_certified_progress WHERE id=1",
                    [],
                    |r| r.get(0),
                )?,
                c.query_row("SELECT count(*) FROM replication_log", [], |r| r.get(0))?,
                c.query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name IN ('node_compaction','node_compaction_history','node_compaction_root','node_compaction_certificates')",
                    [],
                    |r| r.get(0),
                )?,
                c.query_row("SELECT count(*) FROM recovery_completion", [], |r| r.get(0))?,
            ))
        })?)
    }

    fn cid<T: Serialize>(v: &T) -> Result<[u8; 32]> {
        digest(v)
    }
    fn cp(v: &Prefix) -> Result<crate::recovery::transition::Checkpoint> {
        Ok(crate::recovery::transition::Checkpoint {
            sequence: v.sequence,
            digest: cid(v)?,
        })
    }

    #[test]
    fn real_recovered_prepared_opens_restricted_and_rejects_mutations() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (mut p, mut s) = recovered_pair_for_pending(dir.path())?;
        p.upgrade_receipt_capacity()?;
        s.upgrade_receipt_capacity()?;
        p.enable_maintenance()?;
        s.enable_maintenance()?;
        let old_p = p
            .plan_compaction()?
            .publication
            .ok_or("candidate publication missing")?;
        let old_s = s
            .plan_compaction()?
            .publication
            .ok_or("survivor publication missing")?;
        let mut batch = crate::envelope_tests::stock_entry().batch;
        batch.operation_id = "pending-write".into();
        commit(&mut p, &mut s, batch)?;
        p.rotate_snapshot(&old_p)?;
        s.rotate_snapshot(&old_s)?;
        let pp = p.plan_compaction()?;
        let sp = s.plan_compaction()?;
        let plan = compaction::PairPlan {
            id: [31; 32],
            primary: pp,
            secondary: sp,
        };
        plan.validate_certified()?;
        let request = crate::recovery::transition::Request {
            format: 1,
            id: [32; 32],
            authority_id: [33; 32],
            revision: 1,
            install: "fixture".into(),
            region: "test".into(),
            scope: cid(p.identity())?,
            schema: cid(&plan.primary.contract)?,
            membership: plan.primary.membership.unwrap(),
            source_anchor: cp(plan.primary.recovery_anchor.as_ref().unwrap())?,
            participants: [
                crate::recovery::transition::Participant {
                    member: p.recovery_member_identity()?.unwrap(),
                    generation: p.connection(checkpoint::generation)?,
                    old_base: plan.primary.head.base.as_ref().map(cp).transpose()?,
                    target: cp(&plan.primary.checkpoint)?,
                    plan: cid(&plan)?,
                    publication: cid(plan.primary.publication.as_ref().unwrap())?,
                },
                crate::recovery::transition::Participant {
                    member: s.recovery_member_identity()?.unwrap(),
                    generation: s.connection(checkpoint::generation)?,
                    old_base: plan.secondary.head.base.as_ref().map(cp).transpose()?,
                    target: cp(&plan.secondary.checkpoint)?,
                    plan: cid(&plan)?,
                    publication: cid(plan.secondary.publication.as_ref().unwrap())?,
                },
            ],
        };
        let (key, public) = super::super::certified::tests::signer()?;
        let token = super::super::certified::tests::sign(&key, &request)?;
        let trust = crate::recovery::transition::TrustStore {
            profile: crate::recovery::grant::Profile {
                issuer: "issuer".into(),
                audience: "audience".into(),
                token_type: crate::recovery::transition::TOKEN_TYPE.into(),
            },
            keys: vec![("fixture".into(), public)],
            max_lifetime: 20,
        };
        let mut wrong_plan = plan.clone();
        wrong_plan.id = [99; 32];
        assert!(prepare_pair(&mut p, &mut s, &wrong_plan, &request, &token, 15, &trust).is_err());
        for n in [&p, &s] {
            n.connection(|c| {
                ensure(c.query_row("SELECT format FROM node_runtime WHERE id=1",[],|r|r.get::<_,u32>(0))? != 5,"failed preflight changed runtime")?;
                ensure(!c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='node_pending_certified_maintenance')",[],|r|r.get::<_,bool>(0))?,"failed preflight created pending state")
            })?;
        }
        s.connection(|c|{c.execute_batch("CREATE TRIGGER fail_pending_runtime BEFORE UPDATE ON node_runtime BEGIN SELECT RAISE(ABORT,'fixture crash'); END;")?;Ok(())})?;
        let crash = prepare_pair(&mut p, &mut s, &plan, &request, &token, 15, &trust).unwrap_err();
        ensure(
            crash.to_string().contains("fixture crash"),
            "pending fixture failed before injected boundary",
        )?;
        assert_eq!(
            p.connection(|c| c
                .query_row("SELECT format FROM node_runtime WHERE id=1", [], |r| r
                    .get::<_, u32>(0))
                .map_err(Into::into))?,
            5
        );
        assert_ne!(
            s.connection(|c| c
                .query_row("SELECT format FROM node_runtime WHERE id=1", [], |r| r
                    .get::<_, u32>(0))
                .map_err(Into::into))?,
            5
        );
        ensure(!s.connection(|c|c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='node_pending_certified_maintenance' OR name='node_pending_certified_progress')",[],|r|r.get::<_,bool>(0)).map_err(Into::into))?,"failed node2 transaction left pending tables")?;
        let saved_digest = p.connection(|c| {
            c.query_row(
                "SELECT digest FROM node_pending_certified_progress WHERE id=1",
                [],
                |r| r.get::<_, String>(0),
            )
            .map_err(Into::into)
        })?;
        p.connection(|c| {
            c.execute(
                "UPDATE node_pending_certified_progress SET digest='corrupt' WHERE id=1",
                [],
            )?;
            Ok(())
        })?;
        assert!(prepare_pair(&mut p, &mut s, &plan, &request, &token, 15, &trust).is_err());
        assert_ne!(
            s.connection(|c| c
                .query_row("SELECT format FROM node_runtime WHERE id=1", [], |r| r
                    .get::<_, u32>(0))
                .map_err(Into::into))?,
            5
        );
        p.connection(|c| {
            c.execute(
                "UPDATE node_pending_certified_progress SET digest=?1 WHERE id=1",
                [saved_digest],
            )?;
            Ok(())
        })?;
        s.connection(|c| {
            c.execute_batch("DROP TRIGGER fail_pending_runtime")?;
            Ok(())
        })?;
        prepare_pair(&mut p, &mut s, &plan, &request, &token, 15, &trust)?;
        let alternate = super::super::certified::tests::sign(&key, &request)?;
        ensure(
            alternate != token,
            "fixture signature unexpectedly repeated",
        )?;
        assert!(prepare_pair(&mut p, &mut s, &plan, &request, &alternate, 15, &trust).is_err());
        prepare_pair(&mut p, &mut s, &plan, &request, &token, 15, &trust)?;
        assert!(prepare_pair(&mut p, &mut s, &plan, &request, &token, 21, &trust).is_err());
        let id = p.identity().clone();
        drop(p);
        drop(s);
        assert!(Node::open(
            dir.path().join("candidate1"),
            Role::Primary,
            id.clone(),
            "fixture",
            StockSchema
        )
        .is_err());
        let mut h = PendingMaintenanceHandle::open_existing(
            dir.path().join("candidate1"),
            Role::Primary,
            id,
            "fixture",
            StockSchema,
            &request,
            &trust,
        )?;
        assert_eq!(h.inspect().checkpoint, plan.primary.checkpoint);
        let mut hs = PendingMaintenanceHandle::open_existing(
            dir.path().join("survivor"),
            Role::Secondary,
            h.inspect().identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust,
        )?;
        assert_eq!(hs.inspect().checkpoint, plan.secondary.checkpoint);

        let journal_path = dir.path().join("maintenance-journal");
        let journal_scope = crate::recovery::transition::JournalScope {
            install: request.install.clone(),
            region: request.region.clone(),
            profile: trust.profile.clone(),
            scope: request.scope,
            schema: request.schema,
            membership: request.membership,
            source_anchor: request.source_anchor.clone(),
            authority_id: request.authority_id,
            initial_revision: request.revision,
        };
        let journal = crate::recovery::transition::Journal::create(
            &journal_path,
            "journal-fixture",
            journal_scope.clone(),
        )?;
        assert!(journal.status(&trust.as_trust())?.request.is_none());
        let before = (pending_evidence(&h)?, pending_evidence(&hs)?);
        let authority = Authority {
            current: Cell::new(false),
            revoke_on_check: Cell::new(false),
        };
        assert!(decide_prepared(&h, &hs, &journal, 15, &trust, &authority).is_err());
        assert!(journal.status(&trust.as_trust())?.request.is_none());
        assert_eq!(before, (pending_evidence(&h)?, pending_evidence(&hs)?));
        let saved_prepared = hs.prepared.clone();
        hs.prepared.token = alternate.clone();
        assert!(decide_prepared(&h, &hs, &journal, 15, &trust, &authority).is_err());
        hs.prepared = saved_prepared.clone();
        hs.prepared.request.id = [88; 32];
        assert!(decide_prepared(&h, &hs, &journal, 15, &trust, &authority).is_err());
        hs.prepared = saved_prepared.clone();
        hs.prepared.plan.id = [89; 32];
        assert!(decide_prepared(&h, &hs, &journal, 15, &trust, &authority).is_err());
        hs.prepared = saved_prepared;
        assert!(journal.status(&trust.as_trust())?.request.is_none());
        assert_eq!(before, (pending_evidence(&h)?, pending_evidence(&hs)?));
        authority.current.set(true);
        let decision = decide_prepared(&h, &hs, &journal, 15, &trust, &authority)?;
        assert_eq!(decision.request(), &request);
        let status = journal.status(&trust.as_trust())?;
        assert_eq!(status.request.as_ref(), Some(&request));
        assert_eq!(status.acknowledgements, [false; 2]);
        assert_eq!(status.completion, None);
        assert_eq!(before, (pending_evidence(&h)?, pending_evidence(&hs)?));
        let retry = decide_prepared(&h, &hs, &journal, 15, &trust, &authority)?;
        assert_eq!(retry.token_digest(), decision.token_digest());
        authority.current.set(false);
        assert!(decide_prepared(&h, &hs, &journal, 15, &trust, &authority).is_err());
        assert_eq!(before, (pending_evidence(&h)?, pending_evidence(&hs)?));
        authority.current.set(true);
        drop(journal);
        let reopened = crate::recovery::transition::Journal::open(
            &journal_path,
            "journal-fixture",
            journal_scope.clone(),
            &trust.as_trust(),
        )?;
        let reopened_status = reopened.status(&trust.as_trust())?;
        assert_eq!(reopened_status.request.as_ref(), Some(&request));
        assert_eq!(reopened_status.acknowledgements, [false; 2]);
        assert_eq!(reopened_status.completion, None);
        assert_eq!(before, (pending_evidence(&h)?, pending_evidence(&hs)?));
        record_decided(&mut h, &reopened, &trust, &authority)?;
        let after_primary = (pending_evidence(&h)?, pending_evidence(&hs)?);
        assert_ne!(after_primary.0, before.0);
        assert_eq!(after_primary.1, before.1);
        authority.current.set(true);
        authority.revoke_on_check.set(true);
        assert!(record_decided(&mut hs, &reopened, &trust, &authority).is_err());
        assert_eq!(
            after_primary,
            (pending_evidence(&h)?, pending_evidence(&hs)?)
        );
        authority.current.set(true);
        let survivor_path = dir.path().join("survivor");
        let moved_path = dir.path().join("survivor-retained");
        let replacement_path = dir.path().join("survivor-replacement");
        let displaced_path = dir.path().join("survivor-displaced");
        std::fs::copy(&survivor_path, &replacement_path)?;
        let replacement_before = std::fs::read(&replacement_path)?;
        std::fs::rename(&survivor_path, &moved_path)?;
        std::fs::rename(&replacement_path, &survivor_path)?;
        let substituted = record_decided(&mut hs, &reopened, &trust, &authority);
        drop(hs);
        std::fs::rename(&survivor_path, &displaced_path)?;
        std::fs::rename(&moved_path, &survivor_path)?;
        ensure(
            std::fs::read(&displaced_path)? == replacement_before,
            "path substitute was mutated",
        )?;
        let mut hs = PendingMaintenanceHandle::open_existing(
            &survivor_path,
            Role::Secondary,
            h.inspect().identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust,
        )?;
        if substituted.is_err() {
            record_decided(&mut hs, &reopened, &trust, &authority)?;
        } else {
            ensure(
                hs.prepared.phase == "decided",
                "retained connection did not advance original file",
            )?;
        }
        let both_decided = (pending_evidence(&h)?, pending_evidence(&hs)?);
        record_decided(&mut h, &reopened, &trust, &authority)?;
        record_decided(&mut hs, &reopened, &trust, &authority)?;
        assert_eq!(
            both_decided,
            (pending_evidence(&h)?, pending_evidence(&hs)?)
        );
        apply_decided(&mut h, &reopened, &trust, &authority)?;
        let primary_applied = (pending_evidence(&h)?, pending_evidence(&hs)?);
        assert_ne!(primary_applied.0, both_decided.0);
        assert_eq!(primary_applied.1, both_decided.1);
        authority.current.set(true);
        authority.revoke_on_check.set(true);
        assert!(apply_decided(&mut hs, &reopened, &trust, &authority).is_err());
        assert_eq!(
            primary_applied,
            (pending_evidence(&h)?, pending_evidence(&hs)?)
        );
        authority.current.set(true);
        apply_decided(&mut hs, &reopened, &trust, &authority)?;
        let both_applied = (pending_evidence(&h)?, pending_evidence(&hs)?);
        apply_decided(&mut h, &reopened, &trust, &authority)?;
        apply_decided(&mut hs, &reopened, &trust, &authority)?;
        assert_eq!(
            both_applied,
            (pending_evidence(&h)?, pending_evidence(&hs)?)
        );
        acknowledge_applied(&h, &reopened, &trust, &authority)?;
        assert_eq!(
            reopened.status(&trust.as_trust())?.acknowledgements,
            [true, false]
        );
        authority.current.set(true);
        authority.revoke_on_check.set(true);
        assert!(acknowledge_applied(&hs, &reopened, &trust, &authority).is_err());
        assert_eq!(
            reopened.status(&trust.as_trust())?.acknowledgements,
            [true, false]
        );
        authority.current.set(true);
        acknowledge_applied(&hs, &reopened, &trust, &authority)?;
        assert_eq!(
            reopened.status(&trust.as_trust())?.acknowledgements,
            [true, true]
        );
        acknowledge_applied(&h, &reopened, &trust, &authority)?;
        acknowledge_applied(&hs, &reopened, &trust, &authority)?;
        authority.current.set(true);
        authority.revoke_on_check.set(true);
        assert!(complete_authority(&h, &hs, &reopened, &trust, &authority,).is_err());
        assert_eq!(reopened.status(&trust.as_trust())?.completion, None);
        authority.current.set(true);
        complete_authority(&h, &hs, &reopened, &trust, &authority)?;
        // The completion id is derived from the request, the issued token and
        // the acknowledgements, so it is stable across retries and restarts.
        let decided = reopened.fetch(&request, &trust.as_trust(), &authority)?;
        let derived = completion_id(
            decided.request(),
            decided.token_digest(),
            decided.acknowledgements(),
        )?;
        assert_eq!(
            reopened.status(&trust.as_trust())?.completion,
            Some(derived)
        );
        complete_authority(&h, &hs, &reopened, &trust, &authority)?;
        assert_eq!(
            reopened.status(&trust.as_trust())?.completion,
            Some(derived)
        );
        // A conflicting id can now only be injected at the journal itself.
        assert!(reopened
            .complete(&decided, [91; 32], &trust.as_trust(), &authority)
            .is_err());
        record_complete(&mut h, &reopened, &trust, &authority)?;
        let primary_complete = (pending_evidence(&h)?, pending_evidence(&hs)?);
        authority.current.set(true);
        authority.revoke_on_check.set(true);
        assert!(record_complete(&mut hs, &reopened, &trust, &authority).is_err());
        assert_eq!(
            primary_complete,
            (pending_evidence(&h)?, pending_evidence(&hs)?)
        );
        authority.current.set(true);
        record_complete(&mut hs, &reopened, &trust, &authority)?;
        let both_complete = (pending_evidence(&h)?, pending_evidence(&hs)?);
        record_complete(&mut h, &reopened, &trust, &authority)?;
        record_complete(&mut hs, &reopened, &trust, &authority)?;
        assert_eq!(
            both_complete,
            (pending_evidence(&h)?, pending_evidence(&hs)?)
        );
        let peer_before_capacity_corruption = pending_evidence(&hs)?;
        h.db.with_connection(|c| {
            c.execute(
                "UPDATE receipt_capacity SET receipt_bytes=receipt_bytes+1 WHERE id=1",
                [],
            )?;
            Ok(())
        })?;
        let primary_identity = h.inspect().identity.clone();
        drop(h);
        assert!(PendingMaintenanceHandle::open_existing(
            dir.path().join("candidate1"),
            Role::Primary,
            primary_identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust,
        )
        .is_err());
        assert_eq!(peer_before_capacity_corruption, pending_evidence(&hs)?);
        let raw = Vesta::open(&dir.path().join("candidate1"), "fixture")?;
        raw.with_connection(|c| {
            c.execute(
                "UPDATE receipt_capacity SET receipt_bytes=receipt_bytes-1 WHERE id=1",
                [],
            )?;
            Ok(())
        })?;
        drop(raw);
        let h = PendingMaintenanceHandle::open_existing(
            dir.path().join("candidate1"),
            Role::Primary,
            primary_identity,
            "fixture",
            StockSchema,
            &request,
            &trust,
        )?;
        let insert_trigger = h.db.with_connection(|c| {
            c.query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='receipt_capacity_insert'",
                [],
                |r| r.get::<_, String>(0),
            )
        })?;
        h.db.with_connection(|c| {
            c.execute_batch(
                "DROP TRIGGER receipt_capacity_insert;
                 CREATE TRIGGER receipt_capacity_insert AFTER INSERT ON operation_receipts BEGIN SELECT 1; END;",
            )?;
            Ok(())
        })?;
        drop(h);
        assert!(PendingMaintenanceHandle::open_existing(
            dir.path().join("candidate1"),
            Role::Primary,
            hs.inspect().identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust,
        )
        .is_err());
        assert_eq!(peer_before_capacity_corruption, pending_evidence(&hs)?);
        let raw = Vesta::open(&dir.path().join("candidate1"), "fixture")?;
        raw.with_connection(|c| {
            c.execute_batch("DROP TRIGGER receipt_capacity_insert")?;
            c.execute_batch(&insert_trigger)?;
            Ok(())
        })?;
        drop(raw);
        let h = PendingMaintenanceHandle::open_existing(
            dir.path().join("candidate1"),
            Role::Primary,
            hs.inspect().identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust,
        )?;
        drop(hs);
        assert!(PendingMaintenanceHandle::open_existing(
            dir.path().join("candidate1"),
            Role::Primary,
            h.inspect().identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust
        )
        .is_err());
        let identity = h.inspect().identity.clone();
        drop(h);
        let path = dir.path().join("candidate1");
        let raw = Vesta::open(&path, "fixture")?;
        let saved = raw.with_connection(|c| {
            c.query_row(
                "SELECT record,digest FROM node_pending_certified_progress WHERE id=1",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
        })?;
        raw.with_connection(|c| {
            c.execute("DELETE FROM node_pending_certified_progress", [])
                .map(|_| ())
        })?;
        drop(raw);
        assert!(PendingMaintenanceHandle::open_existing(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust
        )
        .is_err());
        let raw = Vesta::open(&path, "fixture")?;
        raw.with_connection(|c| {
            c.execute(
                "INSERT INTO node_pending_certified_progress VALUES(1,?1,?2)",
                params![saved.0, saved.1],
            )
            .map(|_| ())
        })?;
        raw.with_connection(|c| {
            c.execute("UPDATE node_runtime SET format=4 WHERE id=1", [])
                .map(|_| ())
        })?;
        drop(raw);
        assert!(PendingMaintenanceHandle::open_existing(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust
        )
        .is_err());
        let raw = Vesta::open(&path, "fixture")?;
        raw.with_connection(|c| {
            c.execute("UPDATE node_runtime SET format=5 WHERE id=1", [])
                .map(|_| ())
        })?;
        drop(raw);
        let wrong = crate::recovery::transition::TrustStore {
            profile: trust.profile.clone(),
            keys: Vec::new(),
            max_lifetime: trust.max_lifetime,
        };
        assert!(PendingMaintenanceHandle::open_existing(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &wrong
        )
        .is_err());
        let raw = Vesta::open(&path, "fixture")?;
        raw.with_connection(|c| {
            let record: String =
                c.query_row("SELECT record FROM recovery_active WHERE id=1", [], |r| {
                    r.get(0)
                })?;
            c.pragma_update(None, "ignore_check_constraints", true)?;
            c.execute("INSERT INTO recovery_active VALUES(2,?1)", [record])?;
            Ok(())
        })?;
        drop(raw);
        assert!(PendingMaintenanceHandle::open_existing(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust
        )
        .is_err());
        let raw = Vesta::open(&path, "fixture")?;
        raw.with_connection(|c| {
            c.execute("DELETE FROM recovery_active WHERE id=2", [])?;
            Ok(())
        })?;
        drop(raw);
        let mut h = PendingMaintenanceHandle::open_existing(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust,
        )?;
        let mut hs = PendingMaintenanceHandle::open_existing(
            dir.path().join("survivor"),
            Role::Secondary,
            identity.clone(),
            "fixture",
            StockSchema,
            &request,
            &trust,
        )?;
        finalize_node(&mut hs, &reopened, &trust, &authority)?;
        ensure(
            h.db.with_connection(|c| c.query_row(
                "SELECT format=5 AND NOT EXISTS(SELECT 1 FROM replication_readiness) FROM node_runtime WHERE id=1",
                [],
                |r| r.get::<_, bool>(0),
            ))?,
            "primary admitted before finalization",
        )?;
        finalize_pair(&mut h, &mut hs, &reopened, &trust, &authority)?;
        drop(h);
        drop(hs);
        let writer_authority = Arc::new(WriterAuthority {
            journal: Mutex::new(reopened),
            trust: trust.clone(),
            current: AtomicBool::new(false),
        });
        assert!(Node::open_with_completed_transition(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            trust.clone(),
            writer_authority.clone(),
        )
        .is_err());
        writer_authority.current.store(true, Ordering::SeqCst);
        let mut primary = Node::open_with_completed_transition(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            trust.clone(),
            writer_authority.clone(),
        )?;
        let mut secondary = Node::open_with_completed_transition(
            dir.path().join("survivor"),
            Role::Secondary,
            identity.clone(),
            "fixture",
            StockSchema,
            trust.clone(),
            writer_authority.clone(),
        )?;
        let second_old_primary = primary
            .plan_compaction()?
            .publication
            .ok_or("second primary publication missing")?;
        let second_old_secondary = secondary
            .plan_compaction()?
            .publication
            .ok_or("second secondary publication missing")?;
        let mut batch = crate::envelope_tests::stock_entry().batch;
        batch.operation_id = "after-certified-finalization".into();
        writer_authority.current.store(false, Ordering::SeqCst);
        assert!(commit(&mut primary, &mut secondary, batch.clone()).is_err());
        writer_authority.current.store(true, Ordering::SeqCst);
        commit(&mut primary, &mut secondary, batch)?;
        primary.rotate_snapshot(&second_old_primary)?;
        secondary.rotate_snapshot(&second_old_secondary)?;
        let second_plan = compaction::PairPlan {
            id: [101; 32],
            primary: primary.plan_compaction()?,
            secondary: secondary.plan_compaction()?,
        };
        second_plan.validate_certified()?;
        ensure(
            second_plan.primary.head.base.as_ref() == Some(&plan.primary.checkpoint)
                && second_plan.secondary.head.base.as_ref() == Some(&plan.secondary.checkpoint),
            "second cycle did not follow first certified bases",
        )?;
        let second_request = crate::recovery::transition::Request {
            format: 1,
            id: [102; 32],
            authority_id: request.authority_id,
            revision: request.revision + 1,
            install: request.install.clone(),
            region: request.region.clone(),
            scope: request.scope,
            schema: request.schema,
            membership: request.membership,
            source_anchor: request.source_anchor.clone(),
            participants: [
                crate::recovery::transition::Participant {
                    member: primary.recovery_member_identity()?.unwrap(),
                    generation: primary.connection(checkpoint::generation)?,
                    old_base: second_plan.primary.head.base.as_ref().map(cp).transpose()?,
                    target: cp(&second_plan.primary.checkpoint)?,
                    plan: cid(&second_plan)?,
                    publication: cid(second_plan.primary.publication.as_ref().unwrap())?,
                },
                crate::recovery::transition::Participant {
                    member: secondary.recovery_member_identity()?.unwrap(),
                    generation: secondary.connection(checkpoint::generation)?,
                    old_base: second_plan
                        .secondary
                        .head
                        .base
                        .as_ref()
                        .map(cp)
                        .transpose()?,
                    target: cp(&second_plan.secondary.checkpoint)?,
                    plan: cid(&second_plan)?,
                    publication: cid(second_plan.secondary.publication.as_ref().unwrap())?,
                },
            ],
        };
        let second_token = super::super::certified::tests::sign(&key, &second_request)?;
        prepare_pair(
            &mut primary,
            &mut secondary,
            &second_plan,
            &second_request,
            &second_token,
            15,
            &trust,
        )?;
        drop(primary);
        drop(secondary);
        let mut second_primary = PendingMaintenanceHandle::open_existing_with_authority(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            &second_request,
            &trust,
            Some(writer_authority.clone()),
        )?;
        let mut second_secondary = PendingMaintenanceHandle::open_existing_with_authority(
            dir.path().join("survivor"),
            Role::Secondary,
            identity.clone(),
            "fixture",
            StockSchema,
            &second_request,
            &trust,
            Some(writer_authority.clone()),
        )?;
        let second_journal = crate::recovery::transition::Journal::open(
            &journal_path,
            "journal-fixture",
            journal_scope,
            &trust.as_trust(),
        )?;
        decide_prepared(
            &second_primary,
            &second_secondary,
            &second_journal,
            15,
            &trust,
            writer_authority.as_ref(),
        )?;
        writer_authority.current.store(false, Ordering::SeqCst);
        assert!(record_decided(
            &mut second_primary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )
        .is_err());
        writer_authority.current.store(true, Ordering::SeqCst);
        record_decided(
            &mut second_primary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        record_decided(
            &mut second_secondary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        apply_decided(
            &mut second_primary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        apply_decided(
            &mut second_secondary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        acknowledge_applied(
            &second_primary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        acknowledge_applied(
            &second_secondary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        complete_authority(
            &second_primary,
            &second_secondary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        record_complete(
            &mut second_primary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        record_complete(
            &mut second_secondary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        finalize_node(
            &mut second_secondary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        drop(second_primary);
        drop(second_secondary);
        assert!(Node::open_with_completed_transition(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            trust.clone(),
            writer_authority.clone(),
        )
        .is_err());
        let restarted_secondary = Node::open_with_completed_transition(
            dir.path().join("survivor"),
            Role::Secondary,
            identity.clone(),
            "fixture",
            StockSchema,
            trust.clone(),
            writer_authority.clone(),
        )?;
        drop(restarted_secondary);
        let mut restarted_primary = PendingMaintenanceHandle::open_existing_with_authority(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            &second_request,
            &trust,
            Some(writer_authority.clone()),
        )?;
        finalize_node(
            &mut restarted_primary,
            &second_journal,
            &trust,
            writer_authority.as_ref(),
        )?;
        drop(restarted_primary);
        let mut reopened_primary = Node::open_with_completed_transition(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            trust.clone(),
            writer_authority.clone(),
        )?;
        let mut reopened_secondary = Node::open_with_completed_transition(
            dir.path().join("survivor"),
            Role::Secondary,
            identity,
            "fixture",
            StockSchema,
            trust.clone(),
            writer_authority,
        )?;
        ensure(
            reopened_primary.connection(|c| {
                c.query_row(
                    "SELECT count(*) FROM node_compaction_certificates",
                    [],
                    |r| r.get::<_, u64>(0),
                )
                .map_err(Into::into)
            })? == 2
                && reopened_secondary.connection(|c| {
                    c.query_row(
                        "SELECT count(*) FROM node_compaction_certificates",
                        [],
                        |r| r.get::<_, u64>(0),
                    )
                    .map_err(Into::into)
                })? == 2,
            "second certified segment missing",
        )?;
        ensure(
            reopened_primary.plan_compaction()?.head.base
                == Some(second_plan.primary.checkpoint.clone())
                && reopened_secondary.plan_compaction()?.head.base
                    == Some(second_plan.secondary.checkpoint.clone()),
            "second certified bases not durable",
        )?;
        let second_verified = crate::recovery::transition::verify_historical(
            &second_token,
            &trust.as_trust(),
            &second_request,
        )?;
        let loss_request = crate::recovery::transition::LossRequest {
            format: 1,
            id: [104; 32],
            authority_id: second_request.authority_id,
            revision: second_request.revision + 1,
            install: second_request.install.clone(),
            region: second_request.region.clone(),
            scope: second_request.scope,
            schema: second_request.schema,
            membership: second_request.membership,
            replacement_membership: [105; 32],
            source_certificate: second_verified.certificate_id(),
            source_token_digest: second_verified.token_digest(),
            source_cut: second_request.participants[0].target.clone(),
            lost_member: second_request.participants[0].member,
            lost_generation: second_request.participants[0].generation,
            survivor: second_request.participants[1].clone(),
            survivor_cut: second_request.participants[1].target.clone(),
            survivor_publication: second_request.participants[1].publication,
            replacement_member: [106; 32],
            replacement_generation: [107; 32],
            fencing_ref: [108; 32],
            source_kind: None,
            abandoned_request: None,
            supersedes: None,
        };
        loss_request.validate()?;
        reopened_secondary.connection(|c| {
            super::loss::validate::<StockSchema>(
                c,
                &reopened_secondary.adapter,
                &reopened_secondary.identity,
                &reopened_secondary.contract,
                &reopened_secondary.initial,
                &trust,
                &loss_request,
            )
            .map(|_| ())
        })?;
        let mut wrong_loss = loss_request.clone();
        wrong_loss.survivor.generation = [109; 32];
        assert!(reopened_secondary
            .connection(|c| super::loss::validate::<StockSchema>(
                c,
                &reopened_secondary.adapter,
                &reopened_secondary.identity,
                &reopened_secondary.contract,
                &reopened_secondary.initial,
                &trust,
                &wrong_loss,
            )
            .map(|_| ()))
            .is_err());
        let _before_intervening = reopened_primary.view()?;
        let mut intervening = crate::envelope_tests::stock_entry().batch;
        intervening.operation_id = "after-second-certified-cycle".into();
        commit(
            &mut reopened_primary,
            &mut reopened_secondary,
            intervening.clone(),
        )?;
        let _after_intervening = reopened_primary.view()?;
        ensure(
            reopened_primary
                .receipt(&intervening.operation_id)?
                .is_some()
                && reopened_secondary
                    .receipt(&intervening.operation_id)?
                    .is_some(),
            "second-cycle intervening receipt/view missing",
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // S5a: closing preflight, phase boundaries and API shape.
    // -----------------------------------------------------------------------

    use super::super::tests::support;
    use crate::envelope_tests::stock_entry;

    #[track_caller]
    fn refused<T>(outcome: Result<T>, expected: &str) {
        match outcome {
            Ok(_) => panic!("expected an error containing {expected:?}"),
            Err(e) => {
                let text = e.to_string();
                assert!(
                    text.contains(expected),
                    "expected {expected:?}, got {text:?}"
                );
            }
        }
    }

    struct Lifecycle {
        pair: support::CertifiedPair,
        journal: crate::recovery::transition::Journal,
        authority: Authority,
    }

    fn lifecycle(seed: &str) -> Result<Lifecycle> {
        let pair = support::certified_pair(seed, [51; 32], "lifecycle")?;
        let journal = crate::recovery::transition::Journal::create(
            &pair.dir.path().join("lifecycle-journal"),
            "journal-fixture",
            support::journal_scope(&pair.request),
        )?;
        Ok(Lifecycle {
            pair,
            journal,
            authority: Authority {
                current: Cell::new(true),
                revoke_on_check: Cell::new(false),
            },
        })
    }

    impl Lifecycle {
        fn prepare(&mut self) -> Result<()> {
            prepare_pair(
                &mut self.pair.p,
                &mut self.pair.s,
                &self.pair.plan,
                &self.pair.request,
                &self.pair.token,
                15,
                &self.pair.trust,
            )
        }
    }

    /// C2: a pinned publication is refused by the preflight, before the marker
    /// write turns `prepare_pair` into a one-way door.
    #[test]
    fn prepare_refuses_a_pinned_publication_and_leaves_both_nodes_ordinary() -> Result<()> {
        let mut fixture = lifecycle("pinned-preflight")?;
        let publication = fixture
            .pair
            .p
            .plan_compaction()?
            .publication
            .ok_or("publication missing")?;
        fixture.pair.p.pin_snapshot(&publication, "transfer-1")?;
        refused(fixture.prepare(), "snapshot publication is pinned");
        // Both nodes are still ordinary and writable.
        for node in [&fixture.pair.p, &fixture.pair.s] {
            assert!(node.checkpoint().is_ok());
            assert!(node.connection(|c| Ok(!pending_present(c)?))?);
        }
        let mut batch = stock_entry().batch;
        batch.operation_id = "still-writable".into();
        commit(&mut fixture.pair.p, &mut fixture.pair.s, batch)?;
        // Releasing the pin makes the pair preparable again. The commit above
        // moved the cut, so the plan is rebuilt from the live nodes.
        fixture
            .pair
            .p
            .release_snapshot_pin(&publication, "transfer-1")?;
        let fresh = lifecycle("pinned-preflight-clean")?;
        let mut fresh = fresh;
        fresh.prepare()?;
        Ok(())
    }

    /// C3: every durable shape whose APPLY preconditions could never hold is
    /// refused at preflight instead of bricking both nodes.
    ///
    /// Note: for these synthetic shapes the existing structural verifiers
    /// (`history_format`, `certified::verify_metadata`) already refuse during
    /// the preflight's own `plan_compaction`, so the new `require_appliable`
    /// check is defence in depth. What is asserted here is the property that
    /// matters: every one of them is refused *before any marker is written*, so
    /// neither node is left in the one-way pending state.
    #[test]
    fn prepare_refuses_states_apply_could_never_satisfy() -> Result<()> {
        for (name, sql) in [
            (
                "legacy-version",
                "UPDATE node_maintenance_format SET version=2 WHERE id=1",
            ),
            (
                "legacy-root",
                "CREATE TABLE node_compaction_root(id INTEGER PRIMARY KEY CHECK(id=1),base TEXT NOT NULL)",
            ),
            (
                "legacy-history",
                "CREATE TABLE node_compaction_history(sequence INTEGER PRIMARY KEY,plan TEXT NOT NULL,digest TEXT NOT NULL)",
            ),
            (
                "certificates-without-format",
                "CREATE TABLE node_compaction_certificates(sequence INTEGER PRIMARY KEY,record TEXT NOT NULL)",
            ),
        ] {
            let mut fixture = lifecycle(name)?;
            fixture.pair.s.connection(|c| {
                c.execute_batch(sql)?;
                Ok(())
            })?;
            assert!(fixture.prepare().is_err(), "{name} was prepared");
            // Neither node was marked, so neither is stuck in pending state.
            for node in [&fixture.pair.p, &fixture.pair.s] {
                assert!(
                    node.connection(|c| Ok(!pending_present(c)?))?,
                    "{name} left a marker"
                );
            }
            assert!(fixture.pair.p.checkpoint().is_ok());
        }
        // The real check, driven on a scratch database that carries exactly the
        // durable shapes it is meant to refuse.
        let scratch = Connection::open_in_memory()?;
        scratch.execute_batch(
            "CREATE TABLE node_maintenance_format(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
             INSERT INTO node_maintenance_format VALUES(1,1);
             CREATE TABLE node_publication_pins(pin TEXT PRIMARY KEY NOT NULL,digest TEXT NOT NULL);",
        )?;
        // A clean version-1 node is appliable.
        require_appliable(&scratch)?;
        // A pin is refused.
        scratch.execute("INSERT INTO node_publication_pins VALUES('t','d')", [])?;
        refused(
            require_appliable(&scratch),
            "snapshot publication is pinned",
        );
        scratch.execute("DELETE FROM node_publication_pins", [])?;
        require_appliable(&scratch)?;
        // Legacy compaction tables without certificates are refused.
        scratch.execute_batch(
            "CREATE TABLE node_compaction_root(id INTEGER PRIMARY KEY CHECK(id=1),base TEXT NOT NULL)",
        )?;
        refused(
            require_appliable(&scratch),
            "requires a node without legacy compaction",
        );
        scratch.execute_batch("DROP TABLE node_compaction_root")?;
        scratch.execute_batch(
            "CREATE TABLE node_compaction_history(sequence INTEGER PRIMARY KEY,plan TEXT NOT NULL,digest TEXT NOT NULL)",
        )?;
        refused(
            require_appliable(&scratch),
            "requires a node without legacy compaction",
        );
        scratch.execute_batch("DROP TABLE node_compaction_history")?;
        // Maintenance version 2 (legacy compaction) is refused.
        scratch.execute(
            "UPDATE node_maintenance_format SET version=2 WHERE id=1",
            [],
        )?;
        refused(
            require_appliable(&scratch),
            "requires a node without legacy compaction",
        );
        // Certificates present require the certified format.
        scratch.execute_batch(
            "CREATE TABLE node_compaction_certificates(sequence INTEGER PRIMARY KEY,record TEXT NOT NULL)",
        )?;
        refused(
            require_appliable(&scratch),
            "requires certified maintenance format",
        );
        scratch.execute(
            "UPDATE node_maintenance_format SET version=3 WHERE id=1",
            [],
        )?;
        require_appliable(&scratch)?;
        Ok(())
    }

    /// Format-1 progress rows are byte-identical to what the pre-abort code
    /// wrote: `abort` is skipped entirely when absent.
    #[test]
    fn format_one_progress_rows_are_byte_identical() -> Result<()> {
        let pair = support::certified_pair("golden", [68; 32], "golden")?;
        let prepared = Prepared {
            format: 1,
            phase: "prepared".into(),
            plan: pair.plan.clone(),
            request: pair.request.clone(),
            token: pair.token.clone(),
            decision: None,
            completion: None,
            abort: None,
        };
        let json = serde_json::to_string(&prepared)?;
        assert!(
            !json.contains("abort"),
            "format 1 row mentions abort: {json}"
        );
        // The stored shape is exactly the seven historical fields.
        let value: serde_json::Value = serde_json::from_str(&json)?;
        let mut keys: Vec<&str> = value
            .as_object()
            .ok_or("progress is not an object")?
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "completion",
                "decision",
                "format",
                "phase",
                "plan",
                "request",
                "token"
            ]
        );
        // And it still round-trips through the format-2 struct.
        assert_eq!(serde_json::from_str::<Prepared>(&json)?, prepared);
        Ok(())
    }

    /// `prepare_pair` with the roles swapped is refused, and nothing is marked.
    #[test]
    fn prepare_refuses_swapped_roles() -> Result<()> {
        let mut fixture = lifecycle("swapped-roles")?;
        let Lifecycle { pair, .. } = &mut fixture;
        refused(
            prepare_pair(
                &mut pair.s,
                &mut pair.p,
                &pair.plan,
                &pair.request,
                &pair.token,
                15,
                &pair.trust,
            ),
            "pending pair mismatch",
        );
        for node in [&fixture.pair.p, &fixture.pair.s] {
            assert!(node.connection(|c| Ok(!pending_present(c)?))?);
        }
        Ok(())
    }

    /// L3 and M2: a node without pending maintenance is a typed error, and a
    /// pending node can be inspected read-only without knowing the request.
    #[test]
    fn peek_reports_the_durable_phase_and_role_without_the_request() -> Result<()> {
        let mut fixture = lifecycle("peek")?;
        let identity = fixture.pair.p.identity().clone();
        let primary_path = fixture.pair.dir.path().join("candidate1");
        let secondary_path = fixture.pair.dir.path().join("survivor");

        // A node that never prepared gives the typed non-pending error.
        let plain = fixture.pair.dir.path().join("never-prepared");
        drop(Node::open(
            &plain,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
        )?);
        refused(
            peek_pending(&plain, &identity, "fixture"),
            "node has no pending certified maintenance",
        );
        fixture.prepare()?;

        // Release every lock but keep the directory alive, the way a restart
        // leaves the files behind.
        let Lifecycle { pair, journal, .. } = fixture;
        let support::CertifiedPair {
            dir,
            p,
            s,
            request,
            trust,
            ..
        } = pair;
        drop(p);
        drop(s);
        drop(journal);

        let summary = peek_pending(&primary_path, &identity, "fixture")?;
        assert_eq!(summary.role, Role::Primary);
        assert_eq!(summary.phase, "prepared");
        assert_eq!(summary.request, request);
        assert_eq!(
            peek_pending(&secondary_path, &identity, "fixture")?.role,
            Role::Secondary
        );
        // The request read back is exactly what the restricted handle needs, so
        // an operator can resume without having kept it.
        let handle = PendingMaintenanceHandle::open_existing(
            &primary_path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
            &summary.request,
            &trust,
        )?;
        assert_eq!(handle.inspect().role, Role::Primary);
        drop(handle);
        // A foreign identity is refused even though the file is pending.
        let mut other = identity.clone();
        other.epoch += 1;
        refused(
            peek_pending(&primary_path, &other, "fixture"),
            "pending marker mismatch",
        );
        drop(dir);
        Ok(())
    }

    /// M3: a symlinked lock file is refused by every opener.
    #[test]
    fn symlinked_node_lock_is_refused_by_every_opener() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let identity = stock_entry().batch.identity;
        let path = dir.path().join("node");
        let node = Node::open(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
        )?;
        drop(node);
        let lock = path.with_extension("node-lock");
        let decoy = dir.path().join("decoy");
        std::fs::write(&decoy, b"")?;
        std::fs::remove_file(&lock)?;
        std::os::unix::fs::symlink(&decoy, &lock)?;

        refused(
            Node::<StockSchema>::open(
                &path,
                Role::Primary,
                identity.clone(),
                "fixture",
                StockSchema,
            ),
            "node lock is not a regular file",
        );
        refused(
            peek_pending(&path, &identity, "fixture"),
            "node lock is not a regular file",
        );
        std::fs::remove_file(&lock)?;
        Node::<StockSchema>::open(&path, Role::Primary, identity, "fixture", StockSchema)?;
        Ok(())
    }

    /// H2: the completion id is derived, stable across retries, and different
    /// for different requests.
    #[test]
    fn completion_ids_are_derived_and_stable() -> Result<()> {
        let first = support::certified_pair("derived-a", [53; 32], "lifecycle")?;
        let a = completion_id(&first.request, [7; 32], [true; 2])?;
        assert_eq!(a, completion_id(&first.request, [7; 32], [true; 2])?);
        let mut other = first.request.clone();
        other.id = [54; 32];
        assert_ne!(a, completion_id(&other, [7; 32], [true; 2])?);
        assert_ne!(a, completion_id(&first.request, [8; 32], [true; 2])?);
        assert_ne!(a, completion_id(&first.request, [7; 32], [true, false])?);
        Ok(())
    }

    /// H1 plus one assertion per phase boundary: every out-of-order call names
    /// the phase it refuses, and finalization is restartable per node.
    #[test]
    fn phase_boundaries_are_typed_and_finalization_is_restartable() -> Result<()> {
        let mut fixture = lifecycle("phases")?;
        fixture.prepare()?;
        let identity = fixture.pair.p.identity().clone();
        let primary_path = fixture.pair.dir.path().join("candidate1");
        let secondary_path = fixture.pair.dir.path().join("survivor");
        let Lifecycle {
            pair,
            journal,
            authority,
        } = fixture;
        let support::CertifiedPair {
            dir,
            p,
            s,
            request,
            trust,
            ..
        } = pair;
        drop(p);
        drop(s);

        let open = |path: &Path, role: Role| {
            PendingMaintenanceHandle::open_existing(
                path,
                role,
                identity.clone(),
                "fixture",
                StockSchema,
                &request,
                &trust,
            )
        };
        let mut h = open(&primary_path, Role::Primary)?;
        let mut hs = open(&secondary_path, Role::Secondary)?;

        // prepared: nothing downstream of the decision may run yet.
        refused(
            record_decided(&mut h, &journal, &trust, &authority),
            "transition missing",
        );
        refused(
            apply_decided(&mut h, &journal, &trust, &authority),
            "invalid pending apply transition",
        );
        refused(
            acknowledge_applied(&h, &journal, &trust, &authority),
            "pending node is not applied",
        );
        refused(
            record_complete(&mut h, &journal, &trust, &authority),
            "transition missing",
        );
        refused(
            finalize_node(&mut h, &journal, &trust, &authority),
            "pending node is not complete",
        );
        refused(
            complete_authority(&h, &hs, &journal, &trust, &authority),
            "pending completion pair mismatch",
        );

        // decided: apply is now legal, acknowledge still is not.
        decide_prepared(&h, &hs, &journal, 15, &trust, &authority)?;
        record_decided(&mut h, &journal, &trust, &authority)?;
        record_decided(&mut hs, &journal, &trust, &authority)?;
        refused(
            acknowledge_applied(&h, &journal, &trust, &authority),
            "pending node is not applied",
        );
        refused(
            finalize_node(&mut h, &journal, &trust, &authority),
            "pending node is not complete",
        );

        // applied: acknowledgement opens, completion needs both nodes.
        apply_decided(&mut h, &journal, &trust, &authority)?;
        apply_decided(&mut hs, &journal, &trust, &authority)?;
        refused(
            record_complete(&mut h, &journal, &trust, &authority),
            "transition acknowledgements incomplete",
        );
        refused(
            finalize_node(&mut h, &journal, &trust, &authority),
            "pending node is not complete",
        );

        // acked-one: completion at the authority is still refused.
        acknowledge_applied(&h, &journal, &trust, &authority)?;
        refused(
            complete_authority(&h, &hs, &journal, &trust, &authority),
            "acknowledgements incomplete",
        );
        // acked-both, then completed.
        acknowledge_applied(&hs, &journal, &trust, &authority)?;
        complete_authority(&h, &hs, &journal, &trust, &authority)?;
        refused(
            finalize_node(&mut h, &journal, &trust, &authority),
            "pending node is not complete",
        );

        // recorded-complete on one node only, then a crash-equivalent restart.
        record_complete(&mut h, &journal, &trust, &authority)?;
        record_complete(&mut hs, &journal, &trust, &authority)?;
        finalize_node(&mut hs, &journal, &trust, &authority)?;
        drop(h);
        drop(hs);

        // The secondary is finalised and is an ordinary node again; the primary
        // is still pending and finalises alone.
        refused(
            peek_pending(&secondary_path, &identity, "fixture"),
            "node has no pending certified maintenance",
        );
        assert_eq!(
            peek_pending(&primary_path, &identity, "fixture")?.phase,
            "complete"
        );
        let mut h = open(&primary_path, Role::Primary)?;
        finalize_node(&mut h, &journal, &trust, &authority)?;
        // Repeating on the same handle is a clean no-op, and reopening a
        // finalised node is the typed non-pending error, never a missing table.
        finalize_node(&mut h, &journal, &trust, &authority)?;
        drop(h);
        refused(
            open(&primary_path, Role::Primary),
            "node has no pending certified maintenance",
        );
        refused(
            peek_pending(&primary_path, &identity, "fixture"),
            "node has no pending certified maintenance",
        );
        drop(dir);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // S7: maintenance abort (C1) end to end.
    // -----------------------------------------------------------------------

    /// Everything an abort scenario needs, with both handles already open.
    struct Aborting {
        dir: tempfile::TempDir,
        identity: Identity<SchemaId>,
        request: crate::recovery::transition::Request,
        trust: crate::recovery::transition::TrustStore,
        key: ring::signature::EcdsaKeyPair,
        journal: crate::recovery::transition::Journal,
        authority: Authority,
        primary_path: std::path::PathBuf,
        secondary_path: std::path::PathBuf,
        never: (crate::recovery::transition::MaintenanceAbort, String),
        decided: (crate::recovery::transition::MaintenanceAbort, String),
    }

    impl Aborting {
        fn open(&self, role: Role) -> Result<PendingMaintenanceHandle<StockSchema>> {
            PendingMaintenanceHandle::open_existing(
                match role {
                    Role::Primary => &self.primary_path,
                    Role::Secondary => &self.secondary_path,
                },
                role,
                self.identity.clone(),
                "fixture",
                StockSchema,
                &self.request,
                &self.trust,
            )
        }
        fn handles(
            &self,
        ) -> Result<(
            PendingMaintenanceHandle<StockSchema>,
            PendingMaintenanceHandle<StockSchema>,
        )> {
            Ok((self.open(Role::Primary)?, self.open(Role::Secondary)?))
        }
        fn abort(&self, decided: bool) -> crate::recovery::transition::MaintenanceAbort {
            if decided {
                self.decided.0.clone()
            } else {
                self.never.0.clone()
            }
        }
        fn token(&self, decided: bool) -> String {
            if decided {
                self.decided.1.clone()
            } else {
                self.never.1.clone()
            }
        }
        /// Is this node still pending? Once the abort finished it is an
        /// ordinary node again and the sequence has converged.
        fn pending(&self, role: Role) -> Result<bool> {
            let path = match role {
                Role::Primary => &self.primary_path,
                Role::Secondary => &self.secondary_path,
            };
            let db = Vesta::open_read_only_with_passphrase(path, "fixture")?;
            Ok(db.with_connection(|c| {
                c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='node_pending_certified_maintenance')",
                    [],
                    |r| r.get(0),
                )
            })?)
        }
        /// Run the whole sequence from the top; every earlier step converges.
        /// A node that is no longer pending has already converged.
        fn run(&self, decided: bool) -> Result<()> {
            if !self.pending(Role::Primary)? && !self.pending(Role::Secondary)? {
                self.journal
                    .fetch_abort(&self.request, &self.trust.as_trust(), &self.authority)?;
                return Ok(());
            }
            let abort = self.abort(decided);
            let token = self.token(decided);
            let (mut h, mut hs) = self.handles()?;
            if decided && h.prepared.phase == "prepared" {
                decide_prepared(&h, &hs, &self.journal, 15, &self.trust, &self.authority)?;
                record_decided(&mut h, &self.journal, &self.trust, &self.authority)?;
                record_decided(&mut hs, &self.journal, &self.trust, &self.authority)?;
            }
            begin_abort(&mut h, &abort, &token, 15, &self.trust)?;
            begin_abort(&mut hs, &abort, &token, 15, &self.trust)?;
            abort_authority(
                &h,
                &hs,
                &self.journal,
                &abort,
                &token,
                15,
                &self.trust,
                &self.authority,
            )?;
            abort_pair(&mut h, &mut hs, &self.journal, &self.trust, &self.authority)?;
            Ok(())
        }
    }

    fn aborting(seed: &str) -> Result<Aborting> {
        let pair = support::certified_pair(seed, [61; 32], "abort")?;
        let journal = crate::recovery::transition::Journal::create(
            &pair.dir.path().join("abort-journal"),
            "journal-fixture",
            support::journal_scope(&pair.request),
        )?;
        let support::CertifiedPair {
            dir,
            mut p,
            mut s,
            plan,
            request,
            token,
            trust,
            key,
        } = pair;
        prepare_pair(&mut p, &mut s, &plan, &request, &token, 15, &trust)?;
        let identity = p.identity().clone();
        let primary_path = dir.path().join("candidate1");
        let secondary_path = dir.path().join("survivor");
        drop(p);
        drop(s);
        let request_for_aborts = request.clone();
        let revision = request.revision;
        let never = {
            let abort = support::abort_of(&request_for_aborts, 60, false, revision)?;
            let token = support::sign_abort(&key, &abort, (10, 20))?;
            (abort, token)
        };
        let decided = {
            let abort = support::abort_of(&request_for_aborts, 60, true, revision)?;
            let token = support::sign_abort(&key, &abort, (10, 20))?;
            (abort, token)
        };
        Ok(Aborting {
            dir,
            identity,
            request,
            trust,
            key,
            journal,
            authority: Authority {
                current: Cell::new(true),
                revoke_on_check: Cell::new(false),
            },
            primary_path,
            secondary_path,
            never,
            decided,
        })
    }

    /// The pair is ordinary again: it opens, writes, and the secondary
    /// re-confirms its checkpoint (readiness is deliberately not restored).
    fn assert_pair_usable(f: &Aborting) -> Result<(u64, Node<StockSchema>, Node<StockSchema>)> {
        refused(
            peek_pending(&f.primary_path, &f.identity, "fixture"),
            "node has no pending certified maintenance",
        );
        refused(
            peek_pending(&f.secondary_path, &f.identity, "fixture"),
            "node has no pending certified maintenance",
        );
        let mut p = Node::open(
            &f.primary_path,
            Role::Primary,
            f.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        let mut s = Node::open(
            &f.secondary_path,
            Role::Secondary,
            f.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        let before = p.checkpoint()?.sequence;
        let mut batch = stock_entry().batch;
        batch.operation_id = format!("after-abort-{before}");
        let result = commit(&mut p, &mut s, batch)?;
        assert_eq!(result.sequence, before + 1);
        assert_eq!(p.checkpoint()?, s.checkpoint()?);
        Ok((before + 1, p, s))
    }

    /// (+) The scenario this mechanism exists for: the token expires while the
    /// pair is PREPARED, so the transition can never be decided.
    #[test]
    fn expired_token_prepared_pair_aborts_and_becomes_ordinary_again() -> Result<()> {
        let f = aborting("abort-never-decided")?;
        // The token is only valid in [10, 20); the decision now fails for ever.
        let (h, hs) = f.handles()?;
        refused(
            decide_prepared(&h, &hs, &f.journal, 999, &f.trust, &f.authority),
            "time window",
        );
        drop(h);
        drop(hs);

        f.run(false)?;
        // Exact retry of the whole sequence converges.
        f.run(false)?;
        let (sequence, p, s) = assert_pair_usable(&f)?;
        assert!(sequence > 0);
        drop(p);
        drop(s);
        drop(f);
        Ok(())
    }

    /// (+) Same for a transition that was decided but never applied.
    #[test]
    fn decided_but_unapplied_pair_aborts_and_becomes_ordinary_again() -> Result<()> {
        let f = aborting("abort-decided")?;
        f.run(true)?;
        f.run(true)?;
        let (_, p, s) = assert_pair_usable(&f)?;
        drop(p);
        drop(s);
        drop(f);
        Ok(())
    }

    /// (+) After the abort the pair can run a completely fresh certified cycle
    /// at the next revision, and the aborted one can never be re-decided.
    #[test]
    fn aborted_pair_completes_a_fresh_certified_cycle() -> Result<()> {
        let f = aborting("abort-then-fresh")?;
        f.run(false)?;
        let (_, mut p, mut s) = assert_pair_usable(&f)?;

        // The aborted revision is consumed; a new request takes the next one.
        let old = p
            .plan_compaction()?
            .publication
            .ok_or("publication missing")?;
        let old_s = s
            .plan_compaction()?
            .publication
            .ok_or("publication missing")?;
        p.rotate_snapshot(&old)?;
        s.rotate_snapshot(&old_s)?;
        let plan = compaction::PairPlan {
            id: [62; 32],
            primary: p.plan_compaction()?,
            secondary: s.plan_compaction()?,
        };
        plan.validate_certified()?;
        let mut fresh = f.request.clone();
        fresh.id = [63; 32];
        fresh.revision = f.request.revision + 1;
        fresh.participants = [
            crate::recovery::transition::Participant {
                generation: p.connection(checkpoint::generation)?,
                old_base: plan
                    .primary
                    .head
                    .base
                    .as_ref()
                    .map(support::cut)
                    .transpose()?,
                target: support::cut(&plan.primary.checkpoint)?,
                plan: support::digest_of(&plan)?,
                publication: support::digest_of(
                    plan.primary.publication.as_ref().ok_or("publication")?,
                )?,
                ..f.request.participants[0].clone()
            },
            crate::recovery::transition::Participant {
                generation: s.connection(checkpoint::generation)?,
                old_base: plan
                    .secondary
                    .head
                    .base
                    .as_ref()
                    .map(support::cut)
                    .transpose()?,
                target: support::cut(&plan.secondary.checkpoint)?,
                plan: support::digest_of(&plan)?,
                publication: support::digest_of(
                    plan.secondary.publication.as_ref().ok_or("publication")?,
                )?,
                ..f.request.participants[1].clone()
            },
        ];
        let token = super::super::certified::tests::sign(&f.key, &fresh)?;
        prepare_pair(&mut p, &mut s, &plan, &fresh, &token, 15, &f.trust)?;
        drop(p);
        drop(s);
        let mut h = PendingMaintenanceHandle::open_existing(
            &f.primary_path,
            Role::Primary,
            f.identity.clone(),
            "fixture",
            StockSchema,
            &fresh,
            &f.trust,
        )?;
        let mut hs = PendingMaintenanceHandle::open_existing(
            &f.secondary_path,
            Role::Secondary,
            f.identity.clone(),
            "fixture",
            StockSchema,
            &fresh,
            &f.trust,
        )?;
        decide_prepared(&h, &hs, &f.journal, 15, &f.trust, &f.authority)?;
        record_decided(&mut h, &f.journal, &f.trust, &f.authority)?;
        record_decided(&mut hs, &f.journal, &f.trust, &f.authority)?;
        apply_decided(&mut h, &f.journal, &f.trust, &f.authority)?;
        apply_decided(&mut hs, &f.journal, &f.trust, &f.authority)?;
        acknowledge_applied(&h, &f.journal, &f.trust, &f.authority)?;
        acknowledge_applied(&hs, &f.journal, &f.trust, &f.authority)?;
        complete_authority(&h, &hs, &f.journal, &f.trust, &f.authority)?;
        record_complete(&mut h, &f.journal, &f.trust, &f.authority)?;
        record_complete(&mut hs, &f.journal, &f.trust, &f.authority)?;
        finalize_pair(&mut h, &mut hs, &f.journal, &f.trust, &f.authority)?;
        drop(h);
        drop(hs);
        // The previously aborted request can never be decided again.
        drop(f);
        Ok(())
    }

    /// (−) Everything the one-way door must refuse.
    #[test]
    fn abort_is_one_way_and_binds_to_its_request() -> Result<()> {
        let f = aborting("abort-negatives")?;
        let abort = f.abort(false);
        let token = f.token(false);

        // An abort for another request or revision is refused.
        let mut foreign = f.request.clone();
        foreign.id = [64; 32];
        let other = support::abort_of(&foreign, 65, false, foreign.revision)?;
        let other_token = support::sign_abort(&f.key, &other, (10, 20))?;
        let (mut h, mut hs) = f.handles()?;
        refused(
            begin_abort(&mut h, &other, &other_token, 15, &f.trust),
            "pending abort binding mismatch",
        );
        // An expired or foreign token never starts an abort.
        refused(
            begin_abort(&mut h, &abort, &token, 999, &f.trust),
            "time window",
        );
        let attacker = super::super::certified::tests::signer()?.0;
        let forged = support::sign_abort(&attacker, &abort, (10, 20))?;
        refused(
            begin_abort(&mut h, &abort, &forged, 15, &f.trust),
            "signature",
        );
        // `decided: true` while the node is only prepared is refused.
        let wrong_phase = support::abort_of(&f.request, 66, true, f.request.revision)?;
        let wrong_phase_token = support::sign_abort(&f.key, &wrong_phase, (10, 20))?;
        refused(
            begin_abort(&mut h, &wrong_phase, &wrong_phase_token, 15, &f.trust),
            "invalid pending abort transition",
        );

        // One node aborting is not evidence: the journal records nothing.
        begin_abort(&mut h, &abort, &token, 15, &f.trust)?;
        refused(
            abort_authority(
                &h,
                &hs,
                &f.journal,
                &abort,
                &token,
                15,
                &f.trust,
                &f.authority,
            ),
            "pending node is not aborting",
        );
        refused(
            f.journal
                .fetch_abort(&f.request, &f.trust.as_trust(), &f.authority),
            "maintenance abort missing",
        );
        // `finish_abort` before the journal abort is refused.
        refused(
            finish_abort(&mut h, &f.journal, &f.trust, &f.authority),
            "maintenance abort missing",
        );

        // From `aborting` no lifecycle call may roll forward.
        refused(
            record_decided(&mut h, &f.journal, &f.trust, &f.authority),
            "invalid pending decision transition",
        );
        refused(
            apply_decided(&mut h, &f.journal, &f.trust, &f.authority),
            "invalid pending apply transition",
        );
        refused(
            acknowledge_applied(&h, &f.journal, &f.trust, &f.authority),
            "pending node is not applied",
        );
        refused(
            record_complete(&mut h, &f.journal, &f.trust, &f.authority),
            "transition missing",
        );
        refused(
            finalize_node(&mut h, &f.journal, &f.trust, &f.authority),
            "pending node is not complete",
        );
        // A different abort on an already aborting node is a conflict, and an
        // abort for another request is still a binding mismatch.
        refused(
            begin_abort(&mut h, &wrong_phase, &wrong_phase_token, 15, &f.trust),
            "pending abort conflict",
        );
        refused(
            begin_abort(&mut h, &other, &other_token, 15, &f.trust),
            "pending abort binding mismatch",
        );
        let same_request_other_id = support::abort_of(&f.request, 67, false, f.request.revision)?;
        let same_request_other_token =
            support::sign_abort(&f.key, &same_request_other_id, (10, 20))?;
        refused(
            begin_abort(
                &mut h,
                &same_request_other_id,
                &same_request_other_token,
                15,
                &f.trust,
            ),
            "pending abort conflict",
        );
        // Exact retry on an aborting node is a no-op.
        begin_abort(&mut h, &abort, &token, 15, &f.trust)?;

        // With both aborting the authority records it, and only then does
        // `finish_abort` succeed.
        begin_abort(&mut hs, &abort, &token, 15, &f.trust)?;
        abort_authority(
            &h,
            &hs,
            &f.journal,
            &abort,
            &token,
            15,
            &f.trust,
            &f.authority,
        )?;
        abort_pair(&mut h, &mut hs, &f.journal, &f.trust, &f.authority)?;
        drop(h);
        drop(hs);
        assert_pair_usable(&f)?;
        Ok(())
    }

    /// (−) An applied node can never be aborted.
    #[test]
    fn abort_is_refused_after_apply() -> Result<()> {
        let f = aborting("abort-after-apply")?;
        let (mut h, mut hs) = f.handles()?;
        decide_prepared(&h, &hs, &f.journal, 15, &f.trust, &f.authority)?;
        record_decided(&mut h, &f.journal, &f.trust, &f.authority)?;
        record_decided(&mut hs, &f.journal, &f.trust, &f.authority)?;
        apply_decided(&mut h, &f.journal, &f.trust, &f.authority)?;
        let abort = f.abort(true);
        let token = f.token(true);
        refused(
            begin_abort(&mut h, &abort, &token, 15, &f.trust),
            "invalid pending abort transition",
        );
        // The still-decided peer may begin, but the authority refuses because
        // the applied node is not aborting.
        begin_abort(&mut hs, &abort, &token, 15, &f.trust)?;
        refused(
            abort_authority(
                &h,
                &hs,
                &f.journal,
                &abort,
                &token,
                15,
                &f.trust,
                &f.authority,
            ),
            "pending node is not aborting",
        );
        Ok(())
    }

    /// (−) The default policy denies every abort.
    #[test]
    fn default_policy_refuses_to_record_an_abort() -> Result<()> {
        struct Bare;
        impl crate::recovery::transition::Policy for Bare {
            fn continuity(
                &self,
                _: &crate::recovery::transition::JournalScope,
                _: &crate::recovery::transition::Request,
            ) -> terrapi_vesta_recovery::Result<()> {
                Ok(())
            }
            fn prepared(
                &self,
                _: &crate::recovery::transition::JournalScope,
                _: &crate::recovery::transition::Request,
                _: &crate::recovery::transition::Participant,
            ) -> terrapi_vesta_recovery::Result<()> {
                Ok(())
            }
            fn applied(
                &self,
                _: &crate::recovery::transition::JournalScope,
                _: &crate::recovery::transition::CommittedTransition,
                _: &crate::recovery::transition::Participant,
            ) -> terrapi_vesta_recovery::Result<()> {
                Ok(())
            }
        }
        let f = aborting("abort-default-deny")?;
        let abort = f.abort(false);
        let token = f.token(false);
        let (mut h, mut hs) = f.handles()?;
        begin_abort(&mut h, &abort, &token, 15, &f.trust)?;
        begin_abort(&mut hs, &abort, &token, 15, &f.trust)?;
        refused(
            abort_authority(&h, &hs, &f.journal, &abort, &token, 15, &f.trust, &Bare),
            "maintenance abort evidence missing",
        );
        Ok(())
    }

    /// (crash) Drop everything at each boundary, reopen from disk and replay
    /// the whole sequence from the top.
    #[test]
    fn abort_survives_a_crash_at_every_boundary() -> Result<()> {
        let f = aborting("abort-crash")?;
        let abort = f.abort(false);
        let token = f.token(false);

        // After the first begin_abort only.
        {
            let mut h = f.open(Role::Primary)?;
            begin_abort(&mut h, &abort, &token, 15, &f.trust)?;
        }
        assert_eq!(
            peek_pending(&f.primary_path, &f.identity, "fixture")?.phase,
            "aborting"
        );
        assert_eq!(
            peek_pending(&f.secondary_path, &f.identity, "fixture")?.phase,
            "prepared"
        );
        f.run(false)?;

        // After both begin_abort, before the journal abort: the previous run
        // already recorded it, so re-running is the converging retry path.
        f.run(false)?;
        assert_eq!(
            f.journal
                .fetch_abort(&f.request, &f.trust.as_trust(), &f.authority)?
                .abort()
                .id,
            abort.id
        );
        // Both nodes are ordinary again and stay that way across the replays.
        assert_pair_usable(&f)?;
        Ok(())
    }
}
