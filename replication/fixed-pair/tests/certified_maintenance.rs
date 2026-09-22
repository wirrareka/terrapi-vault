//! One full certified maintenance cycle and one maintenance abort, driven only
//! through the public `experimental-recovery` API. This is the proof that the
//! public surface of `typed::maintenance::pending` is sufficient on its own:
//! nothing here reaches a connection, a crate-internal helper or a timestamp.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use terrapi_vesta_replication::{
    commit, recover,
    recovery::{
        decision,
        grant::{Context, Profile, Reservation},
        model::{Baseline, Plan},
        transition,
    },
    schema::{RequestSchema, Schema, SchemaId},
    typed::{
        maintenance::{
            compaction::PairPlan,
            pending::{
                abort_authority, abort_pair, acknowledge_applied, apply_decided, begin_abort,
                complete_authority, decide_prepared, finalize_node, peek_pending, prepare_pair,
                record_complete, record_decided, MaintenanceAuthorities, PendingMaintenanceHandle,
            },
            CompactionPlan,
        },
        recovery::{activate_pair, complete_pair},
        CertifiedAuthority, Node, Prefix, Request,
    },
    Batch, Identity, Result, Role,
};

const PASS: &str = "certified-maintenance";

// ---------------------------------------------------------------------------
// A minimal application schema.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Change(String);
#[derive(Clone, Copy)]
struct Adapter;

impl Schema for Adapter {
    type Change = Change;
    type View = Vec<String>;
    fn identity(&self) -> SchemaId {
        SchemaId {
            name: "certified.fixture".into(),
            version: 1,
        }
    }
    fn tables(&self) -> &'static [&'static str] {
        &["certified_values"]
    }
    fn initialize(&self, c: &Connection) -> Result<()> {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS certified_values(value TEXT PRIMARY KEY NOT NULL)",
        )?;
        Ok(())
    }
    fn execute(&self, c: &Connection, changes: &[Change]) -> Result<()> {
        for change in changes {
            c.execute(
                "INSERT OR REPLACE INTO certified_values VALUES(?1)",
                [&change.0],
            )?;
        }
        Ok(())
    }
    fn view(&self, c: &Connection) -> Result<Self::View> {
        Ok(
            c.prepare("SELECT value FROM certified_values ORDER BY value")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?,
        )
    }
}
impl RequestSchema for Adapter {
    const FINGERPRINT_VERSION: u32 = 1;
    fn request_fingerprint(&self, changes: &[Change]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"certified.fixture.v1\0");
        for change in changes {
            h.update((change.0.len() as u64).to_be_bytes());
            h.update(change.0.as_bytes());
        }
        h.finalize().into()
    }
}

fn identity() -> Identity<SchemaId> {
    Identity {
        cluster: "certified".into(),
        tenant: "maintenance".into(),
        epoch: 1,
        schema: Adapter.identity(),
    }
}

fn batch(operation: &str) -> Request<Adapter> {
    Batch {
        identity: identity(),
        operation_id: operation.into(),
        changes: vec![Change(operation.into())],
    }
}

fn digest_of<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).into())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock after the epoch")
        .as_secs()
}

fn signer() -> Result<(EcdsaKeyPair, Vec<u8>)> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| "key generation")?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|_| "key parsing")?;
    let public = key.public_key().as_ref().to_vec();
    Ok((key, public))
}

fn jwt(key: &EcdsaKeyPair, header: serde_json::Value, claims: serde_json::Value) -> Result<String> {
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header)?),
        B64.encode(serde_json::to_vec(&claims)?)
    );
    let signature = key
        .sign(&SystemRandom::new(), input.as_bytes())
        .map_err(|_| "signing")?;
    Ok(format!("{input}.{}", B64.encode(signature.as_ref())))
}

// ---------------------------------------------------------------------------
// Member recovery authority (decision journal): only used to build the
// recovered pair that certified maintenance requires.
// ---------------------------------------------------------------------------

struct RecoveryAuthority {
    key: EcdsaKeyPair,
    scope: decision::Scope,
    request: decision::Request,
}

impl RecoveryAuthority {
    fn token(&self) -> Result<String> {
        jwt(
            &self.key,
            serde_json::json!({"alg":"ES256","kid":"fixture","typ":self.scope.profile.token_type}),
            serde_json::json!({"version":1,"iss":self.scope.profile.issuer,
                "aud":self.scope.profile.audience,"action":"replace_primary",
                "install_id":self.scope.install,"region":self.scope.region,
                "grant_id":([8;32]),"iat":100,"nbf":100,"exp":200,
                "plan":self.request.plan,"fencing_ref":([7;32])}),
        )
    }
}

impl decision::Policy for RecoveryAuthority {
    fn continuity(&self, _: &decision::Scope) -> Result<()> {
        Ok(())
    }
    fn context(&self, _: &decision::Scope, request: &decision::Request) -> Result<Context> {
        assert_eq!(request, &self.request);
        Ok(Context {
            profile: self.scope.profile.clone(),
            keys: vec![("fixture".into(), self.key.public_key().as_ref().to_vec())],
            now: 150,
            max_lifetime: 100,
            install_id: self.scope.install.clone(),
            region: self.scope.region.clone(),
            reservation: Some(Reservation {
                plan: request.plan.clone(),
                grant_id: [8; 32],
                fencing_ref: [7; 32],
            }),
            fencing_confirmed: true,
        })
    }
    fn prepared(&self, _: &decision::Scope, request: &decision::Request) -> Result<()> {
        assert_eq!(request, &self.request);
        Ok(())
    }
    fn applied(
        &self,
        _: &decision::Scope,
        _: &decision::CommittedDecision,
        member: &decision::Prepared,
    ) -> Result<()> {
        assert!(self.request.prepared.contains(member));
        Ok(())
    }
}

/// A primary/secondary pair produced by one completed member recovery, with a
/// frozen publication on each node: the only kind of pair certified
/// maintenance accepts.
fn recovered_pair(dir: &Path) -> Result<(Node<Adapter>, Node<Adapter>)> {
    let id = identity();
    let mut old = Node::open(
        dir.join("original"),
        Role::Primary,
        id.clone(),
        PASS,
        Adapter,
    )?;
    let mut s = Node::open(
        dir.join("survivor"),
        Role::Secondary,
        id.clone(),
        PASS,
        Adapter,
    )?;
    commit(&mut old, &mut s, batch("before-recovery"))?;
    drop(old);
    let plan = Plan {
        recovery_id: [5; 32],
        revision: 5,
        candidate: [3; 32],
        baseline: Baseline {
            scope: serde_json::to_string(&id)?,
            revision: 4,
            digest: [4; 32],
            old_primary: [1; 32],
            survivor: [2; 32],
            survivor_generation: s.journal_head()?.read_generation,
            checkpoint: s.recovery_checkpoint_digest()?,
        },
    };
    s.seal_recovery_source(&plan)?;
    let manifest = s.publish_recovery_snapshot()?;
    let mut p = Node::open(dir.join("candidate"), Role::Secondary, id, PASS, Adapter)?;
    p.begin_snapshot(&manifest)?;
    for n in 0..manifest.pages {
        p.receive_snapshot(&s.snapshot_page(&manifest, n)?)?;
    }
    p.finish_snapshot(&manifest)?;
    let request = decision::Request {
        id: [10; 32],
        prepared: [
            p.inspect_recovery(&plan, plan.candidate)?,
            s.inspect_recovery(&plan, plan.baseline.survivor)?,
        ],
        plan,
    };
    let (key, _) = signer()?;
    let authority = RecoveryAuthority {
        key,
        scope: decision::Scope {
            install: "certified-test".into(),
            region: "test".into(),
            profile: Profile {
                issuer: "fixture-authority".into(),
                audience: "fixture-recovery".into(),
                token_type: "fixture-recovery+jwt".into(),
            },
            baseline: request.plan.baseline.clone(),
        },
        request: request.clone(),
    };
    let journal =
        decision::Journal::create(&dir.join("recovery-journal"), PASS, authority.scope.clone())?;
    journal.decide(request.clone(), &authority.token()?, &authority)?;
    let committed = journal.fetch(&request, &authority)?;
    p.record_recovery_decision(&committed, request.plan.candidate)?;
    s.record_recovery_decision(&committed, request.plan.baseline.survivor)?;
    activate_pair(&mut p, &mut s, &journal, &request, &authority)?;
    complete_pair(&mut p, &mut s, &journal, &request, [12; 32], &authority)?;
    recover(&mut p, &mut s)?;
    assert_eq!(p.role(), Role::Primary);
    p.publish_snapshot()?;
    Ok((p, s))
}

// ---------------------------------------------------------------------------
// Certified maintenance authority (transition journal).
// ---------------------------------------------------------------------------

/// Test policy. A production policy must check the external authority's live
/// head/reservation in every hook; this one only records that it was asked.
struct MaintenancePolicy;

impl transition::Policy for MaintenancePolicy {
    fn continuity(
        &self,
        _: &transition::JournalScope,
        _: &transition::Request,
    ) -> terrapi_vesta_recovery::Result<()> {
        Ok(())
    }
    fn prepared(
        &self,
        _: &transition::JournalScope,
        _: &transition::Request,
        _: &transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        Ok(())
    }
    fn applied(
        &self,
        _: &transition::JournalScope,
        _: &transition::CommittedTransition,
        _: &transition::Participant,
    ) -> terrapi_vesta_recovery::Result<()> {
        Ok(())
    }
    fn abort_applicable(
        &self,
        _: &transition::JournalScope,
        _: &transition::MaintenanceAbort,
    ) -> terrapi_vesta_recovery::Result<()> {
        Ok(())
    }
}

/// The live certified authority a completed node needs in order to open.
struct LiveAuthority {
    journal: Mutex<transition::Journal>,
    trust: transition::TrustStore,
}

impl CertifiedAuthority for LiveAuthority {
    fn fetch_completed(
        &self,
        request: &transition::Request,
    ) -> terrapi_vesta_recovery::Result<transition::CompletedTransition> {
        self.journal
            .lock()
            .map_err(|_| "authority poisoned")?
            .fetch_completed(request, &self.trust.as_trust(), &MaintenancePolicy)
    }
    fn fetch_completed_revision(
        &self,
        request: &transition::Request,
    ) -> terrapi_vesta_recovery::Result<transition::HistoricalCompletedTransition> {
        self.journal
            .lock()
            .map_err(|_| "authority poisoned")?
            .fetch_completed_revision(request, &self.trust.as_trust(), &MaintenancePolicy)
    }
}

fn cut(prefix: &Prefix) -> Result<transition::Checkpoint> {
    Ok(transition::Checkpoint {
        sequence: prefix.sequence,
        digest: digest_of(prefix)?,
    })
}

fn participant(
    node: &Node<Adapter>,
    local: &CompactionPlan,
    plan: &PairPlan,
) -> Result<transition::Participant> {
    Ok(transition::Participant {
        member: node
            .recovery_member_identity()?
            .ok_or("member identity missing")?,
        generation: node.journal_head()?.read_generation,
        old_base: local.head.base.as_ref().map(cut).transpose()?,
        target: cut(&local.checkpoint)?,
        plan: digest_of(plan)?,
        publication: digest_of(local.publication.as_ref().ok_or("publication missing")?)?,
    })
}

struct Fixture {
    _dir: tempfile::TempDir,
    primary_path: PathBuf,
    secondary_path: PathBuf,
    plan: PairPlan,
    request: transition::Request,
    token: String,
    key: EcdsaKeyPair,
    trust: transition::TrustStore,
    journal: transition::Journal,
    p: Option<Node<Adapter>>,
    s: Option<Node<Adapter>>,
}

fn fixture() -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let (mut p, mut s) = recovered_pair(dir.path())?;
    p.upgrade_receipt_capacity()?;
    s.upgrade_receipt_capacity()?;
    p.enable_maintenance()?;
    s.enable_maintenance()?;
    let old_p = p
        .plan_compaction()?
        .publication
        .ok_or("primary publication missing")?;
    let old_s = s
        .plan_compaction()?
        .publication
        .ok_or("secondary publication missing")?;
    commit(&mut p, &mut s, batch("before-maintenance"))?;
    p.rotate_snapshot(&old_p)?;
    s.rotate_snapshot(&old_s)?;
    let plan = PairPlan {
        id: [51; 32],
        primary: p.plan_compaction()?,
        secondary: s.plan_compaction()?,
    };
    let request = transition::Request {
        format: 1,
        id: [42; 32],
        authority_id: [43; 32],
        revision: 1,
        install: "certified-test".into(),
        region: "test".into(),
        scope: digest_of(p.identity())?,
        schema: digest_of(&plan.primary.contract)?,
        membership: plan.primary.membership.ok_or("membership missing")?,
        source_anchor: cut(plan
            .primary
            .recovery_anchor
            .as_ref()
            .ok_or("anchor missing")?)?,
        participants: [
            participant(&p, &plan.primary, &plan)?,
            participant(&s, &plan.secondary, &plan)?,
        ],
    };
    let (key, public) = signer()?;
    let issued = now();
    let token = jwt(
        &key,
        serde_json::json!({"alg":"ES256","kid":"fixture","typ":transition::TOKEN_TYPE}),
        serde_json::json!({"version":1,"iss":"issuer","aud":"audience",
            "action":"compact_pair","certificate_id":([17u8;32]),
            "iat":issued - 60,"nbf":issued - 60,"exp":issued + 3600,
            "request":request,"request_digest":request.digest()?}),
    )?;
    let profile = Profile {
        issuer: "issuer".into(),
        audience: "audience".into(),
        token_type: transition::TOKEN_TYPE.into(),
    };
    let trust = transition::TrustStore {
        profile: profile.clone(),
        keys: vec![("fixture".into(), public)],
        max_lifetime: 7200,
    };
    let journal = transition::Journal::create(
        &dir.path().join("maintenance-journal"),
        PASS,
        transition::JournalScope {
            install: request.install.clone(),
            region: request.region.clone(),
            profile,
            scope: request.scope,
            schema: request.schema,
            membership: request.membership,
            source_anchor: request.source_anchor.clone(),
            authority_id: request.authority_id,
            initial_revision: request.revision,
        },
    )?;
    Ok(Fixture {
        primary_path: dir.path().join("candidate"),
        secondary_path: dir.path().join("survivor"),
        _dir: dir,
        plan,
        request,
        token,
        key,
        trust,
        journal,
        p: Some(p),
        s: Some(s),
    })
}

impl Fixture {
    /// PREPARE through the public API, then release the ordinary nodes: the
    /// files are from here on reachable only through restricted handles.
    fn prepare(&mut self) -> Result<()> {
        let (mut p, mut s) = (
            self.p.take().ok_or("primary taken")?,
            self.s.take().ok_or("secondary taken")?,
        );
        prepare_pair(
            &mut p,
            &mut s,
            &self.plan,
            &self.request,
            &self.token,
            &self.trust,
        )?;
        // Exact retry converges.
        prepare_pair(
            &mut p,
            &mut s,
            &self.plan,
            &self.request,
            &self.token,
            &self.trust,
        )?;
        drop(p);
        drop(s);
        // The one-way door is shut: ordinary open fails on both.
        assert!(Node::open(&self.primary_path, Role::Primary, identity(), PASS, Adapter).is_err());
        Ok(())
    }

    /// Reopen a pending node knowing only its path: the request is read back
    /// with `peek_pending`, the role comes from the durable marker.
    fn open(&self, path: &Path, expected: Role) -> Result<PendingMaintenanceHandle<Adapter>> {
        let summary = peek_pending(path, &identity(), PASS)?;
        assert_eq!(summary.role, expected);
        assert_eq!(summary.request, self.request);
        let handle = PendingMaintenanceHandle::open_existing_with_authority(
            path,
            identity(),
            PASS,
            Adapter,
            &summary.request,
            &self.trust,
            None,
        )?;
        assert_eq!(handle.inspect().role, expected);
        assert_eq!(handle.request(), &self.request);
        Ok(handle)
    }

    fn phase(&self, path: &Path) -> Result<String> {
        Ok(peek_pending(path, &identity(), PASS)?.phase)
    }
}

#[test]
fn full_certified_cycle_through_the_public_api() -> Result<()> {
    let mut f = fixture()?;
    f.prepare()?;
    let authorities = MaintenanceAuthorities::new(&f.journal, &f.trust, &MaintenancePolicy);
    {
        let mut hp = f.open(&f.primary_path, Role::Primary)?;
        let mut hs = f.open(&f.secondary_path, Role::Secondary)?;
        // Swapped handles are refused: the role is the nodes' own.
        assert!(decide_prepared(&hs, &hp, &authorities).is_err());
        decide_prepared(&hp, &hs, &authorities)?;
        for h in [&mut hp, &mut hs] {
            record_decided(h, &authorities)?;
            apply_decided(h, &authorities)?;
            acknowledge_applied(h, &authorities)?;
        }
        complete_authority(&hp, &hs, &authorities)?;
        complete_authority(&hp, &hs, &authorities)?;
        record_complete(&mut hp, &authorities)?;
        record_complete(&mut hs, &authorities)?;
        // Crash between the two finalizations: only the secondary finishes.
        finalize_node(&mut hs, &authorities)?;
    }
    assert_eq!(f.phase(&f.primary_path)?, "complete");
    assert!(peek_pending(&f.secondary_path, &identity(), PASS).is_err());
    {
        let mut hp = f.open(&f.primary_path, Role::Primary)?;
        finalize_node(&mut hp, &authorities)?;
        finalize_node(&mut hp, &authorities)?;
    }
    // Both nodes are ordinary again and open against the live certified
    // authority; the pair accepts writes on the compacted base.
    let live: Arc<dyn CertifiedAuthority> = Arc::new(LiveAuthority {
        journal: Mutex::new(f.journal),
        trust: f.trust.clone(),
    });
    let mut p = Node::open_with_completed_transition(
        &f.primary_path,
        Role::Primary,
        identity(),
        PASS,
        Adapter,
        f.trust.clone(),
        live.clone(),
    )?;
    let mut s = Node::open_with_completed_transition(
        &f.secondary_path,
        Role::Secondary,
        identity(),
        PASS,
        Adapter,
        f.trust.clone(),
        live,
    )?;
    let before = p.checkpoint()?.sequence;
    let written = commit(&mut p, &mut s, batch("after-maintenance"))?;
    assert_eq!(written.sequence, before + 1);
    assert_eq!(p.view()?, s.view()?);
    assert!(p.view()?.contains(&"before-maintenance".to_string()));
    Ok(())
}

#[test]
fn prepared_pair_aborts_through_the_public_api() -> Result<()> {
    let mut f = fixture()?;
    f.prepare()?;
    let abort = transition::MaintenanceAbort {
        format: 2,
        id: [60; 32],
        authority_id: f.request.authority_id,
        revision: f.request.revision,
        install: f.request.install.clone(),
        region: f.request.region.clone(),
        scope: f.request.scope,
        schema: f.request.schema,
        membership: f.request.membership,
        aborted_request: f.request.digest()?,
        aborted_request_id: f.request.id,
        aborted_revision: f.request.revision,
        decided: false,
        source_anchor: f.request.source_anchor.clone(),
    };
    let issued = now();
    let token = jwt(
        &f.key,
        serde_json::json!({"alg":"ES256","kid":"fixture","typ":transition::ABORT_TOKEN_TYPE}),
        serde_json::json!({"version":1,"iss":"issuer","aud":"audience",
            "action":"abort_compact_pair","certificate_id":([77u8;32]),
            "iat":issued - 60,"nbf":issued - 60,"exp":issued + 3600,
            "request":abort,"request_digest":abort.digest()?}),
    )?;
    let authorities = MaintenanceAuthorities::new(&f.journal, &f.trust, &MaintenancePolicy);
    {
        let mut hp = f.open(&f.primary_path, Role::Primary)?;
        let mut hs = f.open(&f.secondary_path, Role::Secondary)?;
        // The authority refuses the abort until both nodes are aborting.
        begin_abort(&mut hp, &abort, &token, &f.trust)?;
        assert!(abort_authority(&hp, &hs, &abort, &token, &authorities).is_err());
        begin_abort(&mut hs, &abort, &token, &f.trust)?;
        begin_abort(&mut hs, &abort, &token, &f.trust)?;
        // One-way: an aborting node can no longer be decided.
        assert!(decide_prepared(&hp, &hs, &authorities).is_err());
        abort_authority(&hp, &hs, &abort, &token, &authorities)?;
        abort_authority(&hp, &hs, &abort, &token, &authorities)?;
        abort_pair(&mut hp, &mut hs, &authorities)?;
    }
    for path in [&f.primary_path, &f.secondary_path] {
        assert!(peek_pending(path, &identity(), PASS).is_err());
    }
    // Both nodes are ordinary, uncompacted and writable again.
    let mut p = Node::open(&f.primary_path, Role::Primary, identity(), PASS, Adapter)?;
    let mut s = Node::open(
        &f.secondary_path,
        Role::Secondary,
        identity(),
        PASS,
        Adapter,
    )?;
    let before = p.checkpoint()?.sequence;
    let written = commit(&mut p, &mut s, batch("after-abort"))?;
    assert_eq!(written.sequence, before + 1);
    assert_eq!(p.checkpoint()?, s.checkpoint()?);
    Ok(())
}
