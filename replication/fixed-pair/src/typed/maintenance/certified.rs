//! Read-side authentication for future certified recovered-pair compaction.
//!
//! This module deliberately does not admit writes or relax recovery validation.
use super::{compaction::PairPlan, *};
use crate::recovery::transition::{self, TrustStore};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const TABLE: &str = "node_compaction_certificates";
const MAX_RECORD: usize = 256 * 1024;
const MAX_ROWS: u64 = 4096;
#[cfg(test)]
const PROGRESS: &str = "node_certified_compaction";

#[cfg(test)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum CertifiedPhase {
    Prepared,
    Decided,
    Applied,
    Complete,
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CertifiedProgress {
    record: CertificateRecord,
    phase: CertifiedPhase,
    token_digest: Option<[u8; 32]>,
    acknowledgements: [bool; 2],
    completion: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CertificateRecord {
    pub format: u32,
    pub plan: PairPlan,
    pub request: transition::Request,
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::typed) struct VerifiedLineage {
    pub source_anchor: Prefix,
    pub current_base: Prefix,
    pub first_revision: u64,
    pub last_revision: u64,
    pub certificates: u64,
}

fn table(c: &Connection) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [TABLE],
        |r| r.get(0),
    )?)
}

#[cfg(test)]
impl CertifiedProgress {
    fn validate(&self) -> Result<()> {
        self.record.plan.validate_certified()?;
        let legal = match self.phase {
            CertifiedPhase::Prepared => {
                self.token_digest.is_none()
                    && self.acknowledgements == [false; 2]
                    && self.completion.is_none()
            }
            CertifiedPhase::Decided => {
                self.token_digest.is_some()
                    && self.acknowledgements == [false; 2]
                    && self.completion.is_none()
            }
            CertifiedPhase::Applied => {
                self.token_digest.is_some()
                    && self.acknowledgements != [true; 2]
                    && self.completion.is_none()
            }
            CertifiedPhase::Complete => {
                self.token_digest.is_some()
                    && self.acknowledgements == [true; 2]
                    && self.completion.is_some_and(|id| id != [0; 32])
            }
        };
        ensure(legal, "invalid certified progress phase")
    }
}

#[cfg(test)]
fn progress(
    c: &Connection,
    identity: &Identity<SchemaId>,
    role: Role,
) -> Result<Option<CertifiedProgress>> {
    if !table_named(c, PROGRESS)? {
        return Ok(None);
    }
    let rows: Vec<(String, String)> = c
        .prepare("SELECT record,digest FROM node_certified_compaction ORDER BY id")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    ensure(rows.len() == 1, "certified progress row mismatch")?;
    rows.into_iter()
        .next()
        .map(|(json, digest)| {
            ensure(json.len() <= MAX_RECORD, "certified progress limit")?;
            let value: CertifiedProgress = serde_json::from_str(&json)?;
            value.validate()?;
            validate_record(&value.record, identity, role, None)?;
            ensure(hash(&value)? == digest, "certified progress integrity")?;
            Ok(value)
        })
        .transpose()
}

#[cfg(test)]
fn save_progress(c: &Connection, value: &CertifiedProgress) -> Result<()> {
    value.validate()?;
    let json = serde_json::to_string(value)?;
    ensure(json.len() <= MAX_RECORD, "certified progress limit")?;
    ensure(
        c.execute(
            "INSERT INTO node_certified_compaction VALUES(1,?1,?2)
             ON CONFLICT(id) DO UPDATE SET record=excluded.record,digest=excluded.digest",
            params![json, hash(value)?],
        )? == 1,
        "certified progress write failed",
    )
}

#[cfg(test)]
fn table_named(c: &Connection, name: &str) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [name],
        |r| r.get(0),
    )?)
}

fn id<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(value)?).into())
}

fn checkpoint(value: &Prefix) -> Result<transition::Checkpoint> {
    Ok(transition::Checkpoint {
        sequence: value.sequence,
        digest: id(value)?,
    })
}

fn publication(value: &snapshot::Manifest) -> Result<[u8; 32]> {
    value.encode()?;
    id(value)
}

pub(super) fn validate_record(
    record: &CertificateRecord,
    identity: &Identity<SchemaId>,
    role: Role,
    previous: Option<&CertificateRecord>,
) -> Result<()> {
    ensure(record.format == 1, "unsupported certificate record format")?;
    record.plan.validate_structural()?;
    let q = &record.request;
    q.validate()?;
    let local = record.plan.local(role);
    let anchor = local
        .recovery_anchor
        .as_ref()
        .ok_or("certificate requires recovery anchor")?;
    let membership = local
        .membership
        .ok_or("certificate requires recovery membership")?;
    let expected_target = checkpoint(&local.checkpoint)?;
    let expected_plan = id(&record.plan)?;
    let expected_publications = [
        publication(
            record
                .plan
                .primary
                .publication
                .as_ref()
                .ok_or("missing publication")?,
        )?,
        publication(
            record
                .plan
                .secondary
                .publication
                .as_ref()
                .ok_or("missing publication")?,
        )?,
    ];
    let expected_bases = [
        record
            .plan
            .primary
            .head
            .base
            .as_ref()
            .map(checkpoint)
            .transpose()?,
        record
            .plan
            .secondary
            .head
            .base
            .as_ref()
            .map(checkpoint)
            .transpose()?,
    ];
    ensure(
        anchor.identity == *identity
            && local.checkpoint.identity == *identity
            && q.scope == id(identity)?
            && q.schema == id(&local.contract)?
            && q.membership == membership
            && q.source_anchor == checkpoint(anchor)?
            && q.participants[0].target == expected_target
            && q.participants[1].target == expected_target
            && q.participants[0].plan == expected_plan
            && q.participants[1].plan == expected_plan
            && q.participants[0].publication == expected_publications[0]
            && q.participants[1].publication == expected_publications[1]
            && q.participants[0].old_base == expected_bases[0]
            && q.participants[1].old_base == expected_bases[1],
        "certificate plan binding mismatch",
    )?;
    if let Some(old) = previous {
        let old_q = &old.request;
        ensure(
            q.authority_id == old_q.authority_id
                && q.revision
                    == old_q
                        .revision
                        .checked_add(1)
                        .ok_or("certificate revision overflow")?
                && q.install == old_q.install
                && q.region == old_q.region
                && q.scope == old_q.scope
                && q.schema == old_q.schema
                && q.membership == old_q.membership
                && q.source_anchor == old_q.source_anchor
                && q.participants
                    .iter()
                    .zip(&old_q.participants)
                    .all(|(a, b)| {
                        a.member == b.member
                            && a.generation == b.generation
                            && a.old_base.as_ref() == Some(&b.target)
                    }),
            "certificate lineage mismatch",
        )?;
    }
    Ok(())
}

pub(in crate::typed) fn verify_metadata(
    c: &Connection,
    maintenance_format: u32,
    trust: Option<&TrustStore>,
) -> Result<Option<VerifiedLineage>> {
    let present = table(c)?;
    if maintenance_format != 3 {
        return if present {
            Err("orphan certificate metadata".into())
        } else {
            Ok(None)
        };
    }
    ensure(present, "certified history missing")?;
    let trust = trust.ok_or("transition trust required")?;
    let owner: String = c.query_row("SELECT value FROM node_identity", [], |r| r.get(0))?;
    let (identity, role): (Identity<SchemaId>, Role) = serde_json::from_str(&owner)?;
    let base = checkpoint::base_for::<SchemaId>(c)?.ok_or("certified base missing")?;
    let count: u64 = c.query_row(&format!("SELECT count(*) FROM {TABLE}"), [], |r| r.get(0))?;
    ensure(
        count > 0 && count <= MAX_ROWS,
        "certificate history row limit",
    )?;
    let (history_rows, history_bytes): (u64, u64) = c.query_row(
        "SELECT count(*),coalesce(max(length(CAST(plan AS BLOB))),0) FROM node_compaction_history",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure(
        history_rows <= MAX_ROWS && history_bytes <= 128 * 1024,
        "compaction history row limit",
    )?;
    let (root_rows, root_bytes): (u64, u64) = c.query_row(
        "SELECT count(*),coalesce(max(length(CAST(base AS BLOB))),0) FROM node_compaction_root",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure(
        root_rows == 1 && root_bytes <= 256 * 1024,
        "compaction root limit",
    )?;
    let root: String = c.query_row(
        "SELECT base FROM node_compaction_root WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let mut preceding: Option<Prefix> = serde_json::from_str(&root)?;
    let mut stmt = c.prepare(
        "SELECT h.sequence,h.plan,h.digest,c.record FROM node_compaction_history h
         LEFT JOIN node_compaction_certificates c ON c.sequence=h.sequence ORDER BY h.sequence",
    )?;
    let mut rows = stmt.query([])?;
    let mut previous: Option<CertificateRecord> = None;
    let mut first_revision = 0;
    let mut seen = HashSet::new();
    let mut verified = 0u64;
    while let Some(row) = rows.next()? {
        let sequence: u64 = row.get(0)?;
        let plan_json: String = row.get(1)?;
        ensure(
            plan_json.len() <= 128 * 1024,
            "compaction history too large",
        )?;
        let plan: PairPlan = serde_json::from_str(&plan_json)?;
        plan.validate_structural()?;
        ensure(
            row.get::<_, String>(2)? == hash(&plan)?,
            "compaction history checksum mismatch",
        )?;
        let local = plan.local(role);
        ensure(
            sequence == local.checkpoint.sequence
                && local.checkpoint.identity == identity
                && local.head.base == preceding,
            "compaction history chain mismatch",
        )?;
        let certificate: Option<String> = row.get(3)?;
        if local.membership.is_none() {
            ensure(certificate.is_none(), "certificate on original compaction")?;
            preceding = Some(local.checkpoint.clone());
            continue;
        }
        let json = certificate.ok_or("certificate history gap")?;
        ensure(json.len() <= MAX_RECORD, "certificate record limit")?;
        let record: CertificateRecord = serde_json::from_str(&json)?;
        ensure(
            record.plan == plan,
            "certificate compaction history mismatch",
        )?;
        validate_record(&record, &identity, role, previous.as_ref())?;
        ensure(
            sequence == record.plan.local(role).checkpoint.sequence,
            "certificate sequence mismatch",
        )?;
        transition::verify_historical(&record.token, &trust.as_trust(), &record.request)?;
        ensure(
            seen.insert(record.request.id),
            "duplicate certificate request id",
        )?;
        if previous.is_none() {
            first_revision = record.request.revision;
        }
        verified += 1;
        preceding = Some(local.checkpoint.clone());
        previous = Some(record);
    }
    ensure(verified == count, "orphan certificate row")?;
    let last = previous.ok_or("certificate history missing")?;
    ensure(
        last.plan.local(role).checkpoint == base,
        "certificate lineage/base mismatch",
    )?;
    Ok(Some(VerifiedLineage {
        source_anchor: last
            .plan
            .local(role)
            .recovery_anchor
            .clone()
            .ok_or("certificate anchor missing")?,
        current_base: base,
        first_revision,
        last_revision: last.request.revision,
        certificates: verified,
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::envelope_tests::{stock_entry, StockSchema};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
    };

    #[derive(Serialize)]
    struct Claims<'a> {
        version: u32,
        iss: &'a str,
        aud: &'a str,
        action: &'a str,
        certificate_id: [u8; 32],
        iat: u64,
        nbf: u64,
        exp: u64,
        request: &'a transition::Request,
        request_digest: [u8; 32],
    }

    pub(crate) fn signer() -> Result<(EcdsaKeyPair, Vec<u8>)> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| "key generation")?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.as_ref(), &rng)
            .map_err(|_| "key parsing")?;
        let public = pair.public_key().as_ref().to_vec();
        Ok((pair, public))
    }

    pub(crate) fn sign(pair: &EcdsaKeyPair, request: &transition::Request) -> Result<String> {
        let header = B64.encode(serde_json::to_vec(&serde_json::json!({
            "alg":"ES256", "kid":"fixture", "typ":transition::TOKEN_TYPE
        }))?);
        let claims = Claims {
            version: 1,
            iss: "issuer",
            aud: "audience",
            action: "compact_pair",
            certificate_id: [17; 32],
            iat: 10,
            nbf: 10,
            exp: 20,
            request,
            request_digest: request.digest()?,
        };
        let payload = B64.encode(serde_json::to_vec(&claims)?);
        let input = format!("{header}.{payload}");
        let signature = pair
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|_| "signing")?;
        Ok(format!("{input}.{}", B64.encode(signature.as_ref())))
    }

    fn fixture() -> Result<(
        tempfile::TempDir,
        Node<StockSchema>,
        CertificateRecord,
        TrustStore,
    )> {
        let dir = tempfile::tempdir()?;
        let batch = stock_entry().batch;
        let mut p = Node::open(
            dir.path().join("p"),
            Role::Primary,
            batch.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        let mut s = Node::open(
            dir.path().join("s"),
            Role::Secondary,
            batch.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        let anchor = p.checkpoint()?;
        crate::commit(&mut p, &mut s, batch)?;
        p.publish_snapshot()?;
        s.publish_snapshot()?;
        let mut plan = super::compaction::plan_pair(&p, &s)?;
        let membership = [8; 32];
        plan.primary.membership = Some(membership);
        plan.secondary.membership = Some(membership);
        plan.primary.recovery_anchor = Some(anchor.clone());
        plan.secondary.recovery_anchor = Some(anchor.clone());
        plan.validate_structural()?;
        let request = transition::Request {
            format: 1,
            id: [9; 32],
            authority_id: [10; 32],
            revision: 7,
            install: "install".into(),
            region: "region".into(),
            scope: id(p.identity())?,
            schema: id(&plan.primary.contract)?,
            membership,
            source_anchor: checkpoint(&anchor)?,
            participants: [
                transition::Participant {
                    member: [11; 32],
                    generation: [12; 32],
                    old_base: None,
                    target: checkpoint(&plan.primary.checkpoint)?,
                    plan: id(&plan)?,
                    publication: publication(plan.primary.publication.as_ref().unwrap())?,
                },
                transition::Participant {
                    member: [13; 32],
                    generation: [14; 32],
                    old_base: None,
                    target: checkpoint(&plan.secondary.checkpoint)?,
                    plan: id(&plan)?,
                    publication: publication(plan.secondary.publication.as_ref().unwrap())?,
                },
            ],
        };
        let (pair, public) = signer()?;
        let record = CertificateRecord {
            format: 1,
            plan,
            token: sign(&pair, &request)?,
            request,
        };
        let trust = TrustStore {
            profile: crate::recovery::grant::Profile {
                issuer: "issuer".into(),
                audience: "audience".into(),
                token_type: transition::TOKEN_TYPE.into(),
            },
            keys: vec![("fixture".into(), public)],
            max_lifetime: 20,
        };
        Ok((dir, p, record, trust))
    }

    fn install(p: &Node<StockSchema>, record: &CertificateRecord) -> Result<()> {
        p.connection(|c| {
            c.execute_batch("CREATE TABLE node_compaction_root(id INTEGER PRIMARY KEY CHECK(id=1),base TEXT NOT NULL);
                CREATE TABLE node_compaction_history(sequence INTEGER PRIMARY KEY,plan TEXT NOT NULL,digest TEXT NOT NULL);
                CREATE TABLE node_compaction_certificates(sequence INTEGER PRIMARY KEY,record TEXT NOT NULL);")?;
            c.execute("INSERT INTO node_compaction_root VALUES(1,?1)", [serde_json::to_string(&record.plan.primary.head.base)?])?;
            c.execute("INSERT INTO node_compaction_history VALUES(?1,?2,?3)", params![record.plan.primary.checkpoint.sequence,serde_json::to_string(&record.plan)?,hash(&record.plan)?])?;
            c.execute("INSERT INTO node_compaction_certificates VALUES(?1,?2)", params![record.plan.primary.checkpoint.sequence,serde_json::to_string(record)?])?;
            c.execute("INSERT INTO replication_base VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint", [serde_json::to_string(&record.plan.primary.checkpoint)?])?;
            Ok(())
        })
    }

    fn request_for(
        plan: &PairPlan,
        anchor: &Prefix,
        revision: u64,
        request_id: [u8; 32],
    ) -> Result<transition::Request> {
        Ok(transition::Request {
            format: 1,
            id: request_id,
            authority_id: [10; 32],
            revision,
            install: "install".into(),
            region: "region".into(),
            scope: id(&plan.primary.checkpoint.identity)?,
            schema: id(&plan.primary.contract)?,
            membership: plan.primary.membership.unwrap(),
            source_anchor: checkpoint(anchor)?,
            participants: [
                transition::Participant {
                    member: [11; 32],
                    generation: [12; 32],
                    old_base: plan
                        .primary
                        .head
                        .base
                        .as_ref()
                        .map(checkpoint)
                        .transpose()?,
                    target: checkpoint(&plan.primary.checkpoint)?,
                    plan: id(plan)?,
                    publication: publication(plan.primary.publication.as_ref().unwrap())?,
                },
                transition::Participant {
                    member: [13; 32],
                    generation: [14; 32],
                    old_base: plan
                        .secondary
                        .head
                        .base
                        .as_ref()
                        .map(checkpoint)
                        .transpose()?,
                    target: checkpoint(&plan.secondary.checkpoint)?,
                    plan: id(plan)?,
                    publication: publication(plan.secondary.publication.as_ref().unwrap())?,
                },
            ],
        })
    }

    fn install_chain(
        node: &Node<StockSchema>,
        records: &[CertificateRecord],
        role: Role,
    ) -> Result<()> {
        node.connection(|c| {
            c.execute_batch("CREATE TABLE node_compaction_root(id INTEGER PRIMARY KEY CHECK(id=1),base TEXT NOT NULL);
                CREATE TABLE node_compaction_history(sequence INTEGER PRIMARY KEY,plan TEXT NOT NULL,digest TEXT NOT NULL);
                CREATE TABLE node_compaction_certificates(sequence INTEGER PRIMARY KEY,record TEXT NOT NULL);")?;
            c.execute("INSERT INTO node_compaction_root VALUES(1,?1)", [serde_json::to_string(&records[0].plan.local(role).head.base)?])?;
            for record in records {
                let sequence = record.plan.local(role).checkpoint.sequence;
                c.execute("INSERT INTO node_compaction_history VALUES(?1,?2,?3)", params![sequence,serde_json::to_string(&record.plan)?,hash(&record.plan)?])?;
                c.execute("INSERT INTO node_compaction_certificates VALUES(?1,?2)", params![sequence,serde_json::to_string(record)?])?;
            }
            c.execute("INSERT INTO replication_base VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint", [serde_json::to_string(&records.last().unwrap().plan.local(role).checkpoint)?])?;
            Ok(())
        })
    }

    type ChainFixture = (
        tempfile::TempDir,
        Node<StockSchema>,
        Node<StockSchema>,
        Vec<CertificateRecord>,
        TrustStore,
        EcdsaKeyPair,
    );

    fn chain_fixture() -> Result<ChainFixture> {
        let dir = tempfile::tempdir()?;
        let mut batch = stock_entry().batch;
        let mut p = Node::open(
            dir.path().join("p"),
            Role::Primary,
            batch.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        let mut s = Node::open(
            dir.path().join("s"),
            Role::Secondary,
            batch.identity.clone(),
            "fixture",
            StockSchema,
        )?;
        let anchor = p.checkpoint()?;
        crate::commit(&mut p, &mut s, batch.clone())?;
        let p1 = p.publish_snapshot()?;
        let s1 = s.publish_snapshot()?;
        let mut first = super::compaction::plan_pair(&p, &s)?;
        for plan in [&mut first.primary, &mut first.secondary] {
            plan.membership = Some([8; 32]);
            plan.recovery_anchor = Some(anchor.clone());
        }
        // The survivor may begin from an authority-bound anchor while the fresh
        // candidate has no prior local base.
        first.secondary.head.base = Some(anchor.clone());
        first.validate_structural()?;
        batch.operation_id = "second-certified-cut".into();
        crate::commit(&mut p, &mut s, batch)?;
        p.rotate_snapshot(&p1)?;
        s.rotate_snapshot(&s1)?;
        let mut second = super::compaction::plan_pair(&p, &s)?;
        for plan in [&mut second.primary, &mut second.secondary] {
            plan.membership = Some([8; 32]);
            plan.recovery_anchor = Some(anchor.clone());
            plan.head.base = Some(first.primary.checkpoint.clone());
        }
        second.validate_structural()?;
        let (pair, public) = signer()?;
        let q1 = request_for(&first, &anchor, 7, [9; 32])?;
        let q2 = request_for(&second, &anchor, 8, [15; 32])?;
        let records = vec![
            CertificateRecord {
                format: 1,
                plan: first,
                token: sign(&pair, &q1)?,
                request: q1,
            },
            CertificateRecord {
                format: 1,
                plan: second,
                token: sign(&pair, &q2)?,
                request: q2,
            },
        ];
        let trust = TrustStore {
            profile: crate::recovery::grant::Profile {
                issuer: "issuer".into(),
                audience: "audience".into(),
                token_type: transition::TOKEN_TYPE.into(),
            },
            keys: vec![("fixture".into(), public)],
            max_lifetime: 20,
        };
        Ok((dir, p, s, records, trust, pair))
    }

    #[test]
    fn verifies_signed_lineage_and_rejects_substitution_or_missing_history() -> Result<()> {
        let (_dir, p, record, trust) = fixture()?;
        install(&p, &record)?;
        p.connection(|c| {
            let proof = verify_metadata(c, 3, Some(&trust))?.unwrap();
            assert_eq!(proof.certificates, 1);
            assert_eq!(proof.current_base, record.plan.primary.checkpoint);
            assert!(verify_metadata(c, 3, None).is_err());
            let (_, other_public) = signer()?;
            assert!(verify_metadata(
                c,
                3,
                Some(&TrustStore {
                    keys: vec![("fixture".into(), other_public)],
                    ..trust.clone()
                })
            )
            .is_err());
            c.execute("DELETE FROM node_compaction_certificates", [])?;
            assert!(verify_metadata(c, 3, Some(&trust)).is_err());
            c.execute_batch("DROP TABLE node_compaction_certificates")?;
            assert!(verify_metadata(c, 3, Some(&trust)).is_err());
            Ok(())
        })
    }

    #[test]
    fn rejects_orphan_metadata_and_plan_cut_membership_changes() -> Result<()> {
        let (_dir, p, record, trust) = fixture()?;
        install(&p, &record)?;
        p.connection(|c| {
            assert!(verify_metadata(c, 2, Some(&trust)).is_err());
            let mut bad = record.clone();
            bad.plan.primary.membership = Some([99; 32]);
            c.execute(
                "UPDATE node_compaction_certificates SET record=?1",
                [serde_json::to_string(&bad)?],
            )?;
            assert!(verify_metadata(c, 3, Some(&trust)).is_err());
            for bad in [
                {
                    let mut bad = record.clone();
                    bad.request.participants[0].plan = [98; 32];
                    bad
                },
                {
                    let mut bad = record.clone();
                    bad.request.participants[0].target.sequence += 1;
                    bad
                },
                {
                    let mut bad = record.clone();
                    bad.request.membership = [97; 32];
                    bad
                },
                {
                    let mut bad = record.clone();
                    bad.request.participants[0].publication = [96; 32];
                    bad
                },
            ] {
                c.execute(
                    "UPDATE node_compaction_certificates SET record=?1",
                    [serde_json::to_string(&bad)?],
                )?;
                assert!(verify_metadata(c, 3, Some(&trust)).is_err());
            }
            Ok(())
        })
    }

    #[test]
    fn verifies_two_signed_transitions_for_both_roles_and_rejects_history_gaps() -> Result<()> {
        let (_dir, p, s, records, trust, _pair) = chain_fixture()?;
        install_chain(&p, &records, Role::Primary)?;
        install_chain(&s, &records, Role::Secondary)?;
        p.connection(|c| {
            assert_eq!(
                verify_metadata(c, 3, Some(&trust))?.unwrap().certificates,
                2
            );
            Ok(())
        })?;
        s.connection(|c| {
            assert_eq!(
                verify_metadata(c, 3, Some(&trust))?.unwrap().certificates,
                2
            );
            Ok(())
        })?;
        p.connection(|c| {
            c.execute(
                "DELETE FROM node_compaction_certificates WHERE sequence=?1",
                [records[0].plan.primary.checkpoint.sequence],
            )?;
            assert!(verify_metadata(c, 3, Some(&trust)).is_err());
            Ok(())
        })?;
        s.connection(|c| {
            c.execute(
                "DELETE FROM node_compaction_certificates WHERE sequence=?1",
                [records[0].plan.secondary.checkpoint.sequence],
            )?;
            c.execute(
                "DELETE FROM node_compaction_history WHERE sequence=?1",
                [records[0].plan.secondary.checkpoint.sequence],
            )?;
            assert!(verify_metadata(c, 3, Some(&trust)).is_err());
            Ok(())
        })
    }

    #[test]
    fn rejects_validly_signed_second_transition_member_generation_drift() -> Result<()> {
        let (_dir, p, _s, mut records, trust, pair) = chain_fixture()?;
        records[1].request.participants[0].member = [21; 32];
        records[1].request.participants[0].generation = [22; 32];
        records[1].token = sign(&pair, &records[1].request)?;
        install_chain(&p, &records, Role::Primary)?;
        p.connection(|c| {
            assert!(verify_metadata(c, 3, Some(&trust)).is_err());
            Ok(())
        })
    }

    #[test]
    fn owner_hook_reopens_legacy_without_trust_and_rejects_orphan_table() -> Result<()> {
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
        let node = Node::open(
            &path,
            Role::Primary,
            identity.clone(),
            "fixture",
            StockSchema,
        )?;
        node.connection(|c| {
            c.execute_batch("CREATE TABLE node_compaction_certificates(sequence INTEGER PRIMARY KEY,record TEXT NOT NULL)")?;
            Ok(())
        })?;
        drop(node);
        assert!(Node::open(&path, Role::Primary, identity, "fixture", StockSchema).is_err());
        Ok(())
    }

    #[test]
    fn progress_rejects_illegal_phases_empty_tables_and_ignored_writes() -> Result<()> {
        let (_dir, p, record, _trust) = fixture()?;
        p.connection(|c| {
            c.execute_batch(
                "CREATE TABLE node_certified_compaction(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    record TEXT NOT NULL,
                    digest TEXT NOT NULL)",
            )?;
            assert!(progress(c, p.identity(), Role::Primary).is_err());

            let prepared = CertifiedProgress {
                record: record.clone(),
                phase: CertifiedPhase::Prepared,
                token_digest: None,
                acknowledgements: [false; 2],
                completion: None,
            };
            save_progress(c, &prepared)?;
            assert_eq!(progress(c, p.identity(), Role::Primary)?, Some(prepared));

            let invalid = CertifiedProgress {
                record: record.clone(),
                phase: CertifiedPhase::Complete,
                token_digest: Some([3; 32]),
                acknowledgements: [true, false],
                completion: Some([4; 32]),
            };
            assert!(save_progress(c, &invalid).is_err());

            c.execute("DELETE FROM node_certified_compaction", [])?;
            c.execute_batch(
                "CREATE TRIGGER ignore_certified_progress
                 BEFORE INSERT ON node_certified_compaction BEGIN SELECT RAISE(IGNORE); END;",
            )?;
            assert!(save_progress(
                c,
                &CertifiedProgress {
                    record,
                    phase: CertifiedPhase::Prepared,
                    token_digest: None,
                    acknowledgements: [false; 2],
                    completion: None,
                }
            )
            .is_err());
            Ok(())
        })
    }
}
