use super::*;
use crate::ensure;
use rusqlite::OptionalExtension;

pub const LOSS_TOKEN_TYPE: &str = "terrapi-participant-loss+jwt";
pub const LOSS_SUCCESSOR_TOKEN_TYPE: &str = "terrapi-loss-successor+jwt";
pub const LOSS_SUCCESSOR_ABORT_TOKEN_TYPE: &str = "terrapi-loss-successor-abort+jwt";

/// Hard row cap on the append-only `main.transition_loss_chain` table,
/// checked before any row is decoded.
const MAX_CHAIN_ROWS: usize = 4096;

/// Authority-signed cancellation of a decided loss successor.
///
/// A replacement can be wrong — wrong hardware, wrong site, compromised — and
/// before this existed there was no way back: the successor journal was the
/// only door out of a participant loss and it only opened forwards. The abort
/// makes that journal terminal and lets the authority issue a *superseding*
/// `LossRequest` with a fresh replacement membership.
///
/// It is not a transition and never authorizes a write; it authorizes the
/// survivor to un-install the replacement it already installed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LossSuccessorAbort {
    pub format: u32,
    pub id: Id,
    pub authority_id: Id,
    /// The successor revision being cancelled.
    pub revision: u64,
    pub install: String,
    pub region: String,
    pub scope: Id,
    pub schema: Id,
    /// The parent loss's `replacement_membership`, i.e. this journal's scope.
    pub membership: Id,
    pub parent_loss_certificate: Id,
    pub parent_loss_token_digest: Id,
    pub successor_id: Id,
    pub successor_certificate: Id,
    pub successor_token_digest: Id,
    /// Durable fencing of the replacement member/generation being retired.
    /// Opaque to the journal: only
    /// [`LossPolicy::successor_abort_authorized`] can check that it really
    /// fences the replacement, and it must do so against live node evidence.
    pub fencing_ref: Id,
}

impl LossSuccessorAbort {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.format != 2
            || self.id == [0; 32]
            || self.authority_id == [0; 32]
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || !valid_text(&self.install)
            || !valid_text(&self.region)
            || self.scope == [0; 32]
            || self.schema == [0; 32]
            || self.membership == [0; 32]
            || self.parent_loss_certificate == [0; 32]
            || self.parent_loss_token_digest == [0; 32]
            || self.successor_id == [0; 32]
            || self.successor_certificate == [0; 32]
            || self.successor_token_digest == [0; 32]
            || self.fencing_ref == [0; 32]
        {
            Err("invalid loss successor abort")
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Result<Id, &'static str> {
        self.validate()?;
        Ok(
            Sha256::digest(serde_json::to_vec(self).map_err(|_| "successor abort encoding")?)
                .into(),
        )
    }
}

/// Opaque, durable proof that the authority cancelled a decided loss
/// successor. It authorizes local *un-installation* only.
///
/// It is deliberately unrelated to every transition proof: an abort is the
/// evidence that a replacement must be removed, so accepting it anywhere an
/// installation or writer proof is accepted would be exactly backwards.
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{CommittedLossSuccessorAbort, CommittedLossSuccessorTransition};
/// fn install(_: CommittedLossSuccessorTransition) {}
/// fn abort_is_not_an_installation(proof: CommittedLossSuccessorAbort) { install(proof); }
/// ```
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{CommittedLossSuccessorAbort, CompletedLossSuccessorTransition};
/// fn admit(_: CompletedLossSuccessorTransition) {}
/// fn abort_cannot_admit(proof: CommittedLossSuccessorAbort) { admit(proof); }
/// ```
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{CommittedLossSuccessorAbort, CommittedLoss};
/// fn found_a_successor(_: CommittedLoss) {}
/// fn abort_is_not_a_loss(proof: CommittedLossSuccessorAbort) { found_a_successor(proof); }
/// ```
#[derive(Clone)]
pub struct CommittedLossSuccessorAbort {
    abort: LossSuccessorAbort,
    token: String,
    token_digest: Id,
    certificate_id: Id,
}

impl CommittedLossSuccessorAbort {
    pub fn abort(&self) -> &LossSuccessorAbort {
        &self.abort
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }
    pub fn successor_id(&self) -> Id {
        self.abort.successor_id
    }
    pub fn fencing_ref(&self) -> Id {
        self.abort.fencing_ref
    }
}

/// What a loss decision is anchored to. A format-1 request carries no kind
/// and is always treated as [`SourceKind::Completed`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum SourceKind {
    /// A completed ordinary transition in this journal.
    Completed,
    /// A decided-but-unfinished transition the loss abandons (S11).
    Decided,
    /// A completed loss successor: the pair already survived one loss and is
    /// now losing a second participant.
    LossSuccessor,
}

/// Evidence that a previous loss attempt was aborted and is being replaced.
///
/// `abort_certificate` and `abort_token_digest` name a record in a *different
/// file* — the previous successor journal — which this journal cannot open.
/// They are therefore bound by nothing here except
/// [`LossPolicy::superseded_successor_aborted`], which must check them live.
/// Treat them as a claim until that hook has spoken.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Supersedes {
    pub loss_certificate: Id,
    pub loss_token_digest: Id,
    pub abort_certificate: Id,
    pub abort_token_digest: Id,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LossRequest {
    pub format: u32,
    pub id: Id,
    pub authority_id: Id,
    pub revision: u64,
    pub install: String,
    pub region: String,
    pub scope: Id,
    pub schema: Id,
    pub membership: Id,
    pub source_certificate: Id,
    pub source_token_digest: Id,
    pub source_cut: Checkpoint,
    pub lost_member: Id,
    pub lost_generation: Id,
    pub survivor: Participant,
    pub survivor_cut: Checkpoint,
    pub survivor_publication: Id,
    pub replacement_membership: Id,
    pub replacement_member: Id,
    pub replacement_generation: Id,
    pub fencing_ref: Id,
    /// Format 2 only. `serde_json` omits a skipped field, so a format-1
    /// request re-serialises to exactly its format-1 bytes and every stored
    /// digest and token binding stays valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<SourceKind>,
    /// `Request::digest` of an in-flight certified transition this loss
    /// abandons. Never padding: only meaningful for `Completed`/`Decided`.
    ///
    /// When the journal holds an open decided head, that head binds this
    /// field exactly. Otherwise — a request that was only ever *prepared* —
    /// the journal has never seen it, and the field is bound solely by
    /// [`LossPolicy::maintenance_rollback_authorized`] against live survivor
    /// evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abandoned_request: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<Supersedes>,
}

/// Purpose-specific membership activation following a fenced participant loss.
/// Unlike [`Request`], this may be a data no-op: both targets may equal the
/// survivor cut and the replacement base may equal that same cut.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LossSuccessorRequest {
    pub format: u32,
    pub id: Id,
    pub authority_id: Id,
    pub revision: u64,
    pub install: String,
    pub region: String,
    pub scope: Id,
    pub schema: Id,
    pub membership: Id,
    pub source_certificate: Id,
    pub source_token_digest: Id,
    pub source_cut: Checkpoint,
    pub parent_loss_certificate: Id,
    pub parent_loss_token_digest: Id,
    pub survivor_cut: Checkpoint,
    pub survivor_publication: Id,
    /// Format 1 orders these `[survivor, replacement]`. Format 2 orders them
    /// canonically `[primary, secondary]` and names the survivor with
    /// [`LossSuccessorRequest::survivor_index`]; use [`roles`] or the
    /// `survivor()`/`replacement()` accessors, never a literal index.
    pub participants: [Participant; 2],
    /// Format 2 only: which participant is the survivor. Without it a
    /// recovered pair carries no role information and cannot take a further
    /// loss, so from S9 on every new recovery must issue format 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub survivor_index: Option<u8>,
}

/// `(survivor index, replacement index)`.
///
/// Format 1 fixed the participant order to `[survivor, replacement]`. Format 2
/// keeps the canonical `[primary, secondary]` order used everywhere else and
/// carries the survivor's index explicitly, so the role is still a *result*
/// derived from the signed request and never a caller-supplied parameter.
pub fn roles(request: &LossSuccessorRequest) -> Result<(usize, usize), &'static str> {
    match (request.format, request.survivor_index) {
        (1, None) => Ok((0, 1)),
        (2, Some(i @ (0 | 1))) => Ok((usize::from(i), 1 - usize::from(i))),
        _ => Err("invalid loss successor request"),
    }
}

impl LossSuccessorRequest {
    /// The surviving participant of the parent loss.
    pub fn survivor(&self) -> Result<&Participant, &'static str> {
        Ok(&self.participants[roles(self)?.0])
    }
    /// The participant installed to replace the lost member.
    pub fn replacement(&self) -> Result<&Participant, &'static str> {
        Ok(&self.participants[roles(self)?.1])
    }
    /// `0` or `1`; always `0` for a format-1 request.
    pub fn survivor_index(&self) -> Result<usize, &'static str> {
        Ok(roles(self)?.0)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        let (s, rp) = roles(self)?;
        let survivor = &self.participants[s];
        let replacement = &self.participants[rp];
        if self.id == [0; 32]
            || self.authority_id == [0; 32]
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || !valid_text(&self.install)
            || !valid_text(&self.region)
            || self.scope == [0; 32]
            || self.schema == [0; 32]
            || self.membership == [0; 32]
            || self.source_certificate == [0; 32]
            || self.source_token_digest == [0; 32]
            || !valid_checkpoint(&self.source_cut)
            || self.parent_loss_certificate == [0; 32]
            || self.parent_loss_token_digest == [0; 32]
            || !valid_checkpoint(&self.survivor_cut)
            || self.survivor_publication == [0; 32]
            || survivor.member == [0; 32]
            || replacement.member == [0; 32]
            || survivor.member == replacement.member
            || survivor.generation == [0; 32]
            || replacement.generation == [0; 32]
            || survivor.generation == replacement.generation
            || survivor.plan == [0; 32]
            || survivor.plan != replacement.plan
            || survivor.target != self.survivor_cut
            || replacement.target != self.survivor_cut
            || survivor.publication != self.survivor_publication
            || replacement.publication != self.survivor_publication
            || survivor
                .old_base
                .as_ref()
                .is_some_and(|b| b.sequence > self.survivor_cut.sequence)
            || replacement.old_base.as_ref() != Some(&self.survivor_cut)
        {
            Err("invalid loss successor request")
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Result<Id, &'static str> {
        self.validate()?;
        Ok(
            Sha256::digest(serde_json::to_vec(self).map_err(|_| "successor request encoding")?)
                .into(),
        )
    }
}
impl LossRequest {
    /// The source kind this request means, defaulting a format-1 request
    /// to [`SourceKind::Completed`].
    pub fn kind(&self) -> SourceKind {
        self.source_kind.unwrap_or(SourceKind::Completed)
    }

    /// The format-2 optional fields, checked independently of the clauses
    /// that every loss request has always had.
    fn valid_extensions(&self) -> bool {
        let present = self.source_kind.is_some()
            || self.abandoned_request.is_some()
            || self.supersedes.is_some();
        match self.format {
            1 => !present,
            2 => {
                self.source_kind.is_some()
                    // Never padding: an abandoned request is only meaningful
                    // where an ordinary transition was in flight.
                    && self.abandoned_request.is_none_or(|d| {
                        d != [0; 32]
                            && matches!(
                                self.source_kind,
                                Some(SourceKind::Completed | SourceKind::Decided)
                            )
                    })
                    && self.supersedes.as_ref().is_none_or(|s| {
                        s.loss_certificate != [0; 32]
                            && s.loss_token_digest != [0; 32]
                            && s.abort_certificate != [0; 32]
                            && s.abort_token_digest != [0; 32]
                    })
            }
            _ => false,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.valid_extensions()
            || self.id == [0; 32]
            || self.authority_id == [0; 32]
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || !valid_text(&self.install)
            || !valid_text(&self.region)
            || self.scope == [0; 32]
            || self.schema == [0; 32]
            || self.membership == [0; 32]
            || self.source_certificate == [0; 32]
            || self.source_token_digest == [0; 32]
            || !valid_checkpoint(&self.source_cut)
            || self.lost_member == [0; 32]
            || self.lost_generation == [0; 32]
            || self.survivor.member == [0; 32]
            || self.survivor.generation == [0; 32]
            || self.survivor.member == self.lost_member
            || !valid_checkpoint(&self.survivor_cut)
            || self.survivor.target != self.survivor_cut
            || self.survivor_publication == [0; 32]
            || self.survivor.publication != self.survivor_publication
            || self.survivor_cut.sequence < self.source_cut.sequence
            || (self.survivor_cut.sequence == self.source_cut.sequence
                && self.survivor_cut != self.source_cut)
            || self.replacement_member == [0; 32]
            || self.replacement_membership == [0; 32]
            || self.replacement_membership == self.membership
            || self.replacement_generation == [0; 32]
            || self.replacement_generation == self.lost_generation
            || self.replacement_generation == self.survivor.generation
            || self.replacement_member == self.lost_member
            || self.replacement_member == self.survivor.member
            || self.fencing_ref == [0; 32]
        {
            Err("invalid participant loss request")
        } else {
            Ok(())
        }
    }
    pub fn digest(&self) -> Result<Id, &'static str> {
        self.validate()?;
        Ok(Sha256::digest(serde_json::to_vec(self).map_err(|_| "loss request encoding")?).into())
    }
}

pub trait LossPolicy {
    /// Must consult current external authority state and prove durable fencing of
    /// the exact lost member generation. A historical signature is insufficient.
    fn continuity_and_fencing(
        &self,
        scope: &JournalScope,
        request: &LossRequest,
    ) -> crate::Result<()>;
    /// Must authenticate the survivor fields against durable participant evidence.
    ///
    /// # `source_kind == Decided`
    ///
    /// For a finish-forward loss this hook carries a far heavier duty: it
    /// **must** prove, from live survivor evidence, that the survivor
    /// durably **applied** the decided transition named by
    /// `request.abandoned_request`. That transition is never completed and
    /// the lost member can never acknowledge it, so nothing else in the
    /// system will ever check it again. An implementation that accepts a
    /// merely *prepared* or *decided* survivor here promotes an unfinished
    /// certificate into provenance for data that was never written — which is
    /// precisely the failure this branch exists to avoid.
    fn survivor_prepared(&self, scope: &JournalScope, request: &LossRequest) -> crate::Result<()>;

    /// Authorize a loss that abandons an in-flight certified maintenance
    /// request (`source_kind == Completed` with an `abandoned_request`). The
    /// default is deliberately deny.
    ///
    /// The journal can see a decided transition, but a request that was only
    /// ever *prepared* exists nowhere except on the nodes. An implementation
    /// **must** prove from live survivor evidence that the survivor holds
    /// exactly this pending request, in phase `prepared` or `decided`, and
    /// has **not** applied it. A survivor that applied it must use
    /// [`SourceKind::Decided`] instead — rolling back an applied transition
    /// is impossible, because its history has already been pruned.
    ///
    /// This hook is also what stops `abandoned_request` from becoming
    /// padding: on an idle journal it is the only thing that can refuse it.
    fn maintenance_rollback_authorized(
        &self,
        _scope: &JournalScope,
        _loss: &LossRequest,
        _abandoned_request: &Id,
    ) -> crate::Result<()> {
        Err("maintenance rollback evidence missing".into())
    }

    /// Authorize a loss that finishes an in-flight certified maintenance
    /// transition *forward* (`source_kind == Decided`). The default is
    /// deliberately deny, and it is deny separately from
    /// [`LossPolicy::survivor_prepared`] on purpose: this branch promotes a
    /// transition that was never completed into the pair's provenance, so it
    /// must not ride on a hook every ordinary loss already implements.
    ///
    /// An implementation **must** prove, live, that the survivor durably
    /// **applied** exactly the decided transition named by
    /// `abandoned_request` and holds its certificate. A survivor that is only
    /// prepared or decided must roll back instead; accepting it here would
    /// certify data that was never written.
    fn maintenance_finish_forward_authorized(
        &self,
        _scope: &JournalScope,
        _loss: &LossRequest,
        _abandoned_request: &Id,
    ) -> crate::Result<()> {
        Err("maintenance finish-forward evidence missing".into())
    }

    /// Live-read durable installation evidence for this exact participant.
    /// The default is intentionally deny: a decision handle is not evidence
    /// that either node installed the replacement membership.
    fn loss_successor_applied(
        &self,
        _source_scope: &JournalScope,
        _loss: &LossRequest,
        _successor: &LossSuccessorRequest,
        _participant: &Participant,
    ) -> crate::Result<()> {
        Err("loss successor installation evidence missing".into())
    }

    /// Check the current external authority head for the exact successor.
    fn loss_successor_continuity(
        &self,
        _scope: &JournalScope,
        _request: &LossSuccessorRequest,
    ) -> crate::Result<()> {
        Err("loss successor continuity missing".into())
    }

    /// Authorize [`Journal::abort_loss_successor`]. The default is
    /// deliberately deny.
    ///
    /// An implementation **must**:
    ///
    /// * prove that the replacement member and generation named by
    ///   `successor` are **durably fenced** under `abort.fencing_ref`. The
    ///   replacement may already have installed the successor membership and
    ///   may still be running; an abort that is not backed by durable fencing
    ///   leaves a live node that believes it is a member of the pair; and
    /// * consult the **live** external authority head, not the signature.
    ///   A signed abort is an instruction, and an instruction that was
    ///   superseded before it was recorded must not be recorded.
    fn successor_abort_authorized(
        &self,
        _scope: &JournalScope,
        _loss: &LossRequest,
        _successor: &LossSuccessorRequest,
        _abort: &LossSuccessorAbort,
    ) -> crate::Result<()> {
        Err("loss successor abort evidence missing".into())
    }

    /// Authorize a superseding [`LossRequest`], i.e. one carrying
    /// [`Supersedes`]. The default is deliberately deny.
    ///
    /// An implementation **must** verify, against the live successor journal
    /// of `previous_loss`, that an abort with exactly
    /// `supersedes.abort_certificate` and `supersedes.abort_token_digest` is
    /// **recorded** there. The source journal is a different file and cannot
    /// read it, so this hook is the only thing standing between a superseding
    /// loss and a replacement that was never actually cancelled — which would
    /// leave two live replacements for one lost member.
    fn superseded_successor_aborted(
        &self,
        _scope: &JournalScope,
        _previous_loss: &LossRequest,
        _supersedes: &Supersedes,
    ) -> crate::Result<()> {
        Err("superseded loss abort evidence missing".into())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LossRecord {
    request: LossRequest,
    token: String,
    certificate_id: Id,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SuccessorAbortRecord {
    format: u32,
    abort: LossSuccessorAbort,
    token: String,
    certificate_id: Id,
}

/// Every member, generation and membership this lineage has already burnt:
/// lost members, superseded or aborted replacements, and every membership the
/// pair has left behind, including the original one.
///
/// Carried forward from journal to journal so that a recovery three losses
/// deep still refuses to bring back the member lost by the first one.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Retired {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    members: Vec<Id>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    generations: Vec<Id>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    memberships: Vec<Id>,
}

impl Retired {
    fn is_empty(&self) -> bool {
        self.members.is_empty() && self.generations.is_empty() && self.memberships.is_empty()
    }
    fn push(&mut self, member: Id, generation: Id, membership: Id) {
        if !self.members.contains(&member) {
            self.members.push(member);
        }
        if !self.generations.contains(&generation) {
            self.generations.push(generation);
        }
        if !self.memberships.contains(&membership) {
            self.memberships.push(membership);
        }
    }
    fn contains(&self, member: Id, generation: Id, membership: Id) -> bool {
        self.members.contains(&member)
            || self.generations.contains(&generation)
            || self.memberships.contains(&membership)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SuccessorParent {
    source_scope: JournalScope,
    loss: LossRecord,
    /// Absent — and therefore byte-identical to a format-1 parent record —
    /// when this lineage has retired nothing beyond its own parent loss.
    #[serde(default, skip_serializing_if = "Retired::is_empty")]
    retired: Retired,
}

#[derive(Clone)]
pub struct CommittedLoss {
    request: LossRequest,
    token: String,
    certificate_id: Id,
    token_digest: Id,
}

/// Opaque authorization to install the exact successor membership locally
/// before participant acknowledgements. It is not a completed transition and
/// cannot authorize writes.
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{CommittedLossSuccessorTransition, CompletedTransition};
/// fn admit_writes(_: CompletedTransition) {}
/// fn install_only(proof: CommittedLossSuccessorTransition) { admit_writes(proof); }
/// ```
pub struct CommittedLossSuccessorTransition {
    request: LossSuccessorRequest,
    token: String,
    token_digest: Id,
    certificate_id: Id,
    source_scope: JournalScope,
    loss_request: LossRequest,
    loss_token_digest: Id,
    loss_certificate_id: Id,
    acknowledgements: [bool; 2],
}

impl CommittedLossSuccessorTransition {
    pub fn request(&self) -> &LossSuccessorRequest {
        &self.request
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }
    pub fn source_scope(&self) -> &JournalScope {
        &self.source_scope
    }
    pub fn loss_request(&self) -> &LossRequest {
        &self.loss_request
    }
    pub fn loss_token_digest(&self) -> Id {
        self.loss_token_digest
    }
    pub fn loss_certificate_id(&self) -> Id {
        self.loss_certificate_id
    }
    pub fn acknowledgements(&self) -> [bool; 2] {
        self.acknowledgements
    }
}

/// Purpose-specific writer authority available only after both successor ACKs.
///
/// ```compile_fail
/// use terrapi_vesta_recovery::transition::{CompletedLossSuccessorTransition, CompletedTransition};
/// fn ordinary(_: CompletedTransition) {}
/// fn distinct(proof: CompletedLossSuccessorTransition) { ordinary(proof); }
/// ```
pub struct CompletedLossSuccessorTransition {
    request: LossSuccessorRequest,
    token_digest: Id,
    certificate_id: Id,
    completion: Id,
}
impl CompletedLossSuccessorTransition {
    pub fn request(&self) -> &LossSuccessorRequest {
        &self.request
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }
    pub fn completion(&self) -> Id {
        self.completion
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LossSuccessorRecord {
    request: LossSuccessorRequest,
    token: String,
    certificate_id: Id,
    acknowledgements: [bool; 2],
    completion: Option<Id>,
}
impl CommittedLoss {
    pub fn request(&self) -> &LossRequest {
        &self.request
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn certificate_id(&self) -> Id {
        self.certificate_id
    }
    pub fn token_digest(&self) -> Id {
        self.token_digest
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LossClaims {
    version: u32,
    iss: String,
    aud: String,
    action: String,
    certificate_id: Id,
    iat: u64,
    nbf: u64,
    exp: u64,
    request: LossRequest,
    request_digest: Id,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LossSuccessorClaims {
    version: u32,
    iss: String,
    aud: String,
    action: String,
    certificate_id: Id,
    iat: u64,
    nbf: u64,
    exp: u64,
    request: LossSuccessorRequest,
    request_digest: Id,
}

/// Issuance-time verification of a loss successor token; the only successor
/// API that checks `now`. Returns the certificate id, which is the same value
/// [`CommittedLossSuccessorTransition::certificate_id`] exposes.
pub fn verify_successor_issuance(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossSuccessorRequest,
    now: u64,
) -> Result<Id, &'static str> {
    verify_loss_successor(token, trust, expected, Some(now))
}

/// Durable-proof verification of a loss successor token.
///
/// A recovered pair that loses a *second* participant closes its founding
/// successor journal: every fetch there answers "superseded by participant
/// loss". The replacement installed by the second loss therefore cannot ask
/// that journal for the founding successor, yet it must authenticate it to
/// derive its own role from the canonical participant order. This is how: the
/// operator supplies the request and token, and the signed loss pins them
/// through `source_certificate` and `source_token_digest`.
pub fn verify_successor_historical(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossSuccessorRequest,
) -> Result<Id, &'static str> {
    verify_loss_successor(token, trust, expected, None)
}

fn verify_loss_successor(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossSuccessorRequest,
    now: Option<u64>,
) -> Result<Id, &'static str> {
    expected.validate()?;
    trust.profile.validate()?;
    if token.len() > MAX_TOKEN {
        return Err("token limit");
    }
    let mut parts = token.split('.');
    let h = parts.next().ok_or("header")?;
    let p = parts.next().ok_or("payload")?;
    let s = parts.next().ok_or("signature")?;
    if parts.next().is_some() || h.len() > 1024 {
        return Err("compact shape");
    }
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| "header schema")?;
    if header.alg != "ES256" || header.typ != LOSS_SUCCESSOR_TOKEN_TYPE || header.kid.is_empty() {
        return Err("header purpose");
    }
    let mut keys = trust.keys.iter().filter(|(kid, _)| kid == &header.kid);
    let key = &keys.next().ok_or("untrusted key")?.1;
    if keys.next().is_some() {
        return Err("ambiguous key");
    }
    let sig = decode(s)?;
    if sig.len() != 64 {
        return Err("signature shape");
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
        .verify(&token.as_bytes()[..h.len() + 1 + p.len()], &sig)
        .map_err(|_| "signature")?;
    let c: LossSuccessorClaims = serde_json::from_slice(&decode(p)?).map_err(|_| "claim schema")?;
    let life = c.exp.checked_sub(c.iat).ok_or("time order")?;
    if c.version != 1
        || c.iss != trust.profile.issuer
        || c.aud != trust.profile.audience
        || c.action != "activate_loss_successor"
        || c.certificate_id == [0; 32]
        || life == 0
        || life > trust.max_lifetime
        || c.iat > c.nbf
        || c.nbf >= c.exp
    {
        return Err("claim purpose");
    }
    if now.is_some_and(|n| c.nbf > n || n >= c.exp) {
        return Err("time window");
    }
    if c.request != *expected || c.request_digest != expected.digest()? {
        return Err("request binding");
    }
    Ok(c.certificate_id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessorAbortClaims {
    version: u32,
    iss: String,
    aud: String,
    action: String,
    certificate_id: Id,
    iat: u64,
    nbf: u64,
    exp: u64,
    request: LossSuccessorAbort,
    request_digest: Id,
}

/// Issuance-time verification of a successor abort token; the only successor
/// abort API that checks `now`.
pub fn verify_successor_abort_issuance(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossSuccessorAbort,
    now: u64,
) -> Result<Id, &'static str> {
    verify_successor_abort(token, trust, expected, Some(now))
}

/// Durable-proof verification of a successor abort token. Expiration is not
/// re-applied after valid issuance: the abort is terminal, so there is nothing
/// a stale abort could roll back to.
pub fn verify_successor_abort_historical(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossSuccessorAbort,
) -> Result<Id, &'static str> {
    verify_successor_abort(token, trust, expected, None)
}

fn verify_successor_abort(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossSuccessorAbort,
    now: Option<u64>,
) -> Result<Id, &'static str> {
    expected.validate()?;
    trust.profile.validate()?;
    if token.len() > MAX_TOKEN {
        return Err("token limit");
    }
    let mut parts = token.split('.');
    let h = parts.next().ok_or("header")?;
    let p = parts.next().ok_or("payload")?;
    let s = parts.next().ok_or("signature")?;
    if parts.next().is_some() || h.len() > 1024 {
        return Err("compact shape");
    }
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| "header schema")?;
    if header.alg != "ES256"
        || header.typ != LOSS_SUCCESSOR_ABORT_TOKEN_TYPE
        || header.kid.is_empty()
    {
        return Err("header purpose");
    }
    let mut keys = trust.keys.iter().filter(|(kid, _)| kid == &header.kid);
    let key = &keys.next().ok_or("untrusted key")?.1;
    if keys.next().is_some() {
        return Err("ambiguous key");
    }
    let sig = decode(s)?;
    if sig.len() != 64 {
        return Err("signature shape");
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
        .verify(&token.as_bytes()[..h.len() + 1 + p.len()], &sig)
        .map_err(|_| "signature")?;
    let c: SuccessorAbortClaims =
        serde_json::from_slice(&decode(p)?).map_err(|_| "claim schema")?;
    let life = c.exp.checked_sub(c.iat).ok_or("time order")?;
    if c.version != 1
        || c.iss != trust.profile.issuer
        || c.aud != trust.profile.audience
        || c.action != "abort_loss_successor"
        || c.certificate_id == [0; 32]
        || life == 0
        || life > trust.max_lifetime
        || c.iat > c.nbf
        || c.nbf >= c.exp
    {
        return Err("claim purpose");
    }
    if now.is_some_and(|n| c.nbf > n || n >= c.exp) {
        return Err("time window");
    }
    if c.request != *expected || c.request_digest != expected.digest()? {
        return Err("request binding");
    }
    Ok(c.certificate_id)
}

/// Issuance-time verification of a participant loss token; the only loss API
/// that checks `now`. Returns the certificate id, the same value
/// [`CommittedLoss::certificate_id`] exposes.
pub fn verify_loss_issuance(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossRequest,
    now: u64,
) -> Result<Id, &'static str> {
    verify(token, trust, expected, Some(now))
}

/// Durable-proof verification of a participant loss token, for a node that
/// holds the request and token but cannot reach the journal that recorded
/// them. Expiration is not re-applied after valid issuance; the caller must
/// separately establish that this loss is still the effective one.
pub fn verify_loss_historical(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossRequest,
) -> Result<Id, &'static str> {
    verify(token, trust, expected, None)
}

fn verify(
    token: &str,
    trust: &Trust<'_>,
    expected: &LossRequest,
    now: Option<u64>,
) -> Result<Id, &'static str> {
    expected.validate()?;
    trust.profile.validate()?;
    if token.len() > MAX_TOKEN {
        return Err("token limit");
    }
    let mut parts = token.split('.');
    let h = parts.next().ok_or("header")?;
    let p = parts.next().ok_or("payload")?;
    let s = parts.next().ok_or("signature")?;
    if parts.next().is_some() || h.len() > 1024 {
        return Err("compact shape");
    }
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| "header schema")?;
    if header.alg != "ES256" || header.typ != LOSS_TOKEN_TYPE || header.kid.is_empty() {
        return Err("header purpose");
    }
    let mut keys = trust.keys.iter().filter(|(kid, _)| kid == &header.kid);
    let key = &keys.next().ok_or("untrusted key")?.1;
    if keys.next().is_some() {
        return Err("ambiguous key");
    }
    let sig = decode(s)?;
    if sig.len() != 64 {
        return Err("signature shape");
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
        .verify(&token.as_bytes()[..h.len() + 1 + p.len()], &sig)
        .map_err(|_| "signature")?;
    let c: LossClaims = serde_json::from_slice(&decode(p)?).map_err(|_| "claim schema")?;
    let life = c.exp.checked_sub(c.iat).ok_or("time order")?;
    if c.version != 1
        || c.iss != trust.profile.issuer
        || c.aud != trust.profile.audience
        || c.action != "terminate_and_replace"
        || c.certificate_id == [0; 32]
        || life == 0
        || life > trust.max_lifetime
        || c.iat > c.nbf
        || c.nbf >= c.exp
    {
        return Err("claim purpose");
    }
    if now.is_some_and(|n| c.nbf > n || n >= c.exp) {
        return Err("time window");
    }
    if c.request != *expected || c.request_digest != expected.digest()? {
        return Err("request binding");
    }
    Ok(c.certificate_id)
}

impl Journal {
    /// Create the empty membership-scoped journal that must receive the first
    /// post-loss transition. The parent loss certificate is written in the
    /// same initialization transaction as the empty journal metadata.
    pub fn create_loss_successor(
        path: &Path,
        passphrase: &str,
        scope: JournalScope,
        source: &Journal,
        trust: &Trust<'_>,
        policy: &impl LossPolicy,
    ) -> crate::Result<Self> {
        scope.validate()?;
        ensure(
            !passphrase.is_empty(),
            "invalid transition journal initialization",
        )?;
        let loss = source.fetch_loss(trust, policy)?;
        let loss_token_digest = loss.token_digest();
        let request = loss.request();
        ensure(
            scope.install == request.install
                && scope.region == request.region
                && scope.scope == request.scope
                && scope.schema == request.schema
                && scope.membership == request.replacement_membership
                && scope.source_anchor == request.source_cut
                && scope.authority_id == request.authority_id
                && scope.initial_revision
                    == request
                        .revision
                        .checked_add(1)
                        .ok_or("replacement revision overflow")?,
            "replacement journal scope mismatch",
        )?;
        ensure(
            scope.profile == *trust.profile && source.scope.profile == *trust.profile,
            "replacement trust profile mismatch",
        )?;
        let expected_parent = SuccessorParent {
            source_scope: source.scope.clone(),
            retired: source.retired_identities(trust)?,
            loss: LossRecord {
                request: loss.request,
                token: loss.token,
                certificate_id: loss.certificate_id,
            },
        };
        if path.exists() {
            let this = match Self::open(path, passphrase, scope.clone(), trust) {
                Ok(this) => this,
                Err(_) => {
                    let this = Self {
                        db: Vesta::open(path, passphrase)?,
                        scope,
                    };
                    initialize_pristine_successor(&this, &expected_parent)?;
                    Self::open(path, passphrase, this.scope.clone(), trust)?
                }
            };
            this.connection(|c| {
                let tx = c.unchecked_transaction()?;
                let history = this.read(&tx, trust)?;
                ensure(
                    history.head.is_none() && read_successor(&tx, trust)?.is_none(),
                    "replacement journal is not empty",
                )?;
                let parent = read_parent(&tx, trust, &this.scope)?.ok_or("loss parent missing")?;
                ensure(
                    parent.source_scope == source.scope
                        && parent == expected_parent
                        && Sha256::digest(parent.loss.token.as_bytes()).as_slice()
                            == loss_token_digest,
                    "replacement journal parent conflict",
                )?;
                Ok(())
            })?;
            ensure(
                source.fetch_loss(trust, policy)?.token_digest() == loss_token_digest,
                "loss parent changed during resume",
            )?;
            return Ok(this);
        }
        let db = Vesta::create(path, passphrase, KdfParams::default())?;
        let this = Self { db, scope };
        initialize_pristine_successor(&this, &expected_parent)?;
        ensure(
            source.fetch_loss(trust, policy)?.token_digest() == loss_token_digest,
            "loss parent changed during initialization",
        )?;
        Ok(this)
    }

    pub fn decide_loss_successor<P: LossPolicy>(
        &self,
        request: LossSuccessorRequest,
        token: &str,
        now: u64,
        trust: &Trust<'_>,
        policy: &P,
    ) -> crate::Result<CommittedLossSuccessorTransition> {
        request.validate()?;
        ensure(token.len() <= MAX_TOKEN, "token limit")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            ensure(
                self.read(&tx, trust)?.head.is_none(),
                "ordinary successor history forbidden",
            )?;
            ensure_successor_live(&tx, trust)?;
            ensure_successor_not_aborted(&tx, trust)?;
            let parent = read_parent(&tx, trust, &self.scope)?.ok_or("loss parent missing")?;
            // Whether an identity may be used at all is decided before
            // whether it matches the loss: a retired member is refused as a
            // retired member, never as a binding mismatch.
            let replacement = request.replacement()?;
            ensure(
                !parent.retired.contains(
                    replacement.member,
                    replacement.generation,
                    request.membership,
                ),
                "replacement transition reuses a retired identity",
            )?;
            let loss = &parent.loss.request;
            validate_successor_request(&self.scope, loss, &request)?;
            let parent_digest: Id = Sha256::digest(parent.loss.token.as_bytes()).into();
            ensure(
                request.parent_loss_certificate == parent.loss.certificate_id
                    && request.parent_loss_token_digest == parent_digest,
                "replacement parent binding mismatch",
            )?;
            // Exact retry: skips the fresh `now` check only; both live
            // hooks below still run before the stored decision is returned.
            if let Some(old) = read_successor(&tx, trust)? {
                ensure(
                    old.request == request && old.token == token,
                    "immutable replacement transition conflict",
                )?;
                policy.continuity_and_fencing(&parent.source_scope, loss)?;
                policy.loss_successor_continuity(&self.scope, &request)?;
                return committed_successor(old, parent);
            }
            policy.continuity_and_fencing(&parent.source_scope, loss)?;
            policy.loss_successor_continuity(&self.scope, &request)?;
            let certificate_id = verify_loss_successor(token, trust, &request, Some(now))?;
            policy.continuity_and_fencing(&parent.source_scope, loss)?;
            policy.loss_successor_continuity(&self.scope, &request)?;
            let record = LossSuccessorRecord {
                request,
                token: token.into(),
                certificate_id,
                acknowledgements: [false; 2],
                completion: None,
            };
            save_successor(&tx, &record)?;
            tx.commit()?;
            committed_successor(record, parent)
        })
    }

    /// Revalidate the decided successor and its authenticated loss parent for
    /// local membership installation. This deliberately works before ACKs and
    /// exposes no completed-transition authority.
    pub fn fetch_loss_successor<P: LossPolicy>(
        &self,
        request: &LossSuccessorRequest,
        trust: &Trust<'_>,
        policy: &P,
    ) -> crate::Result<CommittedLossSuccessorTransition> {
        request.validate()?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            ensure(
                self.read(&tx, trust)?.head.is_none(),
                "ordinary successor history forbidden",
            )?;
            ensure_successor_live(&tx, trust)?;
            ensure_successor_not_aborted(&tx, trust)?;
            let parent = read_parent(&tx, trust, &self.scope)?.ok_or("loss parent missing")?;
            validate_successor_request(&self.scope, &parent.loss.request, request)?;
            let parent_digest: Id = Sha256::digest(parent.loss.token.as_bytes()).into();
            ensure(
                request.parent_loss_certificate == parent.loss.certificate_id
                    && request.parent_loss_token_digest == parent_digest,
                "replacement parent binding mismatch",
            )?;
            let record = read_successor(&tx, trust)?.ok_or("replacement transition missing")?;
            ensure(
                record.request == *request,
                "replacement transition unavailable",
            )?;
            policy.continuity_and_fencing(&parent.source_scope, &parent.loss.request)?;
            policy.loss_successor_continuity(&self.scope, request)?;
            committed_successor(record, parent)
        })
    }

    pub fn acknowledge_loss_successor<P: LossPolicy>(
        &self,
        decision: &CommittedLossSuccessorTransition,
        member: &Participant,
        trust: &Trust<'_>,
        policy: &P,
    ) -> crate::Result<()> {
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            self.ensure_journal_format(&tx)?;
            ensure_successor_live(&tx, trust)?;
            ensure_successor_not_aborted(&tx, trust)?;
            let parent = read_parent(&tx, trust, &self.scope)?.ok_or("loss parent missing")?;
            let mut r = read_successor(&tx, trust)?.ok_or("replacement transition missing")?;
            ensure(
                r.request == decision.request
                    && Sha256::digest(r.token.as_bytes()).as_slice() == decision.token_digest,
                "replacement handle mismatch",
            )?;
            let i = r
                .request
                .participants
                .iter()
                .position(|p| p == member)
                .ok_or("replacement member mismatch")?;
            policy.continuity_and_fencing(&parent.source_scope, &parent.loss.request)?;
            policy.loss_successor_applied(
                &parent.source_scope,
                &parent.loss.request,
                &r.request,
                member,
            )?;
            policy.continuity_and_fencing(&parent.source_scope, &parent.loss.request)?;
            policy.loss_successor_continuity(&self.scope, &r.request)?;
            if r.acknowledgements[i] {
                return Ok(());
            }
            r.acknowledgements[i] = true;
            save_successor_replace(&tx, &r)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn complete_loss_successor<P: LossPolicy>(
        &self,
        decision: &CommittedLossSuccessorTransition,
        id: Id,
        trust: &Trust<'_>,
        policy: &P,
    ) -> crate::Result<()> {
        ensure(id != [0; 32], "zero replacement completion")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            self.ensure_journal_format(&tx)?;
            ensure_successor_live(&tx, trust)?;
            ensure_successor_not_aborted(&tx, trust)?;
            let parent = read_parent(&tx, trust, &self.scope)?.ok_or("loss parent missing")?;
            let mut r = read_successor(&tx, trust)?.ok_or("replacement transition missing")?;
            ensure(
                r.request == decision.request && r.acknowledgements == [true; 2],
                "replacement completion evidence missing",
            )?;
            policy.continuity_and_fencing(&parent.source_scope, &parent.loss.request)?;
            policy.loss_successor_continuity(&self.scope, &r.request)?;
            if let Some(old) = r.completion {
                return ensure(old == id, "immutable replacement completion conflict");
            }
            r.completion = Some(id);
            save_successor_replace(&tx, &r)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn fetch_completed_loss_successor<P: LossPolicy>(
        &self,
        request: &LossSuccessorRequest,
        trust: &Trust<'_>,
        policy: &P,
    ) -> crate::Result<CompletedLossSuccessorTransition> {
        let d = self.fetch_loss_successor(request, trust, policy)?;
        ensure(
            d.acknowledgements == [true; 2],
            "replacement acknowledgements incomplete",
        )?;
        self.connection(|c| {
            self.ensure_journal_format(c)?;
            ensure_successor_live(c, trust)?;
            ensure_successor_not_aborted(c, trust)?;
            let r = read_successor(c, trust)?.ok_or("replacement transition missing")?;
            let completion = r.completion.ok_or("replacement completion missing")?;
            Ok(CompletedLossSuccessorTransition {
                request: r.request,
                token_digest: d.token_digest,
                certificate_id: d.certificate_id,
                completion,
            })
        })
    }

    /// Permanently cancel this journal's decided successor.
    ///
    /// A participant loss installs a replacement *before* it can be
    /// acknowledged, so by the time anyone discovers the replacement is wrong
    /// it may already be installed. Without this the successor journal is a
    /// one-way door and the pair is stuck with whatever it installed.
    ///
    /// Admissible until the successor is **completed**; the acknowledgements
    /// may be in any state, because acknowledging an installation is not
    /// agreeing to keep it. Afterwards this journal is terminal and the
    /// authority must issue a superseding [`LossRequest`] carrying
    /// [`Supersedes`] in the *source* journal.
    ///
    /// Abort and completion are each a single `Immediate` transaction on this
    /// file, so they are serialised: whoever commits first wins, the loser
    /// fails closed.
    pub fn abort_loss_successor<P: LossPolicy>(
        &self,
        abort: LossSuccessorAbort,
        token: &str,
        now: u64,
        trust: &Trust<'_>,
        policy: &P,
    ) -> crate::Result<CommittedLossSuccessorAbort> {
        abort.validate()?;
        ensure(token.len() <= MAX_TOKEN, "token limit")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            self.ensure_journal_format(&tx)?;
            ensure_successor_live(&tx, trust)?;
            let parent = read_parent(&tx, trust, &self.scope)?.ok_or("loss parent missing")?;
            ensure(
                abort.install == self.scope.install
                    && abort.region == self.scope.region
                    && abort.scope == self.scope.scope
                    && abort.schema == self.scope.schema
                    && abort.membership == self.scope.membership
                    && abort.authority_id == self.scope.authority_id
                    && abort.parent_loss_certificate == parent.loss.certificate_id
                    && abort.parent_loss_token_digest
                        == <Id>::from(Sha256::digest(parent.loss.token.as_bytes())),
                "loss successor abort parent binding",
            )?;
            policy.continuity_and_fencing(&parent.source_scope, &parent.loss.request)?;
            // Exact retry first: a recorded abort is immutable and terminal,
            // so every later check would reject the very request that has to
            // converge after a crash.
            //
            // It skips the fresh `now` check and
            // `successor_abort_authorized`: the replacement it would ask
            // about is already fenced and being un-installed, and the resume
            // happens with the original, by then expired, token.
            // `continuity_and_fencing` runs on both sides of the branch.
            if let Some(existing) = read_successor_abort(&tx, trust)? {
                ensure(
                    existing.abort == abort && existing.token == token,
                    "immutable loss successor abort conflict",
                )?;
                policy.continuity_and_fencing(&parent.source_scope, &parent.loss.request)?;
                return committed_successor_abort(&existing, trust);
            }
            let successor = read_successor(&tx, trust)?.ok_or("replacement transition missing")?;
            ensure(
                successor.request.id == abort.successor_id
                    && successor.certificate_id == abort.successor_certificate
                    && <Id>::from(Sha256::digest(successor.token.as_bytes()))
                        == abort.successor_token_digest
                    && successor.request.revision == abort.revision,
                "loss successor abort binding mismatch",
            )?;
            ensure(
                successor.completion.is_none(),
                "completed loss successor cannot be aborted",
            )?;
            policy.successor_abort_authorized(
                &parent.source_scope,
                &parent.loss.request,
                &successor.request,
                &abort,
            )?;
            let certificate_id = verify_successor_abort_issuance(token, trust, &abort, now)?;
            policy.continuity_and_fencing(&parent.source_scope, &parent.loss.request)?;
            let record = SuccessorAbortRecord {
                format: 2,
                abort,
                token: token.into(),
                certificate_id,
            };
            save_successor_abort(&tx, &record)?;
            tx.commit()?;
            committed_successor_abort(&record, trust)
        })
    }

    /// Live re-read of the abort that cancelled `successor`.
    ///
    /// This is what the survivor must match its local un-installation marker
    /// against after a restart. It keeps working when every other successor
    /// operation is closed, because un-installing the replacement is the one
    /// thing still left to do.
    pub fn fetch_loss_successor_abort<P: LossPolicy>(
        &self,
        successor: &LossSuccessorRequest,
        trust: &Trust<'_>,
        policy: &P,
    ) -> crate::Result<CommittedLossSuccessorAbort> {
        successor.validate()?;
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            self.ensure_journal_format(&tx)?;
            let parent = read_parent(&tx, trust, &self.scope)?.ok_or("loss parent missing")?;
            let record = read_successor_abort(&tx, trust)?.ok_or("loss successor abort missing")?;
            let decided = read_successor(&tx, trust)?.ok_or("replacement transition missing")?;
            ensure(
                decided.request == *successor
                    && record.abort.successor_id == successor.id
                    && record.abort.successor_certificate == decided.certificate_id
                    && record.abort.successor_token_digest
                        == <Id>::from(Sha256::digest(decided.token.as_bytes())),
                "loss successor abort binding mismatch",
            )?;
            policy.continuity_and_fencing(&parent.source_scope, &parent.loss.request)?;
            committed_successor_abort(&record, trust)
        })
    }

    pub fn decide_loss(
        &self,
        request: LossRequest,
        token: &str,
        now: u64,
        trust: &Trust<'_>,
        policy: &impl LossPolicy,
    ) -> crate::Result<CommittedLoss> {
        request.validate()?;
        ensure(token.len() <= MAX_TOKEN, "token limit")?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let history = self.read(&tx, trust)?;
            // The revision a non-superseding loss would take, from whichever
            // source anchors it.
            let base = match request.kind() {
                SourceKind::LossSuccessor => {
                    self.loss_from_successor(&tx, &history, &request, trust)?
                }
                SourceKind::Decided => self.loss_from_decided(&history, &request, trust)?,
                SourceKind::Completed => self.loss_from_completed(&history, &request, trust)?,
            };
            // A rollback abandons work the journal may not be able to see:
            // only the survivor knows about a request that was merely
            // prepared. The hook runs after every journal-side check.
            match (request.kind(), request.abandoned_request.as_ref()) {
                (SourceKind::Completed, Some(abandoned)) => {
                    policy.maintenance_rollback_authorized(&self.scope, &request, abandoned)?;
                }
                (SourceKind::Decided, Some(abandoned)) => {
                    policy.maintenance_finish_forward_authorized(
                        &self.scope,
                        &request,
                        abandoned,
                    )?;
                }
                _ => {}
            }
            let chain = read_loss_history(&tx, trust)?;
            let previous = chain.last();
            // Exact retry. It deliberately skips the fresh `now` check and
            // `survivor_prepared`/`maintenance_*_authorized`: a recorded loss
            // is immutable and is resumed with the same, by then possibly
            // expired, token, and the survivor it would ask about has already
            // acted on this decision. `continuity_and_fencing` still runs, so
            // a revoked or unfenced authority state still refuses.
            if let Some(old) = previous.filter(|o| o.request == request) {
                ensure(old.token == token, "immutable loss decision conflict")?;
                policy.continuity_and_fencing(&self.scope, &request)?;
                return committed_loss(old.clone(), trust);
            }
            let expected = match (&request.supersedes, previous) {
                // A loss is a one-way door unless it is explicitly superseded.
                (None, Some(_)) => return Err("immutable loss decision conflict".into()),
                (Some(_), None) => return Err("superseded loss decision missing".into()),
                (Some(s), Some(prev)) => {
                    let retired = read_parent(&tx, trust, &self.scope)?
                        .map(|p| p.retired)
                        .unwrap_or_default();
                    supersedes_previous(s, prev, &request, &chain, &retired)?;
                    policy.superseded_successor_aborted(&self.scope, &prev.request, s)?;
                    prev.request.revision
                }
                (None, None) => base,
            };
            ensure(
                request.revision == expected.checked_add(1).ok_or("loss revision overflow")?,
                "loss participant/revision mismatch",
            )?;
            let certificate_id = verify(token, trust, &request, Some(now))?;
            policy.continuity_and_fencing(&self.scope, &request)?;
            policy.survivor_prepared(&self.scope, &request)?;
            policy.continuity_and_fencing(&self.scope, &request)?;
            let record = LossRecord {
                request,
                token: token.into(),
                certificate_id,
            };
            if record.request.supersedes.is_some() {
                save_chain_record(&tx, &record)?;
            } else {
                save_record(&tx, &record)?;
            }
            tx.commit()?;
            committed_loss(record, trust)
        })
    }
    /// `SourceKind::Completed` (and every format-1 request): the loss is
    /// anchored to the last **completed** ordinary certificate.
    ///
    /// If the effective head is a decided transition that never completed,
    /// the loss must say so (`abandoned_request`) and the survivor must not
    /// have applied it; the loss then terminates that transition the way a
    /// maintenance abort would, and anchors itself to the completed record
    /// below it. A [`Journal::abort`] cannot be used here: it demands proof
    /// that *both* nodes are durably rolling back, and a lost member can
    /// never give it.
    fn loss_from_completed(
        &self,
        history: &History,
        request: &LossRequest,
        trust: &Trust<'_>,
    ) -> crate::Result<u64> {
        let head = history
            .head
            .as_ref()
            .ok_or("completed transition required")?;
        // An open decided head may never be silently ignored: the pair may
        // still be mid-apply, and a loss that pretends it is not there would
        // strand it for ever.
        let abandoning = head.completion.is_none();
        if abandoning {
            ensure(
                request.abandoned_request == Some(head.request.digest()?),
                "open decided transition must be abandoned or sourced",
            )?;
        }
        let record = if abandoning {
            history
                .completed
                .as_ref()
                .ok_or("completed transition required")?
        } else {
            head
        };
        let source = committed(record, trust)?;
        ensure(
            record.completion.is_some() && record.acknowledgements == [true; 2],
            "completed transition required",
        )?;
        let lost_index = record
            .request
            .participants
            .iter()
            .position(|p| {
                p.member == request.lost_member && p.generation == request.lost_generation
            })
            .ok_or("lost participant mismatch")?;
        // Rolling back is only possible while the survivor has not applied.
        // Its acknowledgement on the abandoned head is exactly that evidence.
        if abandoning {
            ensure(
                !head.acknowledgements[1 - lost_index],
                "abandoned transition already applied by the survivor",
            )?;
        }
        let survivor = &record.request.participants[1 - lost_index];
        ensure(
            request.install == self.scope.install
                && request.region == self.scope.region
                && request.scope == self.scope.scope
                && request.schema == self.scope.schema
                && request.membership == self.scope.membership
                && request.authority_id == self.scope.authority_id
                && request.source_certificate == source.certificate_id()
                && request.source_token_digest == source.token_digest()
                && request.source_cut == record.request.participants[0].target,
            "loss source mismatch",
        )?;
        ensure(
            request.survivor.member == survivor.member
                && request.survivor.generation == survivor.generation
                && request.survivor.old_base == survivor.old_base
                && request.replacement_member != record.request.participants[0].member
                && request.replacement_member != record.request.participants[1].member,
            "loss participant/revision mismatch",
        )?;
        // The revision comes from the monotonic counter, which a maintenance
        // abort and an abandoned decided head also consume; the source
        // certificate comes from the last completed record. Without an abort
        // table and without an abandonment the two are the same record and
        // this is byte-identical to format 1.
        Ok(history.last_revision)
    }

    /// `SourceKind::Decided`: the survivor already **applied** the decided
    /// transition, so rolling back is impossible — its history has been
    /// pruned. The loss finishes that transition forward instead, anchoring
    /// itself to the decided certificate.
    ///
    /// The decided record is never marked completed and no acknowledgement is
    /// ever written on behalf of the lost member: the loss certificate is
    /// what authenticates the unfinished transition from here on.
    fn loss_from_decided(
        &self,
        history: &History,
        request: &LossRequest,
        trust: &Trust<'_>,
    ) -> crate::Result<u64> {
        let head = history.head.as_ref().ok_or("decided transition required")?;
        ensure(head.completion.is_none(), "decided transition required")?;
        ensure(
            request.abandoned_request == Some(head.request.digest()?),
            "abandoned request must name the decided transition",
        )?;
        let source = committed(head, trust)?;
        let lost_index = head
            .request
            .participants
            .iter()
            .position(|p| {
                p.member == request.lost_member && p.generation == request.lost_generation
            })
            .ok_or("lost participant mismatch")?;
        // If the lost member already acknowledged, the survivor can
        // acknowledge too and the authority can complete the transition the
        // ordinary way; finishing forward by loss would throw that away.
        ensure(
            !head.acknowledgements[lost_index],
            "lost participant already acknowledged; complete the transition instead",
        )?;
        // Branch A requires this acknowledgement to be false, branch B
        // requires it true, so one journal state can never satisfy both and
        // the authority can never be offered a choice.
        ensure(
            head.acknowledgements[1 - lost_index],
            "finish forward requires the survivor acknowledgement",
        )?;
        let survivor = &head.request.participants[1 - lost_index];
        ensure(
            request.install == self.scope.install
                && request.region == self.scope.region
                && request.scope == self.scope.scope
                && request.schema == self.scope.schema
                && request.membership == self.scope.membership
                && request.authority_id == self.scope.authority_id
                && request.source_certificate == source.certificate_id()
                && request.source_token_digest == source.token_digest()
                && request.source_cut == head.request.participants[0].target,
            "loss source mismatch",
        )?;
        ensure(
            request.survivor.member == survivor.member
                && request.survivor.generation == survivor.generation
                && request.survivor.old_base == survivor.old_base
                && request.replacement_member != head.request.participants[0].member
                && request.replacement_member != head.request.participants[1].member,
            "loss participant/revision mismatch",
        )?;
        Ok(history.last_revision)
    }

    /// `SourceKind::LossSuccessor`: the pair already survived one loss and is
    /// losing a second participant. The anchor is the completed successor of
    /// this journal, not an ordinary transition — there is none.
    fn loss_from_successor(
        &self,
        c: &Connection,
        history: &History,
        request: &LossRequest,
        trust: &Trust<'_>,
    ) -> crate::Result<u64> {
        ensure(
            history.head.is_none(),
            "ordinary successor history forbidden",
        )?;
        let parent = read_parent(c, trust, &self.scope)?.ok_or("loss parent missing")?;
        let successor = read_successor(c, trust)?.ok_or("replacement transition missing")?;
        ensure_successor_not_aborted(c, trust)?;
        // A format-1 successor carries no role, so neither participant can be
        // proven survivor or replacement; such a pair cannot take a second
        // loss until it is re-founded.
        ensure(
            successor.request.format == 2,
            "format-1 loss successor cannot source a loss",
        )?;
        ensure(
            successor.acknowledgements == [true; 2] && successor.completion.is_some(),
            "completed replacement transition required",
        )?;
        let lost_index = successor
            .request
            .participants
            .iter()
            .position(|p| {
                p.member == request.lost_member && p.generation == request.lost_generation
            })
            .ok_or("lost participant mismatch")?;
        let survivor = &successor.request.participants[1 - lost_index];
        ensure(
            request.install == self.scope.install
                && request.region == self.scope.region
                && request.scope == self.scope.scope
                && request.schema == self.scope.schema
                && request.membership == self.scope.membership
                && request.authority_id == self.scope.authority_id
                && request.source_certificate == successor.certificate_id
                && request.source_token_digest
                    == <Id>::from(Sha256::digest(successor.token.as_bytes()))
                && request.source_cut == successor.request.survivor_cut,
            "loss source mismatch",
        )?;
        ensure(
            request.survivor.member == survivor.member
                && request.survivor.generation == survivor.generation
                && request.survivor.old_base == survivor.old_base
                && request.replacement_member != successor.request.participants[0].member
                && request.replacement_member != successor.request.participants[1].member,
            "loss participant/revision mismatch",
        )?;
        // A retired identity may never come back — not one loss deep, and not
        // three: the set travels with the lineage.
        ensure(
            !parent.retired.contains(
                request.replacement_member,
                request.replacement_generation,
                request.replacement_membership,
            ) && request.replacement_member != parent.loss.request.lost_member
                && request.replacement_generation != parent.loss.request.lost_generation
                && request.replacement_membership != parent.loss.request.membership,
            "loss replacement reuses a retired identity",
        )?;
        // The decided successor consumed `scope.initial_revision`, which the
        // ordinary counter does not know about.
        Ok(history.last_revision.max(successor.request.revision))
    }

    /// Everything this journal's lineage has burnt, ready to be handed to the
    /// successor journal it is about to found: whatever it inherited, plus
    /// its own lost member/generation/membership, plus the replacement of
    /// every loss its chain has superseded.
    fn retired_identities(&self, trust: &Trust<'_>) -> crate::Result<Retired> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let mut retired = read_parent(&tx, trust, &self.scope)?
                .map(|p| p.retired)
                .unwrap_or_default();
            let history = read_loss_history(&tx, trust)?;
            let superseded = history.len().saturating_sub(1);
            for (i, record) in history.iter().enumerate() {
                let r = &record.request;
                if i == 0 {
                    // Identical across the whole chain by construction.
                    retired.push(r.lost_member, r.lost_generation, r.membership);
                }
                if i < superseded {
                    retired.push(
                        r.replacement_member,
                        r.replacement_generation,
                        r.replacement_membership,
                    );
                }
            }
            Ok(retired)
        })
    }

    pub fn fetch_loss(
        &self,
        trust: &Trust<'_>,
        policy: &impl LossPolicy,
    ) -> crate::Result<CommittedLoss> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            self.ensure_journal_format(&tx)?;
            let record = read_record(&tx, trust)?.ok_or("loss decision missing")?;
            policy.continuity_and_fencing(&self.scope, &record.request)?;
            committed_loss(record, trust)
        })
    }
}

fn initialize_pristine_successor(journal: &Journal, parent: &SuccessorParent) -> crate::Result<()> {
    journal.connection(|c| {
        let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
        let objects: Vec<(String, String)> = tx
            .prepare(
                "SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        ensure(
            objects == vec![("table".into(), "vesta_schema".into())],
            "successor initialization is not pristine",
        )?;
        let baseline: (u64, u64) = tx.query_row(
            "SELECT count(*),COALESCE(max(version),0) FROM vesta_schema WHERE id=0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure(baseline == (1, 1), "successor Vesta baseline mismatch")?;
        tx.execute_batch("CREATE TABLE transition_scope(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL); CREATE TABLE transition_head(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL); CREATE TABLE transition_history(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32)); CREATE TABLE transition_loss_parent(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32));")?;
        ensure(
            tx.execute(
                "INSERT INTO transition_scope VALUES(1,?1)",
                [serde_json::to_string(&journal.scope)?],
            )? == 1,
            "successor scope write failed",
        )?;
        ensure(
            tx.execute(
                "INSERT INTO transition_head VALUES(1,?1)",
                [journal.scope.initial_revision - 1],
            )? == 1,
            "successor head write failed",
        )?;
        let parent = serde_json::to_string(parent)?;
        ensure(parent.len() <= 256 * 1024, "loss parent limit")?;
        ensure(
            tx.execute(
                "INSERT INTO transition_loss_parent VALUES(1,?1,?2)",
                params![parent, Sha256::digest(parent.as_bytes()).as_slice()],
            )? == 1,
            "loss parent write failed",
        )?;
        tx.commit()?;
        Ok(())
    })
}

/// A superseding loss replaces exactly one thing — the replacement — and must
/// be identical to the loss it supersedes in every other respect. Anything
/// else would let a "supersession" quietly re-decide who was lost, from what
/// cut, or on whose authority.
fn supersedes_previous(
    s: &Supersedes,
    prev: &LossRecord,
    request: &LossRequest,
    chain: &[LossRecord],
    retired: &Retired,
) -> crate::Result<()> {
    let p = &prev.request;
    ensure(
        s.loss_certificate == prev.certificate_id
            && s.loss_token_digest == <Id>::from(Sha256::digest(prev.token.as_bytes())),
        "superseded loss binding mismatch",
    )?;
    ensure(
        request.format == p.format
            && request.kind() == p.kind()
            && request.authority_id == p.authority_id
            && request.install == p.install
            && request.region == p.region
            && request.scope == p.scope
            && request.schema == p.schema
            && request.membership == p.membership
            && request.source_certificate == p.source_certificate
            && request.source_token_digest == p.source_token_digest
            && request.source_cut == p.source_cut
            && request.lost_member == p.lost_member
            && request.lost_generation == p.lost_generation
            && request.survivor == p.survivor
            && request.survivor_cut == p.survivor_cut
            && request.survivor_publication == p.survivor_publication
            && request.abandoned_request == p.abandoned_request,
        "superseding loss changes more than the replacement",
    )?;
    // A retired replacement identity may never come back, in any generation
    // of the chain: that is the whole anti-replay property of supersession.
    ensure(
        !retired.contains(
            request.replacement_member,
            request.replacement_generation,
            request.replacement_membership,
        ) && chain.iter().all(|r| {
            request.replacement_member != r.request.replacement_member
                && request.replacement_generation != r.request.replacement_generation
                && request.replacement_membership != r.request.replacement_membership
        }),
        "superseding loss reuses a retired replacement",
    )
}

fn validate_successor_request(
    scope: &JournalScope,
    loss: &LossRequest,
    request: &LossSuccessorRequest,
) -> crate::Result<()> {
    let (s, rp) = roles(request)?;
    ensure(
        request.revision == scope.initial_revision
            && request.install == loss.install
            && request.region == loss.region
            && request.scope == loss.scope
            && request.schema == loss.schema
            && request.membership == loss.replacement_membership
            && request.authority_id == loss.authority_id
            && request.source_certificate == loss.source_certificate
            && request.source_token_digest == loss.source_token_digest
            && request.source_cut == loss.source_cut
            && request.parent_loss_certificate != [0; 32]
            && request.survivor_cut == loss.survivor_cut
            && request.survivor_publication == loss.survivor_publication
            && request.participants[s].member == loss.survivor.member
            && request.participants[s].generation == loss.survivor.generation
            && request.participants[s].old_base == loss.survivor.old_base
            && request.participants[rp].member == loss.replacement_member
            && request.participants[rp].generation == loss.replacement_generation
            && request.participants.iter().all(|p| {
                p.target == loss.survivor_cut && p.publication == loss.survivor_publication
            }),
        "replacement transition binding mismatch",
    )
}

/// The single place that decides whether a decided successor has been
/// cancelled by a [`LossSuccessorAbort`]. An aborted successor journal is
/// terminal: nothing may decide, acknowledge, complete, read or source a loss
/// from it ever again.
fn ensure_successor_not_aborted(c: &Connection, trust: &Trust<'_>) -> crate::Result<()> {
    ensure(
        read_successor_abort(c, trust)?.is_none(),
        "loss successor aborted",
    )
}

/// Once a *second* loss is decided in a successor journal, the first
/// successor membership must stop being usable for anything: this is what
/// closes writer admission for the recovered pair the instant it loses
/// another participant.
fn ensure_successor_live(c: &Connection, trust: &Trust<'_>) -> crate::Result<()> {
    ensure(
        !loss_record_exists(c, trust)?,
        "loss successor superseded by participant loss",
    )
}

fn read_successor(c: &Connection, trust: &Trust<'_>) -> crate::Result<Option<LossSuccessorRecord>> {
    if !c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='transition_loss_successor')",[],|r|r.get(0))? { return Ok(None); }
    let raw: Option<(String, Vec<u8>)> = c
        .query_row(
            "SELECT record,digest FROM transition_loss_successor WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    raw.map(|(json, digest)| {
        ensure(
            json.len() <= 256 * 1024 && digest == Sha256::digest(json.as_bytes()).to_vec(),
            "replacement record integrity",
        )?;
        let r: LossSuccessorRecord = serde_json::from_str(&json)?;
        ensure(
            verify_loss_successor(&r.token, trust, &r.request, None)? == r.certificate_id,
            "replacement certificate mismatch",
        )?;
        ensure(
            r.completion
                .is_none_or(|id| id != [0; 32] && r.acknowledgements == [true; 2]),
            "invalid replacement completion",
        )?;
        Ok(r)
    })
    .transpose()
}
fn save_successor(c: &Connection, r: &LossSuccessorRecord) -> crate::Result<()> {
    let json = serde_json::to_string(r)?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS transition_loss_successor(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32));")?;
    ensure(
        c.execute(
            "INSERT INTO transition_loss_successor VALUES(1,?1,?2)",
            params![json, Sha256::digest(json.as_bytes()).as_slice()],
        )? == 1,
        "replacement write failed",
    )
}
fn save_successor_replace(c: &Connection, r: &LossSuccessorRecord) -> crate::Result<()> {
    let json = serde_json::to_string(r)?;
    ensure(
        c.execute(
            "UPDATE transition_loss_successor SET record=?1,digest=?2 WHERE id=1",
            params![json, Sha256::digest(json.as_bytes()).as_slice()],
        )? == 1,
        "replacement update failed",
    )
}
fn committed_successor(
    r: LossSuccessorRecord,
    parent: SuccessorParent,
) -> crate::Result<CommittedLossSuccessorTransition> {
    Ok(CommittedLossSuccessorTransition {
        request: r.request,
        token_digest: Sha256::digest(r.token.as_bytes()).into(),
        token: r.token,
        certificate_id: r.certificate_id,
        source_scope: parent.source_scope,
        loss_token_digest: Sha256::digest(parent.loss.token.as_bytes()).into(),
        loss_certificate_id: parent.loss.certificate_id,
        loss_request: parent.loss.request,
        acknowledgements: r.acknowledgements,
    })
}

pub(super) fn successor_parent_exists(c: &Connection) -> crate::Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='transition_loss_parent')",
        [],
        |r| r.get(0),
    )?)
}

pub(super) fn validate_successor_parent(
    c: &Connection,
    trust: &Trust<'_>,
    scope: &JournalScope,
) -> crate::Result<()> {
    if let Some(parent) = read_parent(c, trust, scope)? {
        ensure(
            parent.source_scope.profile == *trust.profile
                && parent.source_scope.install == parent.loss.request.install
                && parent.source_scope.region == parent.loss.request.region
                && parent.source_scope.scope == parent.loss.request.scope
                && parent.source_scope.schema == parent.loss.request.schema
                && parent.source_scope.membership == parent.loss.request.membership
                && parent.source_scope.authority_id == parent.loss.request.authority_id
                && scope.profile == parent.source_scope.profile
                && scope.install == parent.loss.request.install
                && scope.region == parent.loss.request.region
                && scope.scope == parent.loss.request.scope
                && scope.schema == parent.loss.request.schema
                && scope.membership == parent.loss.request.replacement_membership
                && scope.source_anchor == parent.loss.request.source_cut
                && scope.authority_id == parent.loss.request.authority_id
                && scope.initial_revision
                    == parent
                        .loss
                        .request
                        .revision
                        .checked_add(1)
                        .ok_or("replacement revision overflow")?,
            "loss parent scope mismatch",
        )?;
    }
    Ok(())
}

fn read_parent(
    c: &Connection,
    trust: &Trust<'_>,
    scope: &JournalScope,
) -> crate::Result<Option<SuccessorParent>> {
    if !successor_parent_exists(c)? {
        return Ok(None);
    }
    let raw: Option<(String, Vec<u8>)> = c
        .query_row(
            "SELECT record,digest FROM transition_loss_parent WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let record = raw
        .map(|(json, digest)| -> crate::Result<SuccessorParent> {
            ensure(
                json.len() <= 256 * 1024 && digest == Sha256::digest(json.as_bytes()).to_vec(),
                "loss parent integrity",
            )?;
            let record: SuccessorParent = serde_json::from_str(&json)?;
            ensure(
                verify(&record.loss.token, trust, &record.loss.request, None)?
                    == record.loss.certificate_id,
                "loss parent certificate mismatch",
            )?;
            Ok(record)
        })
        .transpose()?;
    ensure(record.is_some(), "loss parent missing")?;
    if let Some(record) = record.as_ref() {
        ensure(
            scope.membership == record.loss.request.replacement_membership,
            "loss parent membership mismatch",
        )?;
    }
    Ok(record)
}

fn decode_loss_row(json: &str, digest: &[u8], trust: &Trust<'_>) -> crate::Result<LossRecord> {
    ensure(
        json.len() <= 256 * 1024 && digest == Sha256::digest(json.as_bytes()).as_slice(),
        "loss record integrity",
    )?;
    let r: LossRecord = serde_json::from_str(json)?;
    ensure(
        verify(&r.token, trust, &r.request, None)? == r.certificate_id,
        "loss certificate mismatch",
    )?;
    Ok(r)
}

/// Every loss decided in this journal, oldest first: the `transition_loss`
/// singleton followed by each superseding row of `main.transition_loss_chain`.
///
/// A journal that never supersedes never creates the chain table and is
/// therefore byte-for-byte a format-1 journal.
fn read_loss_history(c: &Connection, trust: &Trust<'_>) -> crate::Result<Vec<LossRecord>> {
    // The chain is append-only, so truncating it would silently resurrect a
    // superseded replacement. Its length and tail revision are therefore
    // recorded in a singleton written in the same transaction as every row.
    let head = read_chain_head(c)?;
    let mut history = Vec::new();
    if !table_exists(c, "transition_loss")? {
        ensure(head.is_none(), "loss chain truncated")?;
        return Ok(history);
    }
    let raw: Option<(String, Vec<u8>)> = c
        .query_row(
            "SELECT record,digest FROM transition_loss WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((json, digest)) = raw else {
        return Ok(history);
    };
    let first = decode_loss_row(&json, &digest, trust)?;
    ensure(
        first.request.supersedes.is_none(),
        "loss chain root supersedes",
    )?;
    history.push(first);
    if !table_exists(c, "transition_loss_chain")? {
        ensure(head.is_none(), "loss chain truncated")?;
        return Ok(history);
    }
    let rows: i64 = c.query_row("SELECT count(*) FROM main.transition_loss_chain", [], |r| {
        r.get(0)
    })?;
    ensure(
        usize::try_from(rows).is_ok_and(|n| n <= MAX_CHAIN_ROWS),
        "loss chain row limit",
    )?;
    ensure_row_sizes(
        c,
        "SELECT count(*) FROM main.transition_loss_chain WHERE length(record)>?1",
        "loss record limit",
    )?;
    ensure(rows == 0 || head.is_some(), "loss chain head missing")?;
    let mut stmt = c.prepare(
        "SELECT revision,record,digest FROM main.transition_loss_chain ORDER BY revision",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let revision: u64 = row.get(0)?;
        let json: String = row.get(1)?;
        let digest: Vec<u8> = row.get(2)?;
        let record = decode_loss_row(&json, &digest, trust)?;
        ensure(
            revision == record.request.revision,
            "loss chain revision mismatch",
        )?;
        // Each row must name the row it replaces, so the chain cannot be
        // reordered, forked or have a link removed.
        let previous = history.last().ok_or("loss chain root missing")?;
        let s = record
            .request
            .supersedes
            .as_ref()
            .ok_or("loss chain row does not supersede")?;
        ensure(
            s.loss_certificate == previous.certificate_id
                && s.loss_token_digest == <Id>::from(Sha256::digest(previous.token.as_bytes()))
                && record.request.revision
                    == previous
                        .request
                        .revision
                        .checked_add(1)
                        .ok_or("loss revision overflow")?,
            "loss chain link mismatch",
        )?;
        history.push(record);
    }
    match head {
        None => ensure(history.len() == 1, "loss chain head missing")?,
        Some((revision, rows)) => ensure(
            usize::try_from(rows).is_ok_and(|n| n + 1 == history.len())
                && history
                    .last()
                    .is_some_and(|r| r.request.revision == revision),
            "loss chain truncated",
        )?,
    }
    Ok(history)
}

fn read_chain_head(c: &Connection) -> crate::Result<Option<(u64, u64)>> {
    if !table_exists(c, "transition_loss_head")? {
        return Ok(None);
    }
    Ok(c.query_row(
        "SELECT revision,rows FROM main.transition_loss_head WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?)
}

/// The *effective* loss: the last superseding row if there is one, else the
/// original singleton.
fn read_record(c: &Connection, trust: &Trust<'_>) -> crate::Result<Option<LossRecord>> {
    Ok(read_loss_history(c, trust)?.pop())
}

pub(super) fn loss_record_exists(c: &Connection, trust: &Trust<'_>) -> crate::Result<bool> {
    Ok(table_exists(c, "transition_loss")? && read_record(c, trust)?.is_some())
}

fn save_chain_record(c: &Connection, r: &LossRecord) -> crate::Result<()> {
    let json = serde_json::to_string(r)?;
    ensure(json.len() <= 256 * 1024, "loss record limit")?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS main.transition_loss_chain(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32)); CREATE TABLE IF NOT EXISTS main.transition_loss_head(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,rows INTEGER NOT NULL);")?;
    mark_journal_format_two(c)?;
    ensure(
        c.execute(
            "INSERT INTO main.transition_loss_chain VALUES(?1,?2,?3)",
            params![
                r.request.revision,
                json,
                Sha256::digest(json.as_bytes()).as_slice()
            ],
        )? == 1,
        "loss chain write failed",
    )?;
    let rows: i64 = c.query_row("SELECT count(*) FROM main.transition_loss_chain", [], |r| {
        r.get(0)
    })?;
    ensure(
        c.execute(
            "INSERT OR REPLACE INTO main.transition_loss_head VALUES(1,?1,?2)",
            params![r.request.revision, rows],
        )? == 1,
        "loss chain head write failed",
    )
}

fn read_successor_abort(
    c: &Connection,
    trust: &Trust<'_>,
) -> crate::Result<Option<SuccessorAbortRecord>> {
    if !table_exists(c, "transition_loss_successor_abort")? {
        return Ok(None);
    }
    ensure_row_sizes(
        c,
        "SELECT count(*) FROM main.transition_loss_successor_abort WHERE length(record)>?1",
        "loss successor abort integrity",
    )?;
    let raw: Option<(String, Vec<u8>)> = c
        .query_row(
            "SELECT record,digest FROM main.transition_loss_successor_abort WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    raw.map(|(json, digest)| {
        ensure(
            json.len() <= 256 * 1024 && digest == Sha256::digest(json.as_bytes()).to_vec(),
            "loss successor abort integrity",
        )?;
        let r: SuccessorAbortRecord = serde_json::from_str(&json)?;
        ensure(r.format == 2, "loss successor abort format")?;
        ensure(
            verify_successor_abort_historical(&r.token, trust, &r.abort)? == r.certificate_id,
            "loss successor abort certificate mismatch",
        )?;
        Ok(r)
    })
    .transpose()
}

fn save_successor_abort(c: &Connection, r: &SuccessorAbortRecord) -> crate::Result<()> {
    let json = serde_json::to_string(r)?;
    ensure(json.len() <= 256 * 1024, "loss successor abort limit")?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS main.transition_loss_successor_abort(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32));")?;
    mark_journal_format_two(c)?;
    ensure(
        c.execute(
            "INSERT INTO main.transition_loss_successor_abort VALUES(1,?1,?2)",
            params![json, Sha256::digest(json.as_bytes()).as_slice()],
        )? == 1,
        "loss successor abort write failed",
    )
}

fn committed_successor_abort(
    r: &SuccessorAbortRecord,
    trust: &Trust<'_>,
) -> crate::Result<CommittedLossSuccessorAbort> {
    let certificate_id = verify_successor_abort_historical(&r.token, trust, &r.abort)?;
    ensure(
        certificate_id == r.certificate_id,
        "loss successor abort certificate mismatch",
    )?;
    Ok(CommittedLossSuccessorAbort {
        abort: r.abort.clone(),
        token: r.token.clone(),
        token_digest: Sha256::digest(r.token.as_bytes()).into(),
        certificate_id,
    })
}
fn save_record(c: &Connection, r: &LossRecord) -> crate::Result<()> {
    let json = serde_json::to_string(r)?;
    ensure(json.len() <= 256 * 1024, "loss record limit")?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS transition_loss(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32));")?;
    ensure(
        c.execute(
            "INSERT INTO transition_loss VALUES(1,?1,?2)",
            params![json, Sha256::digest(json.as_bytes()).as_slice()],
        )? == 1,
        "loss record write failed",
    )
}
fn committed_loss(r: LossRecord, trust: &Trust<'_>) -> crate::Result<CommittedLoss> {
    let certificate_id = verify(&r.token, trust, &r.request, None)?;
    Ok(CommittedLoss {
        request: r.request,
        token_digest: Sha256::digest(r.token.as_bytes()).into(),
        token: r.token,
        certificate_id,
    })
}
