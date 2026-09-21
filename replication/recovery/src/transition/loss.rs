use super::*;
use crate::ensure;
use rusqlite::OptionalExtension;

pub const LOSS_TOKEN_TYPE: &str = "terrapi-participant-loss+jwt";
pub const LOSS_SUCCESSOR_TOKEN_TYPE: &str = "terrapi-loss-successor+jwt";

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

/// Evidence that a previous loss attempt was aborted and is being replaced
/// (S10). Its shape is validated here; `decide_loss` does not accept it yet.
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
    fn survivor_prepared(&self, scope: &JournalScope, request: &LossRequest) -> crate::Result<()>;

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
struct SuccessorParent {
    source_scope: JournalScope,
    loss: LossRecord,
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
            let parent = read_parent(&tx, trust, &self.scope)?.ok_or("loss parent missing")?;
            let loss = &parent.loss.request;
            validate_successor_request(&self.scope, loss, &request)?;
            let parent_digest: Id = Sha256::digest(parent.loss.token.as_bytes()).into();
            ensure(
                request.parent_loss_certificate == parent.loss.certificate_id
                    && request.parent_loss_token_digest == parent_digest,
                "replacement parent binding mismatch",
            )?;
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
            ensure_successor_live(&tx, trust)?;
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
            ensure_successor_live(&tx, trust)?;
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
            ensure_successor_live(c, trust)?;
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
        // Shapes that are validated but not yet honoured; they arrive with the
        // slices that give them meaning, and accepting one early would record
        // an unenforced claim for ever.
        ensure(
            request.kind() != SourceKind::Decided,
            "decided loss source not enabled",
        )?;
        ensure(
            request.abandoned_request.is_none(),
            "loss abandoned request not enabled",
        )?;
        ensure(
            request.supersedes.is_none(),
            "loss supersession not enabled",
        )?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let history = self.read(&tx, trust)?;
            match request.kind() {
                SourceKind::LossSuccessor => {
                    self.loss_from_successor(&tx, &history, &request, trust)?
                }
                _ => self.loss_from_completed(&history, &request, trust)?,
            }
            if let Some(old) = read_record(&tx, trust)? {
                ensure(
                    old.request == request && old.token == token,
                    "immutable loss decision conflict",
                )?;
                policy.continuity_and_fencing(&self.scope, &request)?;
                return committed_loss(old, trust);
            }
            let certificate_id = verify(token, trust, &request, Some(now))?;
            policy.continuity_and_fencing(&self.scope, &request)?;
            policy.survivor_prepared(&self.scope, &request)?;
            policy.continuity_and_fencing(&self.scope, &request)?;
            let record = LossRecord {
                request,
                token: token.into(),
                certificate_id,
            };
            save_record(&tx, &record)?;
            tx.commit()?;
            committed_loss(record, trust)
        })
    }
    /// `SourceKind::Completed` (and every format-1 request): the loss is
    /// anchored to the completed ordinary head of this journal.
    fn loss_from_completed(
        &self,
        history: &History,
        request: &LossRequest,
        trust: &Trust<'_>,
    ) -> crate::Result<()> {
        let head = history
            .head
            .as_ref()
            .ok_or("completed transition required")?;
        let source = committed(head, trust)?;
        ensure(
            head.completion.is_some() && head.acknowledgements == [true; 2],
            "completed transition required",
        )?;
        let lost_index = head
            .request
            .participants
            .iter()
            .position(|p| {
                p.member == request.lost_member && p.generation == request.lost_generation
            })
            .ok_or("lost participant mismatch")?;
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
        // The revision comes from the monotonic counter, which a maintenance
        // abort also consumes; the source certificate comes from the effective
        // head. Without an abort table the two are the same record and this is
        // byte-identical to format 1.
        ensure(
            request.revision
                == history
                    .last_revision
                    .checked_add(1)
                    .ok_or("loss revision overflow")?
                && request.survivor.member == survivor.member
                && request.survivor.generation == survivor.generation
                && request.survivor.old_base == survivor.old_base
                && request.replacement_member != head.request.participants[0].member
                && request.replacement_member != head.request.participants[1].member,
            "loss participant/revision mismatch",
        )
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
    ) -> crate::Result<()> {
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
        // The decided successor consumed `scope.initial_revision`, which the
        // ordinary counter does not know about.
        let effective = history.last_revision.max(successor.request.revision);
        ensure(
            request.revision == effective.checked_add(1).ok_or("loss revision overflow")?
                && request.survivor.member == survivor.member
                && request.survivor.generation == survivor.generation
                && request.survivor.old_base == survivor.old_base
                && request.replacement_member != successor.request.participants[0].member
                && request.replacement_member != successor.request.participants[1].member,
            "loss participant/revision mismatch",
        )?;
        // A retired identity may never come back: the member, generation and
        // membership burnt by the first loss stay burnt.
        ensure(
            request.replacement_member != parent.loss.request.lost_member
                && request.replacement_generation != parent.loss.request.lost_generation
                && request.replacement_membership != parent.loss.request.membership,
            "loss replacement reuses a retired identity",
        )
    }

    pub fn fetch_loss(
        &self,
        trust: &Trust<'_>,
        policy: &impl LossPolicy,
    ) -> crate::Result<CommittedLoss> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
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
/// cancelled by a `LossSuccessorAbort`.
///
/// S10 introduces that record type and the `transition_loss_successor_abort`
/// singleton; until then no successor can be aborted, so this is vacuously
/// satisfied. Every caller that must fail closed on an aborted successor is
/// already wired to it, so S10 only has to fill in the body.
fn ensure_successor_not_aborted(_c: &Connection, _trust: &Trust<'_>) -> crate::Result<()> {
    Ok(())
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

fn read_record(c: &Connection, trust: &Trust<'_>) -> crate::Result<Option<LossRecord>> {
    if !c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='transition_loss')",
        [],
        |r| r.get(0),
    )? {
        return Ok(None);
    }
    let raw: Option<(String, Vec<u8>)> = c
        .query_row(
            "SELECT record,digest FROM transition_loss WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    raw.map(|(json, digest)| {
        ensure(
            json.len() <= 256 * 1024 && digest == Sha256::digest(json.as_bytes()).to_vec(),
            "loss record integrity",
        )?;
        let r: LossRecord = serde_json::from_str(&json)?;
        ensure(
            verify(&r.token, trust, &r.request, None)? == r.certificate_id,
            "loss certificate mismatch",
        )?;
        Ok(r)
    })
    .transpose()
}

pub(super) fn loss_record_exists(c: &Connection, trust: &Trust<'_>) -> crate::Result<bool> {
    Ok(read_record(c, trust)?.is_some())
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
