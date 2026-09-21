//! Recovery plan specification. No IO or runtime write authority.
//! Authorize/Isolated and checkpoint digests are external assertions to this model.
//! A step is abstractly atomic; cloning state does not demonstrate durability.

pub type Id = [u8; 32];
type Result = std::result::Result<(), &'static str>;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub scope: String,
    pub revision: u64,
    pub digest: Id,
    pub old_primary: Id,
    pub survivor: Id,
    pub survivor_generation: Id,
    /// Opaque digest representing the complete, verified source checkpoint.
    pub checkpoint: Id,
}

impl Baseline {
    /// Structural validation only; does not establish current membership.
    pub fn validate(&self) -> Result {
        if self.scope.trim().is_empty()
            || [
                self.digest,
                self.old_primary,
                self.survivor,
                self.survivor_generation,
                self.checkpoint,
            ]
            .contains(&[0; 32])
            || self.old_primary == self.survivor
        {
            Err("plan does not extend baseline")
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub recovery_id: Id,
    pub baseline: Baseline,
    pub revision: u64,
    /// Unique instance incarnation, not a reusable hostname.
    pub candidate: Id,
}

#[derive(Clone, Debug)]
pub enum Fence {
    HealthFailed,
    Isolated(Id),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tail {
    Quiescent,
    Prepared,
    Decided,
    Corrupt,
    Unknown,
}

#[derive(Clone, Debug)]
pub enum Event {
    /// Models a serialized external operator authorization, not a verifier.
    Authorize,
    Fence(Fence),
    Seal {
        checkpoint: Id,
        tail: Tail,
    },
    Install(Id),
    Prepare(Id),
    Activate(Id),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Restricted,
    Fenced,
    SourceSealed,
    CandidateInstalled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    baseline: Baseline,
    plan: Option<Plan>,
    phase: Phase,
    prepared: [bool; 2],
    active: [bool; 2],
}

impl Model {
    /// Baseline is an authenticated current-state fixture, not a parsed DB image.
    pub fn new(baseline: Baseline) -> Self {
        Self {
            baseline,
            plan: None,
            phase: Phase::Restricted,
            prepared: [false; 2],
            active: [false; 2],
        }
    }

    fn validate_plan(&self, p: &Plan) -> Result {
        self.baseline.validate()?;
        if p.baseline != self.baseline
            || self.baseline.revision.checked_add(1) != Some(p.revision)
            || p.recovery_id == [0; 32]
            || p.candidate == [0; 32]
            || p.candidate == self.baseline.old_primary
            || p.candidate == self.baseline.survivor
        {
            return Err("plan does not extend baseline");
        }
        if self.plan.as_ref().is_some_and(|bound| bound != p) {
            return Err("another plan already bound");
        }
        Ok(())
    }

    fn member(p: &Plan, id: Id) -> std::result::Result<usize, &'static str> {
        if id == p.candidate {
            Ok(0)
        } else if id == p.baseline.survivor {
            Ok(1)
        } else {
            Err("not a member of replacement pair")
        }
    }

    pub fn step(&mut self, p: &Plan, event: Event) -> Result {
        self.validate_plan(p)?;
        if matches!(event, Event::Authorize) {
            self.plan = Some(p.clone());
            return Ok(());
        }
        if self.plan.as_ref() != Some(p) {
            return Err("authorization required");
        }
        match event {
            Event::Authorize => unreachable!(),
            Event::Fence(proof) => {
                if !matches!(proof, Fence::Isolated(id) if id == p.baseline.old_primary) {
                    return Err("health or wrong instance is not fencing");
                }
                self.phase = self.phase.max(Phase::Fenced);
            }
            Event::Seal { checkpoint, tail } => {
                if self.phase < Phase::Fenced
                    || checkpoint != p.baseline.checkpoint
                    || tail != Tail::Quiescent
                {
                    return Err("source not fenced, matching and quiescent");
                }
                self.phase = self.phase.max(Phase::SourceSealed);
            }
            Event::Install(checkpoint) => {
                if self.phase < Phase::SourceSealed || checkpoint != p.baseline.checkpoint {
                    return Err("candidate does not match sealed source");
                }
                self.phase = self.phase.max(Phase::CandidateInstalled);
            }
            Event::Prepare(id) => {
                let member = Self::member(p, id)?;
                if self.phase != Phase::CandidateInstalled {
                    return Err("installation required");
                }
                self.prepared[member] = true;
            }
            Event::Activate(id) => {
                let member = Self::member(p, id)?;
                if self.prepared != [true; 2] {
                    return Err("both members must be prepared");
                }
                self.active[member] = true;
            }
        }
        Ok(())
    }

    pub fn both_active(&self) -> bool {
        self.active == [true; 2]
    }

    /// Abstract invariant only. No runtime caller can use this as a write permit.
    /// `peer_available` assumes a fresh authenticated observation of this same pair.
    pub fn write_eligible(&self, p: &Plan, member: Id, peer_available: bool) -> bool {
        self.plan.as_ref() == Some(p)
            && member == p.candidate
            && self.both_active()
            && peer_available
    }
}
