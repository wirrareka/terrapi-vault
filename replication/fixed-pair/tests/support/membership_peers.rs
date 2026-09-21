//! Test-only suffix of membership recovery, starting after verified installation.
//! Saved is an abstract atomic record, NOT SQL/disk durability. Messages assume
//! an authenticated sender. No cryptography, real sessions or business commits.
use super::model::{Event, Id, Model, Plan};
type Result<T = ()> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Prepared,
    Active,
    Quarantined,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Saved {
    plan: Plan,
    member: Id,
    phase: Phase,
}

impl Saved {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn matches_plan(&self, plan: &Plan) -> bool {
        &self.plan == plan
    }
    pub fn same_member(&self, other: &Self) -> bool {
        self.plan == other.plan && self.member == other.member
    }
    pub fn can_follow(&self, old: &Self) -> bool {
        self.same_member(old)
            && (self.phase == old.phase
                || matches!(
                    (old.phase, self.phase),
                    (Phase::Prepared, Phase::Active | Phase::Quarantined)
                        | (Phase::Active, Phase::Quarantined)
                ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Report(Phase),
    Mutation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub plan: Plan,
    pub from: Id,
    pub to: Id,
    pub receiver_boot: Id,
    kind: Kind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Local {
    saved: Saved,
    boot: Id,
    peer_prepared: bool,
}

impl Local {
    /// Trusted fixture: installation, source/fencing proof and authorization have
    /// already succeeded. Reuse stage-15 plan validation, not its shared state.
    pub fn prepared(plan: Plan, member: Id, boot: Id) -> Result<Self> {
        let mut validator = Model::new(plan.baseline.clone());
        validator.step(&plan, Event::Authorize)?;
        if member != plan.candidate && member != plan.baseline.survivor {
            return Err("not a replacement member");
        }
        Self::restart(
            Saved {
                plan,
                member,
                phase: Phase::Prepared,
            },
            boot,
        )
    }

    /// Caller supplies a fresh non-reused boot/session incarnation. Uniqueness
    /// across host rollback is an external assumption, not proven by this model.
    pub fn restart(saved: Saved, boot: Id) -> Result<Self> {
        let mut validator = Model::new(saved.plan.baseline.clone());
        validator.step(&saved.plan, Event::Authorize)?;
        if saved.member != saved.plan.candidate && saved.member != saved.plan.baseline.survivor {
            return Err("not a replacement member");
        }
        if boot == [0; 32] {
            return Err("missing boot incarnation");
        }
        Ok(Self {
            saved,
            boot,
            peer_prepared: false,
        })
    }

    pub fn saved(&self) -> Saved {
        self.saved.clone()
    }
    pub fn boot(&self) -> Id {
        self.boot
    }
    pub fn is_active(&self) -> bool {
        self.saved.phase == Phase::Active
    }

    fn peer(&self) -> Id {
        if self.saved.member == self.saved.plan.candidate {
            self.saved.plan.baseline.survivor
        } else {
            self.saved.plan.candidate
        }
    }

    fn message(&self, receiver_boot: Id, kind: Kind) -> Message {
        Message {
            plan: self.saved.plan.clone(),
            from: self.saved.member,
            to: self.peer(),
            receiver_boot,
            kind,
        }
    }

    pub fn report(&self, receiver_boot: Id) -> Message {
        self.message(receiver_boot, Kind::Report(self.saved.phase))
    }

    pub fn activate(&mut self) -> Result {
        if self.saved.phase == Phase::Quarantined {
            return Err("quarantined");
        }
        if !self.is_active() && !self.peer_prepared {
            return Err("peer prepare missing");
        }
        self.saved.phase = Phase::Active;
        Ok(())
    }

    pub fn quarantine(&mut self) {
        self.saved.phase = Phase::Quarantined;
        self.peer_prepared = false;
    }

    /// Creates an abstract request, not a permit or acknowledgement of a write.
    pub fn mutation(&self, receiver_boot: Id) -> Result<Message> {
        if !self.is_active() || self.saved.member != self.saved.plan.candidate {
            return Err("not an active writer");
        }
        Ok(self.message(receiver_boot, Kind::Mutation))
    }

    pub fn receive(&mut self, msg: Message) -> Result {
        if msg.plan != self.saved.plan
            || msg.from != self.peer()
            || msg.to != self.saved.member
            || msg.receiver_boot != self.boot
        {
            return Err("wrong plan, member or receiver session");
        }
        if self.saved.phase == Phase::Quarantined {
            return Err("quarantined");
        }
        match msg.kind {
            Kind::Report(phase) => {
                self.peer_prepared = phase != Phase::Quarantined;
            }
            Kind::Mutation => {
                if !self.is_active() || msg.from != self.saved.plan.candidate {
                    return Err("receiver not active or sender not writer");
                }
                // Admission check only: no data changes, receipts or success ACK.
            }
        }
        Ok(())
    }

    pub fn receive_mutation(&mut self, msg: Message) -> Result {
        if msg.kind != Kind::Mutation {
            return Err("mutation required, not a report");
        }
        self.receive(msg)
    }

    pub fn receive_report(&mut self, msg: Message) -> Result {
        if !matches!(msg.kind, Kind::Report(_)) {
            return Err("report required");
        }
        self.receive(msg)
    }
}
