//! Redacted test-only observations. No writes, issuer or permits.
//! Each DB is read consistently; the three observations are NOT one snapshot.
use super::{
    model::Plan,
    peers::{Local, Phase},
    recovery_grant::Context,
    recovery_registry::Registry,
    store::Store,
};
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum Member {
    Unavailable,
    Invalid,
    Prepared,
    ActiveWithPublishedBinding,
    ActiveWithoutBinding,
    ActiveUnverified,
    GrantMismatch,
    Quarantined,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum RegistryState {
    Unavailable,
    Invalid,
    Empty,
    Reserved,
    Published,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum Authorization {
    NotChecked,
    Rejected,
    ValidAtObservation,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum Pair {
    InspectionIncomplete,
    WaitingForActivation,
    PartialActivation,
    BothActiveObserved,
    Quarantined,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum Completion {
    NotEstablished,
    Recorded,
    Unavailable,
    Invalid,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub members: [Member; 2],
    pub registry: RegistryState,
    pub authorization: Authorization,
    pub pair: Pair,
    pub completion: Completion,
    pub non_atomic_observation: bool,
}

pub fn diagnose(
    stores: [Option<&Store>; 2],
    registry: Option<&Registry>,
    plan: &Plan,
    ctx: &Context,
) -> Report {
    // Independent historical read, not a shared snapshot or authorization.
    let completion = match registry {
        None => Completion::Unavailable,
        Some(registry) => match registry.load_completion() {
            Ok(None) => Completion::NotEstablished,
            Ok(Some(record)) if record.plan == *plan => Completion::Recorded,
            _ => Completion::Invalid,
        },
    };
    let (registry_state, authorization, published) = match registry {
        None => (RegistryState::Unavailable, Authorization::NotChecked, None),
        Some(registry) => match registry.diagnostic_snapshot(ctx) {
            Err(_) => (RegistryState::Invalid, Authorization::NotChecked, None),
            Ok((record, valid)) => {
                let state = if record.token.is_some() {
                    RegistryState::Published
                } else if record.input.is_some() {
                    RegistryState::Reserved
                } else {
                    RegistryState::Empty
                };
                let auth = if record.token.is_none() {
                    Authorization::NotChecked
                } else if valid && ctx.reservation.as_ref().is_some_and(|r| r.plan == *plan) {
                    Authorization::ValidAtObservation
                } else {
                    Authorization::Rejected
                };
                (state, auth, record.token)
            }
        },
    };
    let members = std::array::from_fn(|i| {
        let Some(store) = stores[i] else {
            return Member::Unavailable;
        };
        let member = if i == 0 {
            plan.candidate
        } else {
            plan.baseline.survivor
        };
        let Ok(expected) = Local::prepared(plan.clone(), member, [1; 32]) else {
            return Member::Invalid;
        };
        let Ok((record, binding)) = store.diagnostic_snapshot(&expected.saved()) else {
            return Member::Invalid;
        };
        match record.saved.phase() {
            Phase::Quarantined => Member::Quarantined,
            Phase::Prepared => {
                if binding.is_none() {
                    Member::Prepared
                } else {
                    Member::Invalid
                }
            }
            Phase::Active => match (binding, published.as_ref()) {
                (None, _) => Member::ActiveWithoutBinding,
                (Some(_), None) => Member::ActiveUnverified,
                (Some(token), Some(published)) if &token == published => {
                    Member::ActiveWithPublishedBinding
                }
                _ => Member::GrantMismatch,
            },
        }
    });
    let pair = if members.contains(&Member::Quarantined) {
        Pair::Quarantined
    } else if members
        .iter()
        .any(|m| !matches!(m, Member::Prepared | Member::ActiveWithPublishedBinding))
    {
        Pair::InspectionIncomplete
    } else {
        match members
            .iter()
            .filter(|m| **m == Member::ActiveWithPublishedBinding)
            .count()
        {
            2 => Pair::BothActiveObserved,
            1 => Pair::PartialActivation,
            _ => Pair::WaitingForActivation,
        }
    };
    Report {
        members,
        registry: registry_state,
        authorization,
        pair,
        completion,
        non_atomic_observation: true,
    }
}
