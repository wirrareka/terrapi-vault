//! Abstract, test-only authority. Mutex models serialization, NOT durability.
//! Continuity and validated payloads are trusted assertions, not authentication.
use super::model::{Event as MembershipEvent, Id, Model, Plan};
use std::sync::Mutex;

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    request: Id,
    // Full opaque fixture bytes, not a digest or a verified real JWS/completion.
    payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct History {
    plan: Plan,
    // Position 1=reservation, 2=publication, 3=completion. No second recovery.
    entries: Vec<Entry>,
}

struct Witness {
    state: Mutex<History>,
}

#[derive(Clone, Copy)]
struct Access {
    available: bool,
    continuity_known: bool,
}

impl Access {
    fn check(self) -> Result<()> {
        if self.available && self.continuity_known {
            Ok(())
        } else {
            Err("authority unavailable or continuity unknown")
        }
    }
}

impl Witness {
    fn new(plan: Plan) -> Self {
        Self {
            state: Mutex::new(History {
                plan,
                entries: Vec::new(),
            }),
        }
    }

    fn append(
        &self,
        access: Access,
        plan: &Plan,
        expected: usize,
        entry: Entry,
    ) -> Result<History> {
        access.check()?;
        let mut state = self.state.lock().map_err(|_| "poisoned")?;
        Model::new(plan.baseline.clone()).step(plan, MembershipEvent::Authorize)?;
        if plan.baseline != state.plan.baseline
            || (!state.entries.is_empty() && plan != &state.plan)
            || expected >= 3
            || entry.request == [0; 32]
            || entry.payload.is_empty()
            || entry.payload.len() > 32 * 1024
        {
            return Err("invalid binding or payload");
        }
        if let Some(index) = state
            .entries
            .iter()
            .position(|e| e.request == entry.request)
        {
            return if index == expected && state.entries[index] == entry {
                Ok(state.clone())
            } else {
                Err("idempotency conflict")
            };
        }
        if expected != state.entries.len() {
            return Err("sequence conflict");
        }
        state.plan = plan.clone();
        state.entries.push(entry);
        Ok(state.clone())
    }

    fn reconcile(&self, access: Access, local: &mut History) -> Result<()> {
        access.check()?;
        let state = self.state.lock().map_err(|_| "poisoned")?;
        if local.plan.baseline != state.plan.baseline
            || (!local.entries.is_empty() && local.plan != state.plan)
            || !state.entries.starts_with(&local.entries)
        {
            return Err("divergent or ahead local history");
        }
        *local = state.clone();
        Ok(())
    }
}

fn access() -> Access {
    Access {
        available: true,
        continuity_known: true,
    }
}

fn entry(n: u8) -> Entry {
    Entry {
        request: [n; 32],
        payload: vec![n; 64],
    }
}

#[test]
fn competing_restored_registries_get_only_one_reservation() {
    let (_, a) = super::fixture();
    let mut b = a.clone();
    b.candidate = [44; 32];
    let witness = Witness::new(a.clone());
    let results = std::thread::scope(|s| {
        let one = s.spawn(|| witness.append(access(), &a, 0, entry(1)));
        let two = s.spawn(|| witness.append(access(), &b, 0, entry(2)));
        [one.join().unwrap(), two.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    let mut restored = History {
        plan: a,
        entries: vec![],
    };
    witness.reconcile(access(), &mut restored).unwrap();
    assert_eq!(restored, winner);
}

#[test]
fn lost_local_updates_recover_all_three_exact_contents() {
    let (_, plan) = super::fixture();
    let witness = Witness::new(plan.clone());
    let mut local = History {
        plan: plan.clone(),
        entries: vec![],
    };
    for phase in 0..3 {
        let old = local.clone();
        let request = entry(phase as u8 + 1);
        let committed = witness
            .append(access(), &plan, phase, request.clone())
            .unwrap();
        // Abstract cut: authoritative append succeeds, local update/reply is lost.
        assert_eq!(local, old);
        witness.reconcile(access(), &mut local).unwrap();
        assert_eq!(local, committed);
        assert_eq!(local.entries.len(), phase + 1);
        assert_eq!(local.plan.revision, 5);
        assert_eq!(
            witness.append(access(), &plan, phase, request).unwrap(),
            committed
        );
    }
    assert!(witness.append(access(), &plan, 3, entry(4)).is_err());
}

#[test]
fn competing_publications_and_completions_return_only_stored_winner() {
    let (_, plan) = super::fixture();
    let witness = Witness::new(plan.clone());
    witness.append(access(), &plan, 0, entry(1)).unwrap();
    for phase in 1..3 {
        let results = std::thread::scope(|s| {
            let one = s.spawn(|| witness.append(access(), &plan, phase, entry(phase as u8 * 2)));
            let two =
                s.spawn(|| witness.append(access(), &plan, phase, entry(phase as u8 * 2 + 1)));
            [one.join().unwrap(), two.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let winner = results.into_iter().find_map(Result::ok).unwrap();
        let mut local = History {
            plan: plan.clone(),
            entries: vec![],
        };
        witness.reconcile(access(), &mut local).unwrap();
        assert_eq!(local, winner);
    }
}

#[test]
fn unavailable_or_unknown_continuity_cannot_mutate_or_reconcile() {
    let (_, plan) = super::fixture();
    let witness = Witness::new(plan.clone());
    let old = witness.append(access(), &plan, 0, entry(1)).unwrap();
    for denied in [
        Access {
            available: false,
            continuity_known: true,
        },
        Access {
            available: true,
            continuity_known: false,
        },
    ] {
        assert!(witness.append(denied, &plan, 1, entry(2)).is_err());
        let mut local = old.clone();
        assert!(witness.reconcile(denied, &mut local).is_err());
        assert_eq!(local, old); // Historical local state remains readable, not authority.
    }
    assert_eq!(*witness.state.lock().unwrap(), old);
}

#[test]
fn conflicting_retries_wrong_scope_phase_and_divergence_are_rejected() {
    let (_, plan) = super::fixture();
    let witness = Witness::new(plan.clone());
    assert!(witness.append(access(), &plan, 1, entry(1)).is_err());
    let old = witness.append(access(), &plan, 0, entry(1)).unwrap();
    let mut conflict = entry(1);
    conflict.payload.push(9);
    assert!(witness.append(access(), &plan, 0, conflict).is_err());
    assert!(witness.append(access(), &plan, 1, entry(1)).is_err());
    let mut wrong = plan.clone();
    wrong.baseline.scope.push_str("-other");
    assert!(witness.append(access(), &wrong, 1, entry(2)).is_err());
    for entries in [vec![entry(9)], vec![entry(1), entry(2)]] {
        let mut local = History {
            plan: plan.clone(),
            entries,
        };
        let before = local.clone();
        assert!(witness.reconcile(access(), &mut local).is_err());
        assert_eq!(local, before);
    }
    assert_eq!(*witness.state.lock().unwrap(), old);
}

#[test]
fn witness_rollback_requires_external_continuity_not_a_local_receipt() {
    let (_, plan) = super::fixture();
    let witness = Witness::new(plan.clone());
    let receipt = witness.append(access(), &plan, 0, entry(1)).unwrap();
    witness.append(access(), &plan, 1, entry(2)).unwrap();
    let restored = Witness {
        state: Mutex::new(receipt.clone()),
    };
    let unknown = Access {
        available: true,
        continuity_known: false,
    };
    assert!(restored.append(unknown, &plan, 1, entry(9)).is_err());
    // Deliberately false trust assertion demonstrates the model's unsolved boundary:
    // a local old image cannot discover its own rollback.
    let unsafe_result = restored.append(access(), &plan, 1, entry(9)).unwrap();
    assert_ne!(unsafe_result, *witness.state.lock().unwrap());
    assert_eq!(unsafe_result.entries.len(), 2);
}
