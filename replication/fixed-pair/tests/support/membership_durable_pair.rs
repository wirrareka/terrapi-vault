//! Two real fixture DBs, in-memory delivery and a subprocess crash boundary.
//! No production transport, fencing or two-copy business commit implementation.
use super::{
    fixture,
    model::Id,
    peers::{Local, Message, Saved},
    store::{Crash, Record, Store},
};
use std::{path::Path, process::Command};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Endpoint {
    store: Store,
    record: Record,
    local: Local,
}
impl Endpoint {
    fn open(path: &Path, expected: Saved, boot: Id) -> Result<Self> {
        let store = Store::open(path)?;
        let record = store.load(&expected)?;
        let local = Local::restart(record.saved.clone(), boot)?;
        Ok(Self {
            store,
            record,
            local,
        })
    }
    fn boot(&self) -> Id {
        self.local.boot()
    }
    fn current(&self) -> Result {
        if self.store.load(&self.record.saved)? != self.record
            || self.local.saved() != self.record.saved
        {
            return Err("endpoint must reload changed durable state".into());
        }
        Ok(())
    }
    fn report(&self, receiver_boot: Id) -> Result<Message> {
        self.current()?;
        Ok(self.local.report(receiver_boot))
    }
    fn observe(&mut self, msg: Message) -> Result {
        self.current()?;
        Ok(self.local.receive_report(msg)?)
    }
    fn activate(&mut self, crash: Crash) -> Result {
        let mut next = self.local.clone();
        next.activate()?;
        self.store.update(&self.record, next.saved(), crash)?;
        let record = self.store.load(&self.record.saved)?;
        if record.saved != next.saved() {
            return Err("state changed after commit; reload required".into());
        }
        self.record = record;
        self.local = next;
        Ok(())
    }
    fn request(&self, receiver_boot: Id) -> Result<Message> {
        self.current()?;
        Ok(self.local.mutation(receiver_boot)?)
    }
    fn admit(&self, msg: Message) -> Result {
        self.store.admit(&self.record, self.boot(), msg)
    }
}

fn seed(primary: bool) -> Saved {
    let (_, p) = fixture();
    Local::prepared(
        p.clone(),
        if primary {
            p.candidate
        } else {
            p.baseline.survivor
        },
        [1; 32],
    )
    .unwrap()
    .saved()
}
fn create_pair(dir: &Path) {
    drop(Store::create(&dir.join("p.db"), seed(true)).unwrap());
    drop(Store::create(&dir.join("s.db"), seed(false)).unwrap());
}

#[test]
fn undelivered_report_leaves_other_database_prepared_until_explicit_retry() {
    let dir = tempfile::tempdir().unwrap();
    create_pair(dir.path());
    let mut p = Endpoint::open(&dir.path().join("p.db"), seed(true), [10; 32]).unwrap();
    let s = Endpoint::open(&dir.path().join("s.db"), seed(false), [11; 32]).unwrap();
    p.observe(s.report(p.boot()).unwrap()).unwrap();
    p.activate(Crash::None).unwrap();
    let _dropped = p.report(s.boot()).unwrap();
    assert!(s.admit(p.request(s.boot()).unwrap()).is_err());
    assert_eq!(s.record.revision, 0);
    drop(p);
    drop(s);
    let p = Endpoint::open(&dir.path().join("p.db"), seed(true), [20; 32]).unwrap();
    let mut s = Endpoint::open(&dir.path().join("s.db"), seed(false), [21; 32]).unwrap();
    s.observe(p.report(s.boot()).unwrap()).unwrap();
    s.activate(Crash::None).unwrap();
    assert!(s.observe(p.request(s.boot()).unwrap()).is_err());
    assert_eq!(s.store.admissions().unwrap(), 0);
    s.admit(p.request(s.boot()).unwrap()).unwrap();
    s.activate(Crash::None).unwrap();
    assert_eq!(p.record.revision, 1);
    assert_eq!(s.record.revision, 1);
    assert_eq!(s.store.admissions().unwrap(), 1);
}

#[test]
fn failed_local_commit_does_not_publish_active_from_memory() {
    let dir = tempfile::tempdir().unwrap();
    create_pair(dir.path());
    let mut p = Endpoint::open(&dir.path().join("p.db"), seed(true), [10; 32]).unwrap();
    let s = Endpoint::open(&dir.path().join("s.db"), seed(false), [11; 32]).unwrap();
    p.observe(s.report(p.boot()).unwrap()).unwrap();
    p.store.connection(|c| { c.execute_batch("CREATE TRIGGER fail_step BEFORE INSERT ON recovery_steps BEGIN SELECT RAISE(ABORT,'fixture'); END;")?; Ok(()) }).unwrap();
    let before = p.report(s.boot()).unwrap();
    assert!(p.activate(Crash::None).is_err());
    assert_eq!(p.report(s.boot()).unwrap(), before);
    assert!(p.request(s.boot()).is_err());
    assert_eq!(p.store.load(&seed(true)).unwrap().revision, 0);
}

#[test]
fn persisted_quarantine_invalidates_cached_endpoint_and_delayed_request() {
    let dir = tempfile::tempdir().unwrap();
    create_pair(dir.path());
    let mut p = Endpoint::open(&dir.path().join("p.db"), seed(true), [10; 32]).unwrap();
    let mut s = Endpoint::open(&dir.path().join("s.db"), seed(false), [11; 32]).unwrap();
    p.observe(s.report(p.boot()).unwrap()).unwrap();
    s.observe(p.report(s.boot()).unwrap()).unwrap();
    p.activate(Crash::None).unwrap();
    s.activate(Crash::None).unwrap();
    let delayed = p.request(s.boot()).unwrap();
    let stale_report = s.report(p.boot()).unwrap();
    let mut stopped = Local::restart(s.record.saved.clone(), [12; 32]).unwrap();
    stopped.quarantine();
    Store::open(&dir.path().join("s.db"))
        .unwrap()
        .update(&s.record, stopped.saved(), Crash::None)
        .unwrap();
    assert!(s.report(p.boot()).is_err());
    assert!(s.admit(delayed).is_err());
    p.observe(stale_report).unwrap();
    drop(s);
    let s = Endpoint::open(&dir.path().join("s.db"), seed(false), [21; 32]).unwrap();
    assert!(s.admit(p.request(s.boot()).unwrap()).is_err());
    assert_eq!(s.store.admissions().unwrap(), 0);
}

#[test]
fn mismatched_durable_plans_cannot_activate_each_other() {
    let dir = tempfile::tempdir().unwrap();
    create_pair(dir.path());
    let mut p = Endpoint::open(&dir.path().join("p.db"), seed(true), [10; 32]).unwrap();
    let (_, mut other_plan) = fixture();
    other_plan.recovery_id = [90; 32];
    let other_seed = Local::prepared(other_plan.clone(), other_plan.baseline.survivor, [1; 32])
        .unwrap()
        .saved();
    drop(Store::create(&dir.path().join("other.db"), other_seed.clone()).unwrap());
    let mut other = Endpoint::open(&dir.path().join("other.db"), other_seed, [11; 32]).unwrap();
    assert!(p.observe(other.report(p.boot()).unwrap()).is_err());
    assert!(other.observe(p.report(other.boot()).unwrap()).is_err());
    assert!(p.activate(Crash::None).is_err());
    assert!(other.activate(Crash::None).is_err());
    assert_eq!(p.record.revision, 0);
    assert_eq!(other.record.revision, 0);
}

#[test]
#[ignore = "subprocess entry point for the paired fixture crash matrix"]
fn crash_child() {
    let dir = std::env::var("MEMBERSHIP_PAIR_DIR").unwrap();
    let dir = Path::new(&dir);
    let primary = std::env::var("MEMBERSHIP_PAIR_ROLE").unwrap() == "primary";
    let mut own = Endpoint::open(
        &dir.join(if primary { "p.db" } else { "s.db" }),
        seed(primary),
        [30; 32],
    )
    .unwrap();
    let peer = Endpoint::open(
        &dir.join(if primary { "s.db" } else { "p.db" }),
        seed(!primary),
        [31; 32],
    )
    .unwrap();
    own.observe(peer.report(own.boot()).unwrap()).unwrap();
    own.activate(
        if std::env::var("MEMBERSHIP_PAIR_POINT").unwrap() == "before" {
            Crash::BeforeCommit
        } else {
            Crash::AfterCommit
        },
    )
    .unwrap();
    panic!("crash hook not reached");
}

#[test]
fn asymmetric_pair_recovers_when_second_activation_process_crashes() {
    for first_primary in [true, false] {
        for after in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            create_pair(dir.path());
            let mut first = Endpoint::open(
                &dir.path().join(if first_primary { "p.db" } else { "s.db" }),
                seed(first_primary),
                [10; 32],
            )
            .unwrap();
            let second = Endpoint::open(
                &dir.path().join(if first_primary { "s.db" } else { "p.db" }),
                seed(!first_primary),
                [11; 32],
            )
            .unwrap();
            first.observe(second.report(first.boot()).unwrap()).unwrap();
            first.activate(Crash::None).unwrap();
            drop(first);
            drop(second);
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "durable_pair::crash_child", "--ignored"])
                .env("MEMBERSHIP_PAIR_DIR", dir.path())
                .env(
                    "MEMBERSHIP_PAIR_ROLE",
                    if first_primary {
                        "secondary"
                    } else {
                        "primary"
                    },
                )
                .env(
                    "MEMBERSHIP_PAIR_POINT",
                    if after { "after" } else { "before" },
                )
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(if after { 82 } else { 81 }),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut p = Endpoint::open(&dir.path().join("p.db"), seed(true), [20; 32]).unwrap();
            let mut s = Endpoint::open(&dir.path().join("s.db"), seed(false), [21; 32]).unwrap();
            assert_eq!(p.record.revision, u64::from(first_primary || after));
            assert_eq!(s.record.revision, u64::from(!first_primary || after));
            let admission = p.request(s.boot()).and_then(|m| s.admit(m));
            assert_eq!(admission.is_ok(), after);
            p.observe(s.report(p.boot()).unwrap()).unwrap();
            s.observe(p.report(s.boot()).unwrap()).unwrap();
            p.activate(Crash::None).unwrap();
            s.activate(Crash::None).unwrap();
            s.admit(p.request(s.boot()).unwrap()).unwrap();
            assert_eq!(p.record.revision, 1);
            assert_eq!(s.record.revision, 1);
        }
    }
}
