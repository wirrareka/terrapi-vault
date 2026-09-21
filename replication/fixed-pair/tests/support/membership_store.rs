//! Private fixture store on real encrypted Vesta. Not a runtime recovery API.
//! Transition authorization and initial installation remain model assumptions.
use super::{
    model::Id,
    peers::{Local, Message, Saved},
    recovery_grant::Context,
    recovery_registry::Registry,
};
use rusqlite::Connection;
use std::path::Path;
use terrapi_vesta::{KdfParams, Vesta};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSPHRASE: &str = "membership-fixture-only";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub saved: Saved,
    pub revision: u64,
}
pub enum Crash {
    None,
    BeforeCommit,
    AfterCommit,
}
pub struct Store {
    db: Vesta,
}

impl Store {
    pub fn create(path: &Path, saved: Saved) -> Result<Self> {
        if path.exists() {
            return Err("fixture target already exists".into());
        }
        Local::restart(saved.clone(), [1; 32])?;
        let store = Self {
            db: Vesta::create(path, PASSPHRASE, KdfParams::default())?,
        };
        store.connection(|c| {
            let tx = c.unchecked_transaction()?;
            tx.execute_batch("CREATE TABLE recovery(id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL,revision INTEGER NOT NULL CHECK(revision>=0),record TEXT NOT NULL);
                CREATE TABLE recovery_steps(revision INTEGER PRIMARY KEY,record TEXT NOT NULL);
                CREATE TABLE synthetic_admissions(id INTEGER PRIMARY KEY);
                CREATE TABLE recovery_grants(id INTEGER PRIMARY KEY CHECK(id=1),token TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0));")?;
            let json = serde_json::to_string(&saved)?;
            tx.execute("INSERT INTO recovery VALUES(1,1,0,?1)", [&json])?;
            tx.execute("INSERT INTO recovery_steps VALUES(0,?1)", [&json])?;
            tx.commit()?; Ok(())
        })?;
        Ok(store)
    }
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            db: Vesta::open(path, PASSPHRASE)?,
        })
    }
    pub fn connection<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.db.with_connection(|c| {
            c.pragma_update(None, "synchronous", "FULL")?;
            c.pragma_update(None, "temp_store", "MEMORY")?;
            Ok(f(c))
        })?
    }
    fn read(c: &Connection, expected: &Saved) -> Result<Record> {
        let (format, revision, json): (u32, u64, String) = c.query_row(
            "SELECT format,revision,record FROM recovery WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if format != 1 {
            return Err("unsupported fixture record format".into());
        }
        let saved: Saved = serde_json::from_str(&json)?;
        Local::restart(saved.clone(), [1; 32])?;
        if !saved.same_member(expected) {
            return Err("fixture scope mismatch".into());
        }
        let (count, min, max): (u64,u64,u64) = c.query_row(
            "SELECT count(*),coalesce(min(revision),0),coalesce(max(revision),0) FROM recovery_steps", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let last: String = c.query_row(
            "SELECT record FROM recovery_steps WHERE revision=?1",
            [revision],
            |r| r.get(0),
        )?;
        if revision.checked_add(1) != Some(count) || min != 0 || max != revision || last != json {
            return Err("transition record mismatch".into());
        }
        Ok(Record { saved, revision })
    }
    pub fn load(&self, expected: &Saved) -> Result<Record> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let r = Self::read(&tx, expected)?;
            tx.commit()?;
            Ok(r)
        })
    }
    pub fn update(&self, expected: &Record, next: Saved, crash: Crash) -> Result {
        Local::restart(next.clone(), [1; 32])?;
        if !next.can_follow(&expected.saved) {
            return Err("invalid transition".into());
        }
        self.connection(|c| {
            let tx =
                rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            let current = Self::read(&tx, &expected.saved)?;
            if current != *expected {
                return Err("stale recovery writer".into());
            }
            if next == current.saved {
                return Ok(());
            }
            let revision = current
                .revision
                .checked_add(1)
                .filter(|v| *v <= i64::MAX as u64)
                .ok_or("revision overflow")?;
            let json = serde_json::to_string(&next)?;
            tx.execute(
                "UPDATE recovery SET revision=?1,record=?2 WHERE id=1",
                rusqlite::params![revision, json],
            )?;
            tx.execute(
                "INSERT INTO recovery_steps VALUES(?1,?2)",
                rusqlite::params![revision, json],
            )?;
            if matches!(crash, Crash::BeforeCommit) {
                std::process::exit(81);
            }
            tx.commit()?;
            if matches!(crash, Crash::AfterCommit) {
                std::process::exit(82);
            }
            Ok(())
        })
    }
    fn grant(c: &Connection, current: &Record) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        let binding: Option<(String, u64)> = c
            .query_row(
                "SELECT token,revision FROM recovery_grants WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((token, revision)) = binding {
            if revision == 0
                || revision > current.revision
                || token.is_empty()
                || token.len() > 16 * 1024
            {
                return Err("invalid activation binding".into());
            }
            let json: String = c.query_row(
                "SELECT record FROM recovery_steps WHERE revision=?1",
                [revision],
                |r| r.get(0),
            )?;
            let saved: Saved = serde_json::from_str(&json)?;
            if !saved.same_member(&current.saved) || !Local::restart(saved, [1; 32])?.is_active() {
                return Err("activation binding history mismatch".into());
            }
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }
    pub fn activation_token(&self, expected: &Record) -> Result<Option<String>> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let current = Self::read(&tx, &expected.saved)?;
            if current != *expected {
                return Err("stale activation read".into());
            }
            Self::grant(&tx, &current)
        })
    }
    /// One local read snapshot. Raw token stays inside diagnostic collection.
    pub fn diagnostic_snapshot(&self, expected: &Saved) -> Result<(Record, Option<String>)> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let current = Self::read(&tx, expected)?;
            let binding = Self::grant(&tx, &current)?;
            Ok((current, binding))
        })
    }
    /// Authorized suffix only: installation and authenticated peer delivery
    /// remain fixtures. Legacy update/admit methods are not production APIs.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_authorized(
        &self,
        expected: &Record,
        boot: Id,
        report: Message,
        token: &str,
        registry: &Registry,
        context: impl FnOnce() -> Context,
        crash: Crash,
    ) -> Result {
        self.activate_authorized_guarded(
            expected,
            boot,
            report,
            token,
            registry,
            context,
            |_, _| Ok(()),
            crash,
        )
    }
    /// Same atomic transition, with an additional guard under all caller locks.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_authorized_guarded(
        &self,
        expected: &Record,
        boot: Id,
        report: Message,
        token: &str,
        registry: &Registry,
        context: impl FnOnce() -> Context,
        guard: impl FnOnce(&Connection, &Context) -> Result<()>,
        crash: Crash,
    ) -> Result {
        self.connection(|c| {
            let tx =
                rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            let current = Self::read(&tx, &expected.saved)?;
            if current != *expected {
                return Err("stale activation state".into());
            }
            let binding = Self::grant(&tx, &current)?;
            let mut local = Local::restart(current.saved.clone(), boot)?;
            if local.is_active() && binding.is_none() {
                return Err("active without grant binding".into());
            }
            if binding.as_deref().is_some_and(|saved| saved != token) {
                return Err("different activation grant".into());
            }
            local.receive_report(report)?;
            local.activate()?;
            registry.with_grant_guarded(token, context, guard, |grant| {
                if !current.saved.matches_plan(&grant.plan) {
                    return Err("grant targets different member plan".into());
                }
                let next = local.saved();
                if next == current.saved {
                    return Ok(());
                }
                let revision = current
                    .revision
                    .checked_add(1)
                    .filter(|v| *v <= i64::MAX as u64)
                    .ok_or("revision overflow")?;
                let json = serde_json::to_string(&next)?;
                tx.execute(
                    "UPDATE recovery SET revision=?1,record=?2 WHERE id=1",
                    rusqlite::params![revision, json],
                )?;
                tx.execute(
                    "INSERT INTO recovery_steps VALUES(?1,?2)",
                    rusqlite::params![revision, json],
                )?;
                tx.execute(
                    "INSERT INTO recovery_grants VALUES(1,?1,?2)",
                    rusqlite::params![token, revision],
                )?;
                if matches!(crash, Crash::BeforeCommit) {
                    std::process::exit(81);
                }
                tx.commit()?;
                if matches!(crash, Crash::AfterCommit) {
                    std::process::exit(82);
                }
                Ok(())
            })
        })
    }
    /// Synthetic row insertion demonstrates admission and mutation sharing a lock.
    /// It is NOT a replicated business write, receipt or success response.
    pub fn admit(&self, expected: &Record, boot: Id, msg: Message) -> Result {
        self.connection(|c| {
            let tx =
                rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            let current = Self::read(&tx, &expected.saved)?;
            if current != *expected {
                return Err("stale admission state".into());
            }
            Local::restart(current.saved, boot)?.receive_mutation(msg)?;
            tx.execute("INSERT INTO synthetic_admissions DEFAULT VALUES", [])?;
            tx.commit()?;
            Ok(())
        })
    }
    pub fn admissions(&self) -> Result<u64> {
        self.connection(|c| {
            Ok(
                c.query_row("SELECT count(*) FROM synthetic_admissions", [], |r| {
                    r.get(0)
                })?,
            )
        })
    }
}
