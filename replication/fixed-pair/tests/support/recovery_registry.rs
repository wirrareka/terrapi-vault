//! One-predecessor, one-reservation operator registry fixture, outside the pair.
//! No cancellation, advancement, production signer or anti-rollback authority.
use super::{
    model::Baseline,
    recovery_grant::{validate_draft, verify, Context, VerifiedGrant},
};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use std::{path::Path, time::Duration};
use terrapi_vesta::{KdfParams, Vesta};

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSPHRASE: &str = "operator-registry-fixture-only";
pub enum Crash {
    None,
    BeforeCommit,
    AfterCommit,
    AfterSign,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub allocated_revision: u64,
    pub input: Option<String>,
    pub token: Option<String>,
}
pub struct Registry {
    db: Vesta,
}

impl Registry {
    pub fn create(path: &Path, baseline: Baseline, install: &str, region: &str) -> Result<Self> {
        if path.exists()
            || install.is_empty()
            || region.is_empty()
            || baseline.revision >= i64::MAX as u64
        {
            return Err("invalid registry initialization".into());
        }
        let db = Self {
            db: Vesta::create(path, PASSPHRASE, KdfParams::default())?,
        };
        db.connection(|c| {
            let tx = c.unchecked_transaction()?;
            tx.execute_batch(
                "CREATE TABLE registry (
                id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL,
                baseline TEXT NOT NULL, install TEXT NOT NULL, region TEXT NOT NULL,
                allocated INTEGER NOT NULL CHECK(allocated>=0), input TEXT, token TEXT,
                CHECK(token IS NULL OR input IS NOT NULL));
                CREATE TABLE completion(id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL,record TEXT NOT NULL,digest BLOB NOT NULL);",
            )?;
            tx.execute(
                "INSERT INTO registry VALUES(1,1,?1,?2,?3,?4,NULL,NULL)",
                params![
                    serde_json::to_string(&baseline)?,
                    install,
                    region,
                    baseline.revision
                ],
            )?;
            tx.commit()?;
            Ok(())
        })?;
        Ok(db)
    }
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            db: Vesta::open(path, PASSPHRASE)?,
        })
    }
    pub fn connection<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.db.with_connection(|c| {
            c.busy_timeout(Duration::from_secs(5))?;
            c.pragma_update(None, "synchronous", "FULL")?;
            c.pragma_update(None, "temp_store", "MEMORY")?;
            Ok(f(c))
        })?
    }
    pub(super) fn read(c: &Connection) -> Result<(Baseline, String, String, Record)> {
        let (format, json, install, region, allocated, input, token): (
            u32,
            String,
            String,
            String,
            u64,
            Option<String>,
            Option<String>,
        ) = c.query_row(
            "SELECT format,baseline,install,region,allocated,input,token FROM registry WHERE id=1",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )?;
        let baseline: Baseline = serde_json::from_str(&json)?;
        let expected = if input.is_some() {
            baseline.revision.checked_add(1).ok_or("overflow")?
        } else {
            baseline.revision
        };
        if format != 1
            || install.is_empty()
            || region.is_empty()
            || allocated != expected
            || allocated > i64::MAX as u64
            || (input.is_none() && token.is_some())
        {
            return Err("registry invariant".into());
        }
        if let Some(token) = &token {
            if token.rsplit_once('.').map(|(p, _)| p) != input.as_deref() {
                return Err("published input mismatch".into());
            }
        }
        Ok((
            baseline,
            install,
            region,
            Record {
                allocated_revision: allocated,
                input,
                token,
            },
        ))
    }
    pub fn load(&self) -> Result<Record> {
        self.connection(|c| Ok(Self::read(c)?.3))
    }
    /// Read-only observation, not the locked authorization used by activation.
    pub fn diagnostic_snapshot(&self, ctx: &Context) -> Result<(Record, bool)> {
        self.connection(|c| {
            let tx = c.unchecked_transaction()?;
            let record = Self::read(&tx)?.3;
            let valid = Self::bound(&tx, ctx).is_ok()
                && record
                    .token
                    .as_deref()
                    .is_some_and(|token| verify(token, ctx).is_ok());
            Ok((record, valid))
        })
    }
    /// Local harness lock only. No reusable permission escapes this callback.
    /// Callers lock the member DB first, then registry, and commit the member
    /// inside `apply`. Context is sampled after both local locks are acquired.
    pub fn with_grant<T>(
        &self,
        token: &str,
        context: impl FnOnce() -> Context,
        apply: impl FnOnce(&VerifiedGrant) -> Result<T>,
    ) -> Result<T> {
        self.with_grant_guarded(token, context, |_, _| Ok(()), apply)
    }
    /// Extra fixture guard runs with the projection lock held, before apply.
    pub fn with_grant_guarded<T>(
        &self,
        token: &str,
        context: impl FnOnce() -> Context,
        guard: impl FnOnce(&Connection, &Context) -> Result<()>,
        apply: impl FnOnce(&VerifiedGrant) -> Result<T>,
    ) -> Result<T> {
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let ctx = context();
            let record = Self::bound(&tx, &ctx)?;
            if record.token.as_deref() != Some(token) {
                return Err("grant is not current durable publication".into());
            }
            let grant = verify(token, &ctx)?;
            guard(&tx, &ctx)?;
            // No registry mutation; rollback-on-drop releases its lock after apply.
            apply(&grant)
        })
    }
    pub(super) fn bound(c: &Connection, ctx: &Context) -> Result<Record> {
        let (baseline, install, region, record) = Self::read(c)?;
        let reservation = ctx
            .reservation
            .as_ref()
            .ok_or("no trusted reservation context")?;
        if baseline != reservation.plan.baseline
            || install != ctx.install_id
            || region != ctx.region
        {
            return Err("registry scope/predecessor mismatch".into());
        }
        Ok(record)
    }
    pub fn reserve(&self, input: &str, ctx: &Context, crash: Crash) -> Result {
        validate_draft(input, ctx)?;
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let current = Self::bound(&tx, ctx)?;
            if let Some(existing) = current.input {
                return if existing == input {
                    Ok(())
                } else {
                    Err("conflicting immutable reservation".into())
                };
            }
            let revision = current
                .allocated_revision
                .checked_add(1)
                .filter(|v| *v <= i64::MAX as u64)
                .ok_or("revision overflow")?;
            tx.execute(
                "UPDATE registry SET allocated=?1,input=?2 WHERE id=1",
                params![revision, input],
            )?;
            Self::commit(tx, crash)
        })
    }
    /// Only a committed reservation may reach the signer. A token is returned
    /// only after its own commit; subsequent retries return those exact bytes.
    pub fn issue(
        &self,
        ctx: &Context,
        sign: impl FnOnce(&str) -> Result<String>,
        crash: Crash,
    ) -> Result<String> {
        self.connection(|c| {
            let tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            let current = Self::bound(&tx, ctx)?;
            let input = current.input.ok_or("not reserved")?;
            validate_draft(&input, ctx)?;
            if let Some(token) = current.token {
                verify(&token, ctx)?;
                return Ok(token);
            }
            let token = sign(&input)?;
            if matches!(crash, Crash::AfterSign) {
                std::process::exit(93);
            }
            if token.rsplit_once('.').map(|(p, _)| p) != Some(input.as_str()) {
                return Err("signer changed input".into());
            }
            verify(&token, ctx)?;
            tx.execute("UPDATE registry SET token=?1 WHERE id=1", [&token])?;
            Self::commit(tx, crash)?;
            Ok(token)
        })
    }
    pub(super) fn commit(tx: Transaction<'_>, crash: Crash) -> Result {
        if matches!(crash, Crash::BeforeCommit) {
            std::process::exit(91);
        }
        tx.commit()?;
        if matches!(crash, Crash::AfterCommit) {
            std::process::exit(92);
        }
        Ok(())
    }
}
