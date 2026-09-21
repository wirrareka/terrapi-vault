//! Historical projection only; not an activation permission or trust bootstrap.
use super::{
    recovery_completion::{Completion, Evidence},
    recovery_grant::Context,
    recovery_registry::{Crash, Registry, Result},
    recovery_witness_registry::Adapter,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

pub enum Cut {
    None,
    AfterAuthority,
    BeforeLocalCommit,
    AfterLocalCommit,
}

type Row = (u32, String, Vec<u8>);
fn raw(c: &Connection) -> Result<Option<Row>> {
    Ok(c.query_row(
        "SELECT format,record,digest FROM completion WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()?)
}

impl Adapter<'_> {
    pub fn complete(
        &self,
        request: &Completion,
        context: impl FnOnce() -> Context,
        access: impl Fn() -> Result<()>,
        collect: impl FnOnce() -> Result<[Evidence; 2]>,
        cut: Cut,
    ) -> Result<Completion> {
        access()?;
        // Existing immutable completion bypasses context/collector in Registry.
        // For a new completion, check access again inside its write transaction.
        self.authority.complete(
            request,
            context,
            || {
                access()?;
                collect()
            },
            Crash::None,
        )?;
        if matches!(cut, Cut::AfterAuthority) {
            std::process::exit(103);
        }
        self.project_completion(request, access, cut)
    }

    /// Rebuild history only. This returns no fresh authorization or grant token.
    pub fn reconcile_completion(
        &self,
        request: &Completion,
        access: impl Fn() -> Result<()>,
    ) -> Result<Completion> {
        self.project_completion(request, access, Cut::None)
    }

    fn project_completion(
        &self,
        request: &Completion,
        access: impl Fn() -> Result<()>,
        cut: Cut,
    ) -> Result<Completion> {
        access()?;
        self.authority.connection(|c| {
            // Same order as grant projection: authority -> local. Collectors must
            // never acquire member write locks or invoke activation here.
            let authority_tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            access()?;
            let (baseline, install, region, source) = Registry::read(&authority_tx)?;
            let completed =
                Registry::completion_record(&authority_tx)?.ok_or("no authoritative completion")?;
            if &completed != request {
                return Err("completion request conflict".into());
            }
            let row = raw(&authority_tx)?.ok_or("missing completion bytes")?;
            self.local.connection(|c| {
                let local_tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
                let (local_baseline, local_install, local_region, current) =
                    Registry::read(&local_tx)?;
                let existing = Registry::completion_record(&local_tx)?;
                let existing_row = raw(&local_tx)?;
                if local_baseline != baseline
                    || local_install != install
                    || local_region != region
                    || current.allocated_revision > source.allocated_revision
                    || current
                        .input
                        .as_ref()
                        .is_some_and(|v| Some(v) != source.input.as_ref())
                    || current
                        .token
                        .as_ref()
                        .is_some_and(|v| Some(v) != source.token.as_ref())
                    || existing.as_ref().is_some_and(|v| v != &completed)
                    || existing_row.as_ref().is_some_and(|v| v != &row)
                {
                    return Err("divergent completion projection".into());
                }
                access()?;
                if current != source {
                    local_tx.execute(
                        "UPDATE registry SET allocated=?1,input=?2,token=?3 WHERE id=1",
                        params![source.allocated_revision, source.input, source.token],
                    )?;
                }
                if existing.is_none() {
                    // Preserve exact source bytes and checksum, not reserialized JSON.
                    local_tx.execute(
                        "INSERT INTO completion VALUES(1,?1,?2,?3)",
                        params![row.0, row.1, row.2],
                    )?;
                }
                let crash = match cut {
                    Cut::BeforeLocalCommit => Crash::BeforeCommit,
                    Cut::AfterLocalCommit => Crash::AfterCommit,
                    _ => Crash::None,
                };
                Registry::commit(local_tx, crash)
            })?;
            access()?;
            Ok(completed)
        })
    }
}
