//! Test-only two-store adapter. External continuity remains a trusted fixture.
use super::{
    recovery_grant::{validate_draft, verify, Context},
    recovery_registry::{Crash, Registry, Result},
};
use rusqlite::{params, Transaction, TransactionBehavior};

pub enum Cut {
    None,
    AfterReservation,
    AfterPublication,
    BeforeProjectionCommit,
    AfterProjectionCommit,
}

pub struct Adapter<'a> {
    pub authority: &'a Registry,
    pub local: &'a Registry,
}

impl Adapter<'_> {
    pub fn reserve(
        &self,
        input: &str,
        ctx: &Context,
        access: impl Fn() -> Result<()>,
        cut: Cut,
    ) -> Result<()> {
        access()?;
        self.authority.reserve(input, ctx, Crash::None)?;
        if matches!(cut, Cut::AfterReservation) {
            std::process::exit(101);
        }
        self.reconcile(ctx, access)
    }

    pub fn issue(
        &self,
        ctx: &Context,
        access: impl Fn() -> Result<()>,
        sign: impl FnOnce(&str) -> Result<String>,
        cut: Cut,
    ) -> Result<String> {
        // Validate/catch a divergent local projection before calling the signer.
        self.reconcile(ctx, &access)?;
        access()?;
        let token = self.authority.issue(
            ctx,
            |bytes| {
                // Recheck after acquiring the authoritative issue transaction.
                access()?;
                sign(bytes)
            },
            Crash::None,
        )?;
        if matches!(cut, Cut::AfterPublication) {
            std::process::exit(102);
        }
        self.project(ctx, &access, cut)?;
        access()?;
        verify(&token, ctx)?;
        Ok(token)
    }

    pub fn reconcile(&self, ctx: &Context, access: impl Fn() -> Result<()>) -> Result<()> {
        self.project(ctx, access, Cut::None)
    }

    fn project(&self, ctx: &Context, access: impl Fn() -> Result<()>, cut: Cut) -> Result<()> {
        access()?;
        // Fixed harness lock order: authority -> local. No inverse callbacks.
        // IMMEDIATE pins the authority while checking and committing the projection.
        self.authority.connection(|c| {
            let authority_tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
            access()?;
            let source = Registry::bound(&authority_tx, ctx)?;
            if authority_tx.query_row("SELECT EXISTS(SELECT 1 FROM completion)", [], |r| {
                r.get::<_, bool>(0)
            })? {
                return Err("completion projection not supported".into());
            }
            if let Some(input) = &source.input {
                validate_draft(input, ctx)?;
            }
            if let Some(token) = &source.token {
                verify(token, ctx)?;
            }
            self.local.connection(|c| {
                let local_tx = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
                let current = Registry::bound(&local_tx, ctx)?;
                if local_tx.query_row("SELECT EXISTS(SELECT 1 FROM completion)", [], |r| {
                    r.get::<_, bool>(0)
                })? {
                    return Err("local completion requires separate recovery".into());
                }
                if current.allocated_revision > source.allocated_revision
                    || current
                        .input
                        .as_ref()
                        .is_some_and(|v| Some(v) != source.input.as_ref())
                    || current
                        .token
                        .as_ref()
                        .is_some_and(|v| Some(v) != source.token.as_ref())
                {
                    return Err("divergent or ahead local projection".into());
                }
                access()?;
                if current != source {
                    local_tx.execute(
                        "UPDATE registry SET allocated=?1,input=?2,token=?3 WHERE id=1",
                        params![source.allocated_revision, source.input, source.token],
                    )?;
                }
                let crash = match cut {
                    Cut::BeforeProjectionCommit => Crash::BeforeCommit,
                    Cut::AfterProjectionCommit => Crash::AfterCommit,
                    _ => Crash::None,
                };
                Registry::commit(local_tx, crash)
            })
        })
    }
}
