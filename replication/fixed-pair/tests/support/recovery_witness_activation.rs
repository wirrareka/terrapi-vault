//! Test-only witness activation boundary; no runtime promotion or trust bootstrap.
use super::{
    model::Id,
    peers::Message,
    recovery_grant::Context,
    recovery_registry::{Registry, Result},
    recovery_witness_registry::Adapter,
    store::{Crash, Record, Store},
};

pub struct Activation<'a> {
    pub expected: &'a Record,
    pub boot: Id,
    pub report: Message,
    pub token: &'a str,
}

impl Adapter<'_> {
    pub fn activate(
        &self,
        member: &Store,
        request: Activation<'_>,
        context: impl FnOnce() -> Context,
        access: impl Fn() -> Result<()>,
        crash: Crash,
    ) -> Result<()> {
        access()?;
        self.authority.connection(|c| {
            let authority_tx =
                rusqlite::Transaction::new_unchecked(c, rusqlite::TransactionBehavior::Immediate)?;
            access()?;
            // Hold authority across the existing member -> projection suffix,
            // including the member commit. No projection repair in this path.
            member.activate_authorized_guarded(
                request.expected,
                request.boot,
                request.report,
                request.token,
                self.local,
                context,
                |projection, ctx| {
                    access()?;
                    let source = Registry::bound(&authority_tx, ctx)?;
                    let local = Registry::bound(projection, ctx)?;
                    if source != local || source.token.as_deref() != Some(request.token) {
                        return Err("activation requires exact authoritative publication".into());
                    }
                    if Registry::completion_record(&authority_tx)?.is_some()
                        || Registry::completion_record(projection)?.is_some()
                    {
                        return Err("recovery completed; use historical status".into());
                    }
                    Ok(())
                },
                crash,
            )
        })
    }
}
