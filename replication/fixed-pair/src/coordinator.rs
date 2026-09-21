//! Fail-closed write admission. Reads never contact the replica.
use crate::*;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capabilities {
    pub readable: bool,
    /// Last observed state, not a lease or authorization token. Every write rechecks.
    pub writable: bool,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Outcome {
    NotAccepted,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteFailure {
    pub status_code: u16,
    pub operation_id: String,
    pub outcome: Outcome,
    pub retry_same_operation_id: bool,
    pub reason: String,
}
pub trait CoordinatedPrimary<C = Change, I = u32, V = View>: Primary<C, I, V> {
    fn role(&self) -> Role;
    fn identity(&self) -> &Identity<I>;
    fn local_view(&self) -> Result<V>;
    fn local_status(&self) -> Result<Status<C, I>>;
    fn operation(&self, id: &str) -> Result<Option<Entry<C, I>>>;
    fn receipt_matches(&self, receipt: &OperationReceipt, batch: &Batch<C, I>) -> Result<()>;
    fn ensure_write_ready(&self) -> Result<()>;
}
impl CoordinatedPrimary for Node {
    fn role(&self) -> Role {
        self.role
    }
    fn identity(&self) -> &Identity {
        &self.identity
    }
    fn local_view(&self) -> Result<View> {
        Node::view(self)
    }
    fn local_status(&self) -> Result<Status> {
        Node::status(self)
    }
    fn operation(&self, id: &str) -> Result<Option<Entry>> {
        Node::operation(self, id)
    }
    fn receipt_matches(&self, receipt: &OperationReceipt, batch: &Batch) -> Result<()> {
        receipt.matches(batch)
    }
    fn ensure_write_ready(&self) -> Result<()> {
        self.connection(publication::ensure_idle)
    }
}
pub struct Coordinator<R, P = Node, C = Change, I = u32, V = View> {
    primary: P,
    replica: R,
    capabilities: Capabilities,
    verified_at: Option<Instant>,
    types: std::marker::PhantomData<fn(C, I, V)>,
}
impl<R, P, C, I, V> Coordinator<R, P, C, I, V>
where
    C: Clone + Serialize + PartialEq,
    I: Clone + Serialize + PartialEq,
    R: Replica<C, I, V>,
    P: CoordinatedPrimary<C, I, V>,
{
    pub fn new(primary: P, replica: R) -> Result<Self> {
        ensure(
            primary.role() == Role::Primary,
            "coordinator requires fixed primary",
        )?;
        let readable = primary.local_view().is_ok();
        Ok(Self {
            primary,
            replica,
            capabilities: Capabilities {
                readable,
                writable: false,
                reason: "recovery_required".into(),
            },
            verified_at: None,
            types: std::marker::PhantomData,
        })
    }
    pub fn capabilities(&self) -> Capabilities {
        let mut state = self.capabilities.clone();
        if state.writable
            && self
                .verified_at
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(1))
        {
            state.writable = false;
            state.reason = "verification_expired".into();
        }
        state
    }
    pub fn view(&self) -> Result<V> {
        self.primary.local_view()
    }
    pub fn local_status(&self) -> Result<Status<C, I>> {
        self.primary.local_status()
    }
    pub fn reconcile(&mut self) -> Result<usize> {
        self.capabilities.readable = self.primary.local_view().is_ok();
        self.capabilities.writable = false;
        self.capabilities.reason = "peer_unavailable_or_recovery_required".into();
        let completed = recover(&mut self.primary, &mut self.replica)?;
        self.primary.ensure_write_ready()?;
        self.capabilities.writable = true;
        self.capabilities.reason = "replicas_synchronized".into();
        self.verified_at = Some(Instant::now());
        Ok(completed)
    }
    fn unavailable(&mut self, id: &str) -> WriteFailure {
        self.capabilities.writable = false;
        self.capabilities.reason = "peer_unavailable_or_recovery_required".into();
        // A failed retry of a previously decided operation cannot be called rejected.
        let outcome = match (self.primary.operation(id), self.primary.receipt(id)) {
            (Ok(e), Ok(None)) if e.as_ref().is_none_or(|e| e.state == State::Prepared) => {
                Outcome::NotAccepted
            }
            _ => Outcome::Unknown,
        };
        WriteFailure {
            status_code: 503,
            operation_id: id.into(),
            outcome,
            retry_same_operation_id: true,
            reason: self.capabilities.reason.clone(),
        }
    }
    pub fn write(&mut self, batch: Batch<C, I>) -> std::result::Result<WriteResult, WriteFailure> {
        let id = batch.operation_id.clone();
        let invalid = || WriteFailure {
            status_code: 400,
            operation_id: id.clone(),
            outcome: Outcome::NotAccepted,
            retry_same_operation_id: false,
            reason: "invalid_request_or_idempotency_conflict".into(),
        };
        let previous = match self.primary.operation(&id) {
            Ok(e) => e,
            Err(_) => return Err(self.unavailable(&id)),
        };
        if batch.identity != *self.primary.identity()
            || id.is_empty()
            || previous.is_some_and(|e| e.batch != batch)
        {
            return Err(invalid());
        }
        match self.primary.receipt(&id) {
            Ok(Some(r)) if self.primary.receipt_matches(&r, &batch).is_err() => {
                return Err(invalid())
            }
            Err(_) => return Err(self.unavailable(&id)),
            _ => (),
        }
        if self.reconcile().is_err() {
            return Err(self.unavailable(&id));
        }
        match self.primary.completed_result(&batch) {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => (),
            Err(_) => return Err(self.unavailable(&id)),
        }
        let e = match self.primary.prepare(batch) {
            Ok(e) => e,
            Err(e)
                if e.downcast_ref::<rusqlite::Error>()
                    .and_then(|e| e.sqlite_error_code())
                    == Some(rusqlite::ErrorCode::ConstraintViolation) =>
            {
                return Err(invalid())
            }
            Err(_) => return Err(self.unavailable(&id)),
        };
        if self.replica.stage(e).is_err() {
            return Err(self.unavailable(&id));
        }
        let decision = match self.primary.decide(&id) {
            Ok(e) => e,
            Err(_) => {
                // An I/O error while persisting COMMIT can have an uncertain disk outcome.
                let mut failure = self.unavailable(&id);
                failure.outcome = Outcome::Unknown;
                return Err(failure);
            }
        };
        if self.replica.apply(decision.clone()).is_err()
            || self.primary.apply(decision.clone()).is_err()
        {
            return Err(self.unavailable(&id));
        }
        match self.primary.receipt(&id) {
            Ok(Some(receipt)) => Ok(receipt.result),
            _ => Err(self.unavailable(&id)),
        }
    }
}
