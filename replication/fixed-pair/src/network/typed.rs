//! Explicit typed protocol; never deserializes a typed identity as the legacy
//! reference profile. Authentication, deadlines and framing use the shared TLS layer.
use super::*;
use crate::schema::SchemaId;
use crate::typed::{snapshot, Head, Node as TypedNode, Prefix, Record, ReplicatedSchema};
const PROTOCOL: &str = "vesta-typed-pair-v1";

#[derive(Serialize, Deserialize)]
enum Request<C> {
    Summary,
    CheckpointAt(u64),
    JournalPage {
        head: Head,
        after: u64,
        limit: u32,
    },
    Confirm {
        checkpoint: Prefix,
        generation: [u8; 32],
    },
    Status,
    View,
    Stage(Entry<C, SchemaId>),
    Apply(Entry<C, SchemaId>),
    Abort(String),
    SnapshotBegin(snapshot::Manifest),
    SnapshotPage(snapshot::Page),
    SnapshotFinish(snapshot::Manifest),
}
#[derive(Serialize, Deserialize)]
enum Response<C, V> {
    Summary(journal::Summary<SchemaId>),
    Checkpoint(Prefix),
    JournalPage(journal::JournalPage<C, SchemaId>),
    Status(Status<C, SchemaId>),
    View(V),
    Progress(u64),
    Ack,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<C> {
    protocol: String,
    identity: Identity<SchemaId>,
    contract: schema_contract::Contract,
    request: Request<C>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply<C, V> {
    protocol: String,
    identity: Identity<SchemaId>,
    contract: schema_contract::Contract,
    result: std::result::Result<Response<C, V>, String>,
}

pub struct TlsReplica<A: ReplicatedSchema> {
    address: SocketAddr,
    tls: ClientTls,
    identity: Identity<SchemaId>,
    contract: schema_contract::Contract,
    timeout: Duration,
    types: std::marker::PhantomData<fn() -> A>,
}
impl<A: ReplicatedSchema> TlsReplica<A> {
    pub fn new(
        address: SocketAddr,
        tls: ClientTls,
        identity: Identity<SchemaId>,
        timeout: Duration,
        adapter: &A,
    ) -> Result<Self> {
        ensure(
            !timeout.is_zero() && timeout <= Duration::from_secs(60),
            "invalid timeout",
        )?;
        ensure(
            identity.schema == adapter.identity(),
            "typed peer schema mismatch",
        )?;
        Ok(Self {
            address,
            tls,
            identity,
            contract: schema_contract::expected(adapter)?,
            timeout,
            types: std::marker::PhantomData,
        })
    }
    fn request(&mut self, request: Request<A::Change>) -> Result<Response<A::Change, A::View>> {
        let mut stream = connect_tls(self.address, &self.tls, self.timeout)?;
        write_frame(
            &mut stream,
            &Envelope {
                protocol: PROTOCOL.into(),
                identity: self.identity.clone(),
                contract: self.contract.clone(),
                request,
            },
        )?;
        let reply: Reply<A::Change, A::View> = read_frame(&mut stream)?;
        ensure(
            reply.protocol == PROTOCOL
                && reply.identity == self.identity
                && reply.contract == self.contract,
            "typed reply binding mismatch",
        )?;
        reply.result.map_err(Into::into)
    }
    pub fn begin_snapshot(&mut self, manifest: snapshot::Manifest) -> Result<u64> {
        match self.request(Request::SnapshotBegin(manifest))? {
            Response::Progress(n) => Ok(n),
            _ => Err("unexpected response".into()),
        }
    }
    pub fn receive_snapshot(&mut self, page: snapshot::Page) -> Result<u64> {
        page.encode()?;
        match self.request(Request::SnapshotPage(page))? {
            Response::Progress(n) => Ok(n),
            _ => Err("unexpected response".into()),
        }
    }
    pub fn finish_snapshot(&mut self, manifest: snapshot::Manifest) -> Result<Prefix> {
        match self.request(Request::SnapshotFinish(manifest))? {
            Response::Checkpoint(p) => Ok(p),
            _ => Err("unexpected response".into()),
        }
    }
    pub fn install_snapshot_from(&mut self, source: &mut TypedNode<A>) -> Result<Prefix> {
        let manifest = source.publish_snapshot()?;
        let next = self.begin_snapshot(manifest.clone())?;
        ensure(next <= manifest.pages, "invalid peer snapshot cursor")?;
        for n in next..manifest.pages {
            ensure(
                self.receive_snapshot(source.snapshot_page(&manifest, n)?)? == n + 1,
                "invalid peer snapshot acknowledgement",
            )?;
        }
        let checkpoint = self.finish_snapshot(manifest.clone())?;
        ensure(
            checkpoint == manifest.checkpoint,
            "restored peer checkpoint mismatch",
        )?;
        Ok(checkpoint)
    }
}
fn ack<C, V>(response: Response<C, V>) -> Result<()> {
    ensure(matches!(response, Response::Ack), "unexpected response")
}
impl<A: ReplicatedSchema> Replica<A::Change, SchemaId, A::View> for TlsReplica<A> {
    fn peer_identity(&self) -> Result<Option<[u8; 32]>> {
        Ok(Some(self.tls.pin))
    }
    fn summary(&mut self) -> Result<journal::Summary<SchemaId>> {
        match self.request(Request::Summary)? {
            Response::Summary(s) => Ok(s),
            _ => Err("unexpected response".into()),
        }
    }
    fn checkpoint_at(&mut self, n: u64) -> Result<Prefix> {
        match self.request(Request::CheckpointAt(n))? {
            Response::Checkpoint(p) => Ok(p),
            _ => Err("unexpected response".into()),
        }
    }
    fn journal_page(
        &mut self,
        h: &Head,
        after: u64,
        limit: u32,
    ) -> Result<journal::JournalPage<A::Change, SchemaId>> {
        match self.request(Request::JournalPage {
            head: h.clone(),
            after,
            limit,
        })? {
            Response::JournalPage(p) => {
                p.validate(h, after, limit)?;
                Ok(p)
            }
            _ => Err("unexpected response".into()),
        }
    }
    fn confirm_checkpoint(&mut self, checkpoint: Prefix) -> Result<()> {
        let generation = self.summary()?.head.read_generation;
        ack(self.request(Request::Confirm {
            checkpoint,
            generation,
        })?)
    }
    fn status(&mut self) -> Result<Status<A::Change, SchemaId>> {
        match self.request(Request::Status)? {
            Response::Status(s) => Ok(s),
            _ => Err("unexpected response".into()),
        }
    }
    fn view(&mut self) -> Result<A::View> {
        match self.request(Request::View)? {
            Response::View(v) => Ok(v),
            _ => Err("unexpected response".into()),
        }
    }
    fn stage(&mut self, e: Record<A>) -> Result<()> {
        ack(self.request(Request::Stage(e))?)
    }
    fn apply(&mut self, e: Record<A>) -> Result<()> {
        ack(self.request(Request::Apply(e))?)
    }
    fn abort(&mut self, id: &str) -> Result<()> {
        ack(self.request(Request::Abort(id.into()))?)
    }
}
fn dispatch<A: ReplicatedSchema>(
    node: &mut TypedNode<A>,
    envelope: Envelope<A::Change>,
) -> Result<Response<A::Change, A::View>> {
    ensure(
        envelope.protocol == PROTOCOL
            && envelope.identity == *node.identity()
            && envelope.contract == node.schema_contract()?
            && node.role() == Role::Secondary,
        "typed request binding mismatch",
    )?;
    Ok(match envelope.request {
        Request::Summary => Response::Summary(node.summary()?),
        Request::CheckpointAt(n) => Response::Checkpoint(Replica::checkpoint_at(node, n)?),
        Request::JournalPage { head, after, limit } => {
            Response::JournalPage(node.journal_page(&head, after, limit)?)
        }
        Request::Confirm {
            checkpoint,
            generation,
        } => {
            ensure(
                node.summary()?.head.read_generation == generation,
                "stale read admission generation",
            )?;
            node.confirm_checkpoint(checkpoint)?;
            Response::Ack
        }
        Request::Status => Response::Status(node.status()?),
        Request::View => Response::View(node.verified_view()?.ok_or("read admission required")?),
        Request::Stage(e) => {
            node.stage(e)?;
            Response::Ack
        }
        Request::Apply(e) => {
            node.apply(e)?;
            Response::Ack
        }
        Request::Abort(id) => {
            node.abort(&id)?;
            Response::Ack
        }
        Request::SnapshotBegin(m) => Response::Progress(node.begin_snapshot(&m)?),
        Request::SnapshotPage(p) => Response::Progress(node.receive_snapshot(&p)?),
        Request::SnapshotFinish(m) => Response::Checkpoint(node.finish_snapshot(&m)?),
    })
}
pub fn serve<A: ReplicatedSchema>(
    listener: &TcpListener,
    node: &mut TypedNode<A>,
    tls: &ServerTls,
    timeout: Duration,
    stop: &AtomicBool,
) -> Result<()> {
    serve_with_observer(listener, node, tls, timeout, stop, |_| Ok(()))
}
/// The observer must invalidate/publish its cache before returning. It is called
/// before any ACK, including failed/ambiguous mutations and exact retries.
pub fn serve_with_observer<A: ReplicatedSchema>(
    listener: &TcpListener,
    node: &mut TypedNode<A>,
    tls: &ServerTls,
    timeout: Duration,
    stop: &AtomicBool,
    mut publish: impl FnMut(&TypedNode<A>) -> Result<()>,
) -> Result<()> {
    ensure(
        node.role() == Role::Secondary && !timeout.is_zero() && timeout <= Duration::from_secs(60),
        "invalid typed peer server",
    )?;
    listener.set_nonblocking(true)?;
    publish(node)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((socket, _)) => {
                let _ = serve_one(socket, node, tls, timeout, &mut publish);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn serve_one<A: ReplicatedSchema>(
    socket: TcpStream,
    node: &mut TypedNode<A>,
    tls: &ServerTls,
    timeout: Duration,
    publish: &mut impl FnMut(&TypedNode<A>) -> Result<()>,
) -> Result<()> {
    let mut stream = accept_tls(socket, tls, timeout)?;
    if let Some(required) = node.required_recovery_peer()? {
        ensure(
            tls.pin == required,
            "TLS peer differs from recovered membership",
        )?;
    }
    let request: Envelope<A::Change> = read_frame(&mut stream)?;
    let result = dispatch(node, request).map_err(|e| e.to_string());
    publish(node)?;
    write_frame(
        &mut stream,
        &Reply {
            protocol: PROTOCOL.into(),
            identity: node.identity().clone(),
            contract: node.schema_contract()?,
            result,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope_tests::{stock_entry, StockSchema};
    #[test]
    fn typed_tls_snapshot_commit_contract_and_pin_admission() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let batch = stock_entry().batch;
        let id = batch.identity.clone();
        let mut p = TypedNode::open(
            dir.path().join("p"),
            Role::Primary,
            id.clone(),
            "fixture",
            StockSchema,
        )?;
        let mut seed = TypedNode::open(
            dir.path().join("seed"),
            Role::Secondary,
            id.clone(),
            "fixture",
            StockSchema,
        )?;
        commit(&mut p, &mut seed, batch.clone())?;
        let mut target = TypedNode::open(
            dir.path().join("target"),
            Role::Secondary,
            id.clone(),
            "fixture",
            StockSchema,
        )?;
        let (client, server) = super::super::tests::tls();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let handle = std::thread::spawn(move || {
            serve(
                &listener,
                &mut target,
                &server,
                Duration::from_secs(3),
                &shutdown,
            )
            .unwrap();
            target
        });
        let result = (|| -> Result<()> {
            let mut wrong_pin = client.clone();
            wrong_pin.pin = [0; 32];
            let mut bad = TlsReplica::new(
                address,
                wrong_pin,
                id.clone(),
                Duration::from_secs(3),
                &StockSchema,
            )?;
            assert!(bad.summary().is_err());
            let mut peer =
                TlsReplica::new(address, client, id, Duration::from_secs(3), &StockSchema)?;
            peer.contract.fingerprint_version += 1;
            assert!(peer.summary().is_err());
            peer.contract.fingerprint_version -= 1;
            assert_eq!(peer.summary()?.head.length, 0);
            peer.install_snapshot_from(&mut p)?;
            assert!(peer.view().is_err());
            recover(&mut p, &mut peer)?;
            assert_eq!(peer.view()?, p.view()?);
            let mut coordinator = crate::typed::Coordinator::<StockSchema, _>::new(p, peer)?;
            assert_eq!(
                coordinator
                    .write(batch.clone())
                    .map_err(|e| e.reason)?
                    .sequence,
                1
            );
            let mut next = batch.clone();
            next.operation_id = "second".into();
            assert_eq!(coordinator.write(next).map_err(|e| e.reason)?.sequence, 2);
            assert!(coordinator.capabilities().writable);
            let mut conflict = batch;
            conflict.changes.clear();
            assert_eq!(coordinator.write(conflict).unwrap_err().status_code, 400);
            Ok(())
        })();
        stop.store(true, Ordering::SeqCst);
        let target = handle.join().map_err(|_| "typed peer panicked")?;
        result?;
        assert_eq!(target.checkpoint()?.sequence, 2);
        Ok(())
    }
}
