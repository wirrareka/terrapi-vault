//! TLS 1.3, required client certificates, explicit peer pins, bounded chunked messages.
use crate::*;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const MAX_FRAME: usize = 1024 * 1024;
pub mod typed;
mod wire;
pub use wire::MAX_MESSAGE;
use wire::{read_frame, write_frame};
const VERSION: u16 = 12;
pub struct Credentials {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub ca: Vec<u8>,
}
pub fn fingerprint(cert: &[u8]) -> [u8; 32] {
    Sha256::digest(cert).into()
}
fn roots(c: &Credentials) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(c.ca.clone()))?;
    Ok(roots)
}
fn key(c: &Credentials) -> Result<PrivateKeyDer<'static>> {
    Ok(PrivateKeyDer::try_from(c.private_key.clone())?)
}
#[derive(Clone)]
pub struct ClientTls {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    pin: [u8; 32],
}
impl ClientTls {
    pub fn new(c: &Credentials, server_name: &str, pin: [u8; 32]) -> Result<Self> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots(c)?)
                .with_client_auth_cert(
                    vec![CertificateDer::from(c.certificate.clone())],
                    key(c)?,
                )?;
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        Ok(Self {
            config: Arc::new(config),
            name: ServerName::try_from(server_name.to_owned())?,
            pin,
        })
    }
}
pub struct ServerTls {
    config: Arc<ServerConfig>,
    pin: [u8; 32],
}
impl ServerTls {
    pub fn new(c: &Credentials, allowed_client: [u8; 32]) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots(c)?),
            provider.clone(),
        )
        .build()?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![CertificateDer::from(c.certificate.clone())], key(c)?)?;
        config.send_tls13_tickets = 0;
        Ok(Self {
            config: Arc::new(config),
            pin: allowed_client,
        })
    }
}
fn verify_pin(certs: Option<&[CertificateDer<'_>]>, pin: [u8; 32]) -> Result<()> {
    let leaf = certs
        .and_then(|c| c.first())
        .ok_or("peer certificate required")?;
    ensure(
        fingerprint(leaf.as_ref()) == pin,
        "peer certificate not authorized",
    )
}

/// Absolute deadline across handshake, frame reads and writes, including slow-drip traffic.
struct DeadlineStream {
    socket: TcpStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "RPC deadline exceeded"))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.socket
            .set_read_timeout(Some(self.remaining()?))
            .map_err(|e| io::Error::new(e.kind(), format!("read timeout option: {e}")))?;
        self.socket
            .read(b)
            .map_err(|e| io::Error::new(e.kind(), format!("socket read: {e}")))
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.socket
            .set_write_timeout(Some(self.remaining()?))
            .map_err(|e| io::Error::new(e.kind(), format!("write timeout option: {e}")))?;
        self.socket
            .write(b)
            .map_err(|e| io::Error::new(e.kind(), format!("socket write: {e}")))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.socket.flush()
    }
}
#[derive(Serialize, Deserialize)]
enum Request {
    CheckpointAt(u64),
    ActivateBase(publication::Proposal),
    BaseStatus,
    CaptureBase(publication::Proposal),
    ConfirmBase(publication::Proposal),
    MaterializedBegin(materialized::Manifest),
    MaterializedProgress,
    MaterializedChunk {
        token: [u8; 32],
        page: materialized::Page,
    },
    MaterializedFinish([u8; 32]),
    MaterializedCancel([u8; 32]),
    SnapshotBegin(snapshot_staging::SnapshotManifest),
    SnapshotProgress,
    SnapshotChunk {
        token: [u8; 32],
        page: journal::JournalPage,
    },
    SnapshotFinish([u8; 32]),
    SnapshotCancel([u8; 32]),
    Summary,
    JournalPage {
        head: journal::JournalHead,
        after: u64,
        limit: u32,
    },
    Confirm {
        checkpoint: Checkpoint,
        generation: [u8; 32],
    },
    Status,
    View,
    Stage(Entry),
    Apply(Entry),
    Abort(String),
    Install(Snapshot),
}
#[derive(Serialize, Deserialize)]
enum Response {
    Checkpoint(Checkpoint),
    BaseStatus(Option<publication::Record>),
    MaterializedProgress(Option<materialized::Progress>),
    SnapshotProgress(Option<snapshot_staging::SnapshotProgress>),
    Summary(journal::Summary),
    JournalPage(journal::JournalPage),
    Status(Status),
    View(View),
    Ack,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u16,
    identity: Identity,
    schema_contract: schema_contract::Contract,
    request: Request,
}
#[derive(Serialize, Deserialize)]
struct Reply {
    version: u16,
    identity: Identity,
    schema_contract: schema_contract::Contract,
    result: std::result::Result<Response, String>,
}

pub struct TlsReplica {
    address: SocketAddr,
    tls: ClientTls,
    identity: Identity,
    timeout: Duration,
    schema_contract: schema_contract::Contract,
}
impl TlsReplica {
    pub fn new(
        address: SocketAddr,
        tls: ClientTls,
        identity: Identity,
        timeout: Duration,
    ) -> Result<Self> {
        ensure(
            !timeout.is_zero() && timeout <= Duration::from_secs(60),
            "timeout must be in (0,60s]",
        )?;
        Ok(Self {
            address,
            tls,
            identity,
            timeout,
            schema_contract: schema_contract::expected(&reference::Proximi)?,
        })
    }
    fn request(&mut self, request: Request) -> Result<Response> {
        let mut stream = connect_tls(self.address, &self.tls, self.timeout)?;
        write_frame(
            &mut stream,
            &Envelope {
                version: VERSION,
                identity: self.identity.clone(),
                schema_contract: self.schema_contract.clone(),
                request,
            },
        )
        .map_err(|e| format!("request: {e}"))?;
        let reply: Reply = read_frame(&mut stream).map_err(|e| format!("reply: {e}"))?;
        ensure(
            reply.version == VERSION && reply.identity == self.identity,
            "reply identity/version mismatch",
        )?;
        ensure(
            reply.schema_contract == self.schema_contract,
            "reply schema contract mismatch",
        )?;
        reply.result.map_err(Into::into)
    }
    pub fn install(&mut self, snapshot: Snapshot) -> Result<()> {
        expect_ack(self.request(Request::Install(snapshot))?)
    }
    pub fn materialized_progress(&mut self) -> Result<Option<materialized::Progress>> {
        match self.request(Request::MaterializedProgress)? {
            Response::MaterializedProgress(p) => Ok(p),
            _ => Err("unexpected response".into()),
        }
    }
    pub fn materialized_begin(
        &mut self,
        m: materialized::Manifest,
    ) -> Result<materialized::Progress> {
        expect_materialized(self.request(Request::MaterializedBegin(m))?)
    }
    pub fn materialized_chunk(
        &mut self,
        token: [u8; 32],
        page: materialized::Page,
    ) -> Result<materialized::Progress> {
        expect_materialized(self.request(Request::MaterializedChunk { token, page })?)
    }
    pub fn materialized_finish(&mut self, token: [u8; 32]) -> Result<materialized::Progress> {
        expect_materialized(self.request(Request::MaterializedFinish(token))?)
    }
    pub fn materialized_cancel(&mut self, token: [u8; 32]) -> Result<()> {
        expect_ack(self.request(Request::MaterializedCancel(token))?)
    }
    /// Explicit bootstrap from a quiescent fixed primary; never a readiness grant.
    pub fn install_materialized_from(&mut self, source: &Node) -> Result<()> {
        self.install_materialized_source(source, false)
    }
    /// Restore a frozen published checkpoint, without granting readiness or writer authority.
    pub fn install_published_from(&mut self, source: &Node) -> Result<()> {
        self.install_materialized_source(source, true)
    }
    fn install_materialized_source(&mut self, source: &Node, published: bool) -> Result<()> {
        let manifest = if published {
            source.published_manifest()?
        } else {
            source.materialized_manifest()?
        };
        let mut p = self.materialized_begin(manifest.clone())?;
        ensure(
            p.manifest == manifest
                && p.received <= manifest.rows()?
                && p.bytes <= materialized::MAX_BYTES,
            "invalid materialized progress",
        )?;
        let token = p.token;
        while p.received < manifest.rows()? {
            ensure(!p.complete, "premature materialized completion")?;
            let page = if published {
                source.published_page(&manifest, p.received)?
            } else {
                source.materialized_page(&manifest, p.received)?
            };
            let end = p.received + page.rows.len() as u64;
            let previous_bytes = p.bytes;
            p = self.materialized_chunk(token, page)?;
            ensure(
                p.token == token
                    && p.manifest == manifest
                    && p.received == end
                    && !p.complete
                    && p.bytes >= previous_bytes
                    && p.bytes <= materialized::MAX_BYTES,
                "invalid materialized progress",
            )?;
        }
        ensure(
            if published {
                source.published_manifest()? == manifest
            } else {
                source.journal_head()? == manifest.head
            },
            "materialized source changed",
        )?;
        p = self.materialized_finish(token)?;
        ensure(
            p.complete
                && p.token == token
                && p.manifest == manifest
                && p.received == manifest.rows()?
                && p.bytes <= materialized::MAX_BYTES,
            "invalid materialized completion",
        )
    }
    pub fn snapshot_progress(&mut self) -> Result<Option<snapshot_staging::SnapshotProgress>> {
        match self.request(Request::SnapshotProgress)? {
            Response::SnapshotProgress(p) => Ok(p),
            _ => Err("unexpected response".into()),
        }
    }
    pub fn snapshot_begin(
        &mut self,
        manifest: snapshot_staging::SnapshotManifest,
    ) -> Result<snapshot_staging::SnapshotProgress> {
        expect_snapshot(self.request(Request::SnapshotBegin(manifest))?)
    }
    pub fn snapshot_chunk(
        &mut self,
        token: [u8; 32],
        page: journal::JournalPage,
    ) -> Result<snapshot_staging::SnapshotProgress> {
        expect_snapshot(self.request(Request::SnapshotChunk { token, page })?)
    }
    pub fn snapshot_finish(
        &mut self,
        token: [u8; 32],
    ) -> Result<snapshot_staging::SnapshotProgress> {
        expect_snapshot(self.request(Request::SnapshotFinish(token))?)
    }
    pub fn snapshot_cancel(&mut self, token: [u8; 32]) -> Result<()> {
        expect_ack(self.request(Request::SnapshotCancel(token))?)
    }
    /// Caller holds the quiescent source; resume a matching transfer, never replace one implicitly.
    /// Installation alone does not grant read readiness; follow with normal recovery.
    pub fn install_from(&mut self, source: &Node) -> Result<()> {
        let manifest = source.snapshot_manifest()?;
        let mut p = self.snapshot_begin(manifest.clone())?;
        ensure(
            p.manifest == manifest
                && p.received <= manifest.head.length
                && p.bytes <= snapshot_staging::MAX_STAGED_BYTES,
            "invalid snapshot progress",
        )?;
        let token = p.token;
        while p.received < manifest.head.length {
            ensure(!p.complete, "premature snapshot completion")?;
            let page =
                source.journal_page(&manifest.head, p.received, journal::MAX_PAGE_ENTRIES)?;
            let expected = p.received + page.entries.len() as u64;
            p = self.snapshot_chunk(token, page)?;
            ensure(
                p.token == token
                    && p.manifest == manifest
                    && p.received == expected
                    && !p.complete
                    && p.bytes <= snapshot_staging::MAX_STAGED_BYTES,
                "invalid snapshot progress",
            )?;
        }
        ensure(
            source.journal_head()? == manifest.head,
            "snapshot source changed",
        )?;
        p = self.snapshot_finish(token)?;
        ensure(
            p.complete
                && p.token == token
                && p.manifest == manifest
                && p.received == manifest.head.length,
            "invalid snapshot completion",
        )
    }
}
fn expect_snapshot(r: Response) -> Result<snapshot_staging::SnapshotProgress> {
    match r {
        Response::SnapshotProgress(Some(p)) => Ok(p),
        _ => Err("unexpected response".into()),
    }
}
fn expect_materialized(r: Response) -> Result<materialized::Progress> {
    match r {
        Response::MaterializedProgress(Some(p)) => Ok(p),
        _ => Err("unexpected response".into()),
    }
}
fn expect_ack(r: Response) -> Result<()> {
    ensure(matches!(r, Response::Ack), "unexpected response")
}
impl publication::BaseReplica for TlsReplica {
    fn activate_published_base(&mut self, p: publication::Proposal) -> Result<()> {
        expect_ack(self.request(Request::ActivateBase(p))?)
    }
    fn base_status(&mut self) -> Result<Option<publication::Record>> {
        match self.request(Request::BaseStatus)? {
            Response::BaseStatus(r) => Ok(r),
            _ => Err("unexpected response".into()),
        }
    }
    fn capture_base(&mut self, p: publication::Proposal) -> Result<publication::Record> {
        match self.request(Request::CaptureBase(p))? {
            Response::BaseStatus(Some(r)) => Ok(r),
            _ => Err("unexpected response".into()),
        }
    }
    fn confirm_base(&mut self, p: publication::Proposal) -> Result<publication::Record> {
        match self.request(Request::ConfirmBase(p))? {
            Response::BaseStatus(Some(r)) => Ok(r),
            _ => Err("unexpected response".into()),
        }
    }
}
impl Replica for TlsReplica {
    fn peer_identity(&self) -> Result<Option<[u8; 32]>> {
        Ok(Some(self.tls.pin))
    }
    fn checkpoint_at(&mut self, sequence: u64) -> Result<Checkpoint> {
        match self.request(Request::CheckpointAt(sequence))? {
            Response::Checkpoint(c) if c.sequence == sequence && c.identity == self.identity => {
                Ok(c)
            }
            _ => Err("unexpected checkpoint response".into()),
        }
    }
    fn summary(&mut self) -> Result<journal::Summary> {
        match self.request(Request::Summary)? {
            Response::Summary(s) => Ok(s),
            _ => Err("unexpected response".into()),
        }
    }
    fn journal_page(
        &mut self,
        head: &journal::JournalHead,
        after: u64,
        limit: u32,
    ) -> Result<journal::JournalPage> {
        match self.request(Request::JournalPage {
            head: head.clone(),
            after,
            limit,
        })? {
            Response::JournalPage(page) => {
                page.validate(head, after, limit)?;
                Ok(page)
            }
            _ => Err("unexpected response".into()),
        }
    }
    fn confirm_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<()> {
        let generation = self.summary()?.head.read_generation;
        expect_ack(self.request(Request::Confirm {
            checkpoint,
            generation,
        })?)
    }
    fn status(&mut self) -> Result<Status> {
        match self.request(Request::Status)? {
            Response::Status(s) => Ok(s),
            _ => Err("unexpected response".into()),
        }
    }
    fn view(&mut self) -> Result<View> {
        match self.request(Request::View)? {
            Response::View(s) => Ok(s),
            _ => Err("unexpected response".into()),
        }
    }
    fn stage(&mut self, e: Entry) -> Result<()> {
        expect_ack(self.request(Request::Stage(e))?)
    }
    fn apply(&mut self, e: Entry) -> Result<()> {
        expect_ack(self.request(Request::Apply(e))?)
    }
    fn abort(&mut self, id: &str) -> Result<()> {
        expect_ack(self.request(Request::Abort(id.into()))?)
    }
}
fn dispatch(node: &mut Node, envelope: Envelope) -> Result<Response> {
    ensure(
        envelope.version == VERSION && envelope.identity == node.identity,
        "request identity/version mismatch",
    )?;
    ensure(
        envelope.schema_contract == node.schema_contract()?,
        "request schema contract mismatch",
    )?;
    ensure(
        node.role == Role::Secondary,
        "network service requires secondary",
    )?;
    Ok(match envelope.request {
        Request::CheckpointAt(n) => Response::Checkpoint(node.checkpoint_at(n)?),
        Request::ActivateBase(p) => {
            node.activate_published_base(p)?;
            Response::Ack
        }
        Request::BaseStatus => Response::BaseStatus(node.base_status()?),
        Request::CaptureBase(p) => Response::BaseStatus(Some(node.capture_base(p)?)),
        Request::ConfirmBase(p) => Response::BaseStatus(Some(node.confirm_base(p)?)),
        Request::MaterializedBegin(m) => {
            Response::MaterializedProgress(Some(node.materialized_begin(m)?))
        }
        Request::MaterializedProgress => {
            Response::MaterializedProgress(node.materialized_progress()?)
        }
        Request::MaterializedChunk { token, page } => {
            Response::MaterializedProgress(Some(node.materialized_chunk(token, page)?))
        }
        Request::MaterializedFinish(token) => {
            Response::MaterializedProgress(Some(node.materialized_finish(token)?))
        }
        Request::MaterializedCancel(token) => {
            node.materialized_cancel(token)?;
            Response::Ack
        }
        Request::SnapshotBegin(m) => Response::SnapshotProgress(Some(node.snapshot_begin(m)?)),
        Request::SnapshotProgress => Response::SnapshotProgress(node.snapshot_progress()?),
        Request::SnapshotChunk { token, page } => {
            Response::SnapshotProgress(Some(node.snapshot_chunk(token, page)?))
        }
        Request::SnapshotFinish(token) => {
            Response::SnapshotProgress(Some(node.snapshot_finish(token)?))
        }
        Request::SnapshotCancel(token) => {
            node.snapshot_cancel(token)?;
            Response::Ack
        }
        Request::Summary => Response::Summary(node.summary()?),
        Request::JournalPage { head, after, limit } => {
            Response::JournalPage(node.journal_page(&head, after, limit)?)
        }
        Request::Confirm {
            checkpoint,
            generation,
        } => {
            node.confirm_generation(checkpoint, generation)?;
            Response::Ack
        }
        Request::Status => Response::Status(node.status()?),
        Request::View => Response::View(node.view()?),
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
        Request::Install(s) => {
            node.install(s)?;
            Response::Ack
        }
    })
}
fn connect_tls(
    address: SocketAddr,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<StreamOwned<ClientConnection, DeadlineStream>> {
    ensure(
        !timeout.is_zero() && timeout <= Duration::from_secs(60),
        "invalid client timeout",
    )?;
    let deadline = Instant::now() + timeout;
    let socket =
        TcpStream::connect_timeout(&address, timeout).map_err(|e| format!("connect: {e}"))?;
    socket.set_nodelay(true)?;
    let mut io = DeadlineStream { socket, deadline };
    let mut conn = ClientConnection::new(tls.config.clone(), tls.name.clone())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut io)
            .map_err(|e| format!("TLS handshake: {e}"))?;
    }
    verify_pin(conn.peer_certificates(), tls.pin)?;
    Ok(StreamOwned::new(conn, io))
}
fn accept_tls(
    socket: TcpStream,
    tls: &ServerTls,
    timeout: Duration,
) -> Result<StreamOwned<ServerConnection, DeadlineStream>> {
    socket.set_nonblocking(false)?;
    let mut io = DeadlineStream {
        socket,
        deadline: Instant::now() + timeout,
    };
    let mut conn = ServerConnection::new(tls.config.clone())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut io)?;
    }
    verify_pin(conn.peer_certificates(), tls.pin)?;
    Ok(StreamOwned::new(conn, io))
}
#[cfg(test)]
fn serve_one(socket: TcpStream, node: &mut Node, tls: &ServerTls, timeout: Duration) -> Result<()> {
    serve_one_observed(socket, node, tls, timeout, &mut |_| Ok(()))
}
fn serve_one_observed(
    socket: TcpStream,
    node: &mut Node,
    tls: &ServerTls,
    timeout: Duration,
    publish: &mut impl FnMut(&Node) -> Result<()>,
) -> Result<()> {
    let mut stream = accept_tls(socket, tls, timeout)?;
    if let Some(required) = node.required_recovery_peer()? {
        ensure(
            tls.pin == required,
            "TLS peer differs from recovered membership",
        )?;
    }
    let request: Envelope = read_frame(&mut stream)?;
    let changes_view = matches!(
        request.request,
        Request::Apply(_)
            | Request::Install(_)
            | Request::Confirm { .. }
            | Request::SnapshotBegin(_)
            | Request::SnapshotFinish(_)
            | Request::SnapshotCancel(_)
            | Request::MaterializedBegin(_)
            | Request::MaterializedFinish(_)
            | Request::MaterializedCancel(_)
    );
    let result = dispatch(node, request).map_err(|e| e.to_string());
    // Publish before ACK, including idempotent replay. An ambiguous DB error also
    // requires refreshing/invalidation, rather than retaining a possibly stale cache.
    if changes_view {
        publish(node)?;
    }
    write_frame(
        &mut stream,
        &Reply {
            version: VERSION,
            identity: node.identity.clone(),
            schema_contract: node.schema_contract()?,
            result,
        },
    )
}
/// Serial, bounded work: no unbounded tasks and no concurrent mutation of the journal.
pub fn serve(
    listener: &TcpListener,
    node: &mut Node,
    tls: &ServerTls,
    timeout: Duration,
    stop: &AtomicBool,
) -> Result<()> {
    serve_with_observer(listener, node, tls, timeout, stop, |_| Ok(()))
}
pub fn serve_with_observer(
    listener: &TcpListener,
    node: &mut Node,
    tls: &ServerTls,
    timeout: Duration,
    stop: &AtomicBool,
    mut publish: impl FnMut(&Node) -> Result<()>,
) -> Result<()> {
    ensure(
        node.role == Role::Secondary,
        "cannot expose primary mutation commands",
    )?;
    ensure(
        !timeout.is_zero() && timeout <= Duration::from_secs(60),
        "invalid server timeout",
    )?;
    listener.set_nonblocking(true)?;
    publish(node)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((socket, _)) => {
                let _ = serve_one_observed(socket, node, tls, timeout, &mut publish);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
