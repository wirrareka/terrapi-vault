use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use std::{
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use terrapi_vesta_replication::{coordinator::*, network::*, *};

// Large encrypted fixtures must not compete for the same finite RPC deadline.
// Serialize test cases; concurrency explicitly exercised inside each case is unchanged.
static NETWORK_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn identity() -> Identity {
    Identity {
        cluster: "eu-pair".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: 1,
    }
}
fn batch(id: &str) -> Batch {
    Batch {
        identity: identity(),
        operation_id: id.into(),
        changes: vec![Change::PutPlace {
            id: id.into(),
            name: "Airport".into(),
        }],
    }
}
struct Certs {
    ca: Certificate,
    key: KeyPair,
}
impl Certs {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&key).unwrap();
        Self { ca, key }
    }
    fn leaf(&self, name: &str) -> Credentials {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.into()])
            .unwrap()
            .signed_by(&key, &self.ca, &self.key)
            .unwrap();
        Credentials {
            certificate: cert.der().to_vec(),
            private_key: key.serialize_der(),
            ca: self.ca.der().to_vec(),
        }
    }
}
struct Server {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(path: &Path, config: ServerTls) -> Self {
        Self::start_with_timeout(path, config, Duration::from_millis(250))
    }
    fn start_with_timeout(path: &Path, config: ServerTls, timeout: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let path = path.to_owned();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = thread::spawn(move || {
            let mut node = Node::open(
                path,
                Role::Secondary,
                identity(),
                "network fixture passphrase",
            )
            .unwrap();
            ready_tx.send(()).unwrap();
            serve(&listener, &mut node, &config, timeout, &shutdown).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn pair(dir: &Path) -> (Node, Server, TlsReplica) {
    pair_with_timeouts(dir, Duration::from_millis(250), Duration::from_millis(500))
}
fn pair_with_timeouts(
    dir: &Path,
    server_timeout: Duration,
    client_timeout: Duration,
) -> (Node, Server, TlsReplica) {
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let server = certs.leaf("secondary.test");
    let server_tls = ServerTls::new(&server, fingerprint(&client.certificate)).unwrap();
    let client_tls =
        ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap();
    let server = Server::start_with_timeout(&dir.join("s.vesta"), server_tls, server_timeout);
    let peer = TlsReplica::new(server.address, client_tls, identity(), client_timeout).unwrap();
    let primary = Node::open(
        dir.join("p.vesta"),
        Role::Primary,
        identity(),
        "network fixture passphrase",
    )
    .unwrap();
    (primary, server, peer)
}

#[test]
fn mtls_commit_and_offline_gate_keep_reads_and_block_new_writes() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let (p, server, peer) = pair(dir.path());
    let mut gate = Coordinator::new(p, peer).unwrap();
    assert!(!gate.capabilities().writable);
    gate.write(batch("one")).unwrap();
    assert!(gate.capabilities().writable);
    drop(server);
    let failure = gate.write(batch("two")).unwrap_err();
    assert_eq!(failure.status_code, 503);
    assert!(!gate.capabilities().writable);
    assert!(gate.capabilities().readable);
    assert_eq!(gate.view().unwrap().places.len(), 1);
    assert_eq!(gate.local_status().unwrap().entries.len(), 1);
}

#[test]
fn mtls_base_publication_resumes_peer_confirmation_and_keeps_journal() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    use publication::{publish_base, BaseReplica, Phase, Proposal};
    let dir = tempfile::tempdir().unwrap();
    let (mut p, server, mut peer) = pair(dir.path());
    commit(&mut p, &mut peer, batch("one")).unwrap();
    let proposal = Proposal {
        checkpoint: p.checkpoint().unwrap(),
        token: [8; 32],
        primary_generation: p.journal_head().unwrap().read_generation,
        secondary_generation: peer.summary().unwrap().head.read_generation,
    };
    p.capture_base(proposal.clone()).unwrap();
    peer.capture_base(proposal.clone()).unwrap();
    peer.confirm_base(proposal.clone()).unwrap(); // Treat reply as lost by coordinator.
    let record = publish_base(&mut p, &mut peer).unwrap();
    assert_eq!(record.phase, Phase::Confirmed);
    assert_eq!(peer.base_status().unwrap(), Some(record));
    let mut stale = proposal;
    stale.secondary_generation = [0; 32];
    assert!(peer.confirm_base(stale).is_err());
    commit(&mut p, &mut peer, batch("two")).unwrap();
    assert_eq!(peer.status().unwrap().entries.len(), 2);
    drop(server);
    assert!(publish_base(&mut p, &mut peer).is_err());
}

#[test]
fn mtls_base_activation_checks_prefix_and_resumes_lost_peer_ack() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    use publication::{activate_base, publish_base, BaseReplica};
    for primary_first in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut p, _server, mut peer) = pair(dir.path());
        commit(&mut p, &mut peer, batch("one")).unwrap();
        let r = publish_base(&mut p, &mut peer).unwrap();
        if primary_first {
            p.activate_published_base(r.proposal.clone()).unwrap();
        } else {
            peer.activate_published_base(r.proposal.clone()).unwrap();
        }
        // Treat the first activation ACK as lost. Reconciliation must handle either floor.
        recover(&mut p, &mut peer).unwrap();
        activate_base(&mut p, &mut peer).unwrap();
        assert_eq!(
            peer.summary().unwrap().head.base,
            p.journal_head().unwrap().base
        );
        let mut stale = r.proposal;
        stale.secondary_generation = [0; 32];
        assert!(peer.activate_published_base(stale).is_err());
        assert_eq!(commit(&mut p, &mut peer, batch("two")).unwrap().sequence, 2);
        assert_eq!(peer.status().unwrap().entries.len(), 2);
    }
}

#[test]
fn mtls_frozen_base_restore_resumes_chunks_and_catches_up_to_live_primary() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let timeout = Duration::from_secs(30);
    let (mut p, _old_server, mut old) = pair_with_timeouts(source.path(), timeout, timeout);
    let mut b = batch("large");
    b.changes = (0..3)
        .map(|i| Change::PutPlace {
            id: format!("p{i}"),
            name: "x".repeat(500_000),
        })
        .collect();
    commit(&mut p, &mut old, b.clone()).unwrap();
    publication::publish_base(&mut p, &mut old).unwrap();
    let m = p.published_manifest().unwrap();
    let (unused, server, mut peer) = pair_with_timeouts(target.path(), timeout, timeout);
    drop(unused);
    let transfer = peer.materialized_begin(m.clone()).unwrap();
    let page = p.published_page(&m, 0).unwrap();
    assert!(serde_json::to_vec(&page).unwrap().len() > MAX_FRAME);
    peer.materialized_chunk(transfer.token, page).unwrap();
    commit(&mut p, &mut old, batch("newer")).unwrap();
    // Resume an existing staged transfer using the frozen manifest, not the live head.
    peer.install_published_from(&p).unwrap();
    assert_eq!(peer.view().unwrap().places.len(), 3);
    recover(&mut p, &mut peer).unwrap();
    assert_eq!(peer.view().unwrap(), p.view().unwrap());
    assert_eq!(commit(&mut p, &mut peer, b).unwrap().sequence, 1);
    drop(server);
}

#[test]
fn materialized_over_message_limit_resumes_without_old_journal_and_accepts_tail() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    for i in 0..18 {
        let id = format!("large-{i:02}");
        let mut b = batch(&id);
        b.changes = vec![Change::PutPlace {
            id: id.clone(),
            name: "M".repeat(1024 * 1024),
        }];
        p.prepare(b).unwrap();
        let e = p.decide(&id).unwrap();
        p.apply(e).unwrap();
    }
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let server = certs.leaf("secondary.test");
    let client_tls =
        ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap();
    let server_tls = || ServerTls::new(&server, fingerprint(&client.certificate)).unwrap();
    let path = dir.path().join("s");
    let running = Server::start_with_timeout(&path, server_tls(), Duration::from_secs(60));
    let mut peer = TlsReplica::new(
        running.address,
        client_tls.clone(),
        identity(),
        Duration::from_secs(60),
    )
    .unwrap();
    assert!(peer.materialized_progress().unwrap().is_none());
    let m = p.materialized_manifest().unwrap();
    let t = peer.materialized_begin(m.clone()).unwrap();
    let page = p.materialized_page(&m, 0).unwrap();
    assert!(page.rows.len() < m.rows().unwrap() as usize);
    let progress = peer.materialized_chunk(t.token, page.clone()).unwrap();
    assert_eq!(peer.materialized_chunk(t.token, page).unwrap(), progress);
    drop(peer);
    drop(running);
    let running = Server::start_with_timeout(&path, server_tls(), Duration::from_secs(60));
    let mut peer = TlsReplica::new(
        running.address,
        client_tls,
        identity(),
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(peer.materialized_progress().unwrap(), Some(progress));
    peer.install_materialized_from(&p).unwrap();
    let complete = peer.materialized_progress().unwrap().unwrap();
    assert_eq!(complete.token, t.token);
    assert!(complete.complete && complete.bytes > MAX_MESSAGE as u64);
    assert!(peer.status().unwrap().entries.is_empty());
    assert_eq!(peer.summary().unwrap().head.length, 18);
    recover(&mut p, &mut peer).unwrap();
    let original = commit(
        &mut p,
        &mut peer,
        Batch {
            identity: identity(),
            operation_id: "large-00".into(),
            changes: vec![Change::PutPlace {
                id: "large-00".into(),
                name: "M".repeat(1024 * 1024),
            }],
        },
    )
    .unwrap();
    assert_eq!(original.sequence, 1);
    commit(&mut p, &mut peer, batch("tail")).unwrap();
    assert_eq!(peer.status().unwrap().entries.len(), 1);
    peer.materialized_cancel(t.token).unwrap();
    assert!(peer.materialized_progress().unwrap().is_none());
    drop(peer);
    drop(running);
    let s = Node::open(
        &path,
        Role::Secondary,
        identity(),
        "network fixture passphrase",
    )
    .unwrap();
    assert_eq!(s.checkpoint().unwrap(), p.checkpoint().unwrap());
    assert_eq!(s.verified_view().unwrap().unwrap().places.len(), 19);
}

#[test]
fn multichunk_snapshot_status_view_and_tail_preserve_recovery() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    let mut seed = Node::open(
        dir.path().join("seed"),
        Role::Secondary,
        identity(),
        "fixture",
    )
    .unwrap();
    let large_batch = |id: &str| {
        let mut b = batch(id);
        b.changes = vec![Change::PutPlace {
            id: id.into(),
            name: "x".repeat(380_000),
        }];
        b
    };
    for id in ["one", "two", "three"] {
        commit(&mut p, &mut seed, large_batch(id)).unwrap();
    }
    let snapshot = p.snapshot().unwrap();
    assert!(serde_json::to_vec(&snapshot).unwrap().len() > MAX_FRAME);
    assert!(serde_json::to_vec(&p.view().unwrap()).unwrap().len() > MAX_FRAME);
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let server = certs.leaf("secondary.test");
    let replacement = Server::start_with_timeout(
        &dir.path().join("replacement"),
        ServerTls::new(&server, fingerprint(&client.certificate)).unwrap(),
        Duration::from_secs(10),
    );
    let mut peer = TlsReplica::new(
        replacement.address,
        ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap(),
        identity(),
        Duration::from_secs(10),
    )
    .unwrap();
    peer.install(snapshot).unwrap();
    recover(&mut p, &mut peer).unwrap();
    assert_eq!(peer.view().unwrap(), p.view().unwrap());
    let b = large_batch("tail");
    commit(&mut p, &mut peer, b.clone()).unwrap();
    commit(&mut p, &mut peer, b).unwrap();
    assert_eq!(peer.status().unwrap().entries.len(), 4);
    assert_eq!(peer.view().unwrap(), p.view().unwrap());
    drop(replacement);
    let s = Node::open(
        dir.path().join("replacement"),
        Role::Secondary,
        identity(),
        "network fixture passphrase",
    )
    .unwrap();
    assert_eq!(s.verified_view().unwrap(), Some(p.view().unwrap()));
}

#[test]
fn paged_recovery_exceeds_whole_message_limit() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    use terrapi_vesta_replication::journal::{MAX_PAGE_BYTES, MAX_PAGE_ENTRIES};
    // This is a large-state correctness test, not a ten-second latency contract.
    // Dedicated deadline tests still exercise bounded/stalled RPC behavior.
    let rpc_timeout = Duration::from_secs(30);
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    // Valid no-op history with large IDs: journal >16 MiB while the business view is tiny.
    // Build a committed primary fixture using the trusted low-level API.
    for i in 0..52 {
        let b = Batch {
            identity: identity(),
            operation_id: format!("{i}-{}", "x".repeat(350_000)),
            changes: vec![],
        };
        p.prepare(b.clone()).unwrap();
        let e = p.decide(&b.operation_id).unwrap();
        p.apply(e).unwrap();
    }
    assert!(serde_json::to_vec(&p.status().unwrap()).unwrap().len() > MAX_MESSAGE);
    let head = p.journal_head().unwrap();
    let first = p.journal_page(&head, 0, MAX_PAGE_ENTRIES).unwrap();
    assert!(first.entries.len() < MAX_PAGE_ENTRIES as usize);
    assert!(
        first
            .entries
            .iter()
            .map(|e| serde_json::to_vec(e).unwrap().len() + 1)
            .sum::<usize>()
            <= MAX_PAGE_BYTES
    );
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let server = certs.leaf("secondary.test");
    let replacement = Server::start_with_timeout(
        &dir.path().join("replacement"),
        ServerTls::new(&server, fingerprint(&client.certificate)).unwrap(),
        rpc_timeout,
    );
    let mut peer = TlsReplica::new(
        replacement.address,
        ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap(),
        identity(),
        rpc_timeout,
    )
    .unwrap();
    assert_eq!(recover(&mut p, &mut peer).unwrap(), 52);
    // The old diagnostic is still bounded and fails, but admission does not use it.
    assert!(peer.status().is_err());
    assert_eq!(recover(&mut p, &mut peer).unwrap(), 0);
    commit(&mut p, &mut peer, batch("real-tail")).unwrap();
    assert_eq!(peer.summary().unwrap().head.length, 53);
    assert_eq!(peer.view().unwrap(), p.view().unwrap());
    let stale = peer.summary().unwrap().head;
    peer.stage(p.prepare(batch("pending")).unwrap()).unwrap();
    assert!(peer.journal_page(&stale, 0, MAX_PAGE_ENTRIES).is_err());
    recover(&mut p, &mut peer).unwrap();
}

#[test]
fn staged_snapshot_over_wire_limit_resumes_after_receiver_restart() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    for i in 0..26 {
        let b = Batch {
            identity: identity(),
            operation_id: format!("{i}-{}", "x".repeat(660_000)),
            changes: vec![],
        };
        p.prepare(b.clone()).unwrap();
        let e = p.decide(&b.operation_id).unwrap();
        p.apply(e).unwrap();
    }
    p.prepare(batch("visible-after-install")).unwrap();
    let e = p.decide("visible-after-install").unwrap();
    p.apply(e).unwrap();
    assert!(serde_json::to_vec(&p.status().unwrap()).unwrap().len() > MAX_MESSAGE);
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let cert = certs.leaf("secondary.test");
    let client_tls =
        ClientTls::new(&client, "secondary.test", fingerprint(&cert.certificate)).unwrap();
    let path = dir.path().join("receiver");
    let start = || {
        Server::start_with_timeout(
            &path,
            ServerTls::new(&cert, fingerprint(&client.certificate)).unwrap(),
            Duration::from_secs(20),
        )
    };
    let server = start();
    let mut peer = TlsReplica::new(
        server.address,
        client_tls.clone(),
        identity(),
        Duration::from_secs(20),
    )
    .unwrap();
    let m = p.snapshot_manifest().unwrap();
    let t = peer.snapshot_begin(m.clone()).unwrap();
    let page = p.journal_page(&m.head, 0, 1).unwrap();
    peer.snapshot_chunk(t.token, page.clone()).unwrap();
    assert_eq!(peer.snapshot_chunk(t.token, page).unwrap().received, 1);
    drop(server);
    let s = Node::open(
        &path,
        Role::Secondary,
        identity(),
        "network fixture passphrase",
    )
    .unwrap();
    assert_eq!(s.snapshot_progress().unwrap().unwrap().received, 1);
    assert!(s.view().unwrap().places.is_empty());
    assert!(s.verified_view().unwrap().is_none());
    drop(s);
    let server = start();
    let mut peer = TlsReplica::new(
        server.address,
        client_tls,
        identity(),
        Duration::from_secs(20),
    )
    .unwrap();
    peer.install_from(&p).unwrap();
    let done = peer.snapshot_progress().unwrap().unwrap();
    assert!(done.complete);
    assert_eq!(done.token, t.token);
    assert_eq!(done.received, 27);
    peer.snapshot_finish(t.token).unwrap();
    assert_eq!(peer.view().unwrap(), p.view().unwrap());
    recover(&mut p, &mut peer).unwrap();
    drop(server);
    let s = Node::open(
        &path,
        Role::Secondary,
        identity(),
        "network fixture passphrase",
    )
    .unwrap();
    assert_eq!(s.verified_view().unwrap(), Some(p.view().unwrap()));
}

#[test]
fn certificates_require_both_trust_and_exact_peer_authorization() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let certs = Certs::new();
    let allowed = certs.leaf("primary.test");
    let wrong = certs.leaf("other.test");
    let server_cert = certs.leaf("secondary.test");
    let server = Server::start(
        &dir.path().join("s.vesta"),
        ServerTls::new(&server_cert, fingerprint(&allowed.certificate)).unwrap(),
    );
    let bad_client = ClientTls::new(
        &wrong,
        "secondary.test",
        fingerprint(&server_cert.certificate),
    )
    .unwrap();
    let mut peer = TlsReplica::new(
        server.address,
        bad_client,
        identity(),
        Duration::from_millis(500),
    )
    .unwrap();
    assert!(peer.status().is_err());
    let wrong_name = ClientTls::new(
        &allowed,
        "wrong.test",
        fingerprint(&server_cert.certificate),
    )
    .unwrap();
    assert!(TlsReplica::new(
        server.address,
        wrong_name,
        identity(),
        Duration::from_millis(500)
    )
    .unwrap()
    .status()
    .is_err());
    let wrong_pin = ClientTls::new(&allowed, "secondary.test", [0; 32]).unwrap();
    assert!(TlsReplica::new(
        server.address,
        wrong_pin,
        identity(),
        Duration::from_millis(500)
    )
    .unwrap()
    .status()
    .is_err());
    let mut alien = Certs::new().leaf("primary.test");
    // Trust the real server, but present a client certificate signed by an unknown CA.
    alien.ca = certs.ca.der().to_vec();
    let alien_tls = ClientTls::new(
        &alien,
        "secondary.test",
        fingerprint(&server_cert.certificate),
    )
    .unwrap();
    assert!(TlsReplica::new(
        server.address,
        alien_tls,
        identity(),
        Duration::from_millis(500)
    )
    .unwrap()
    .status()
    .is_err());
    let good = ClientTls::new(
        &allowed,
        "secondary.test",
        fingerprint(&server_cert.certificate),
    )
    .unwrap();
    let mut stale = identity();
    stale.epoch += 1;
    assert!(TlsReplica::new(
        server.address,
        good.clone(),
        stale,
        Duration::from_millis(500)
    )
    .unwrap()
    .status()
    .is_err());
    assert!(
        TlsReplica::new(server.address, good, identity(), Duration::from_millis(500))
            .unwrap()
            .status()
            .is_ok()
    );
}

#[test]
fn stalled_tls_handshake_has_a_deadline() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let server = certs.leaf("secondary.test");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let hold = thread::spawn(move || {
        let (_socket, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_millis(500));
    });
    let tls = ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap();
    let mut peer = TlsReplica::new(address, tls, identity(), Duration::from_millis(100)).unwrap();
    let start = Instant::now();
    assert!(peer.status().is_err());
    assert!(start.elapsed() < Duration::from_millis(450));
    hold.join().unwrap();
}

#[test]
fn network_recovery_completes_decision_and_deduplicates_retry() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let (mut p, _server, mut peer) = pair(dir.path());
    let e = p.prepare(batch("one")).unwrap();
    peer.stage(e).unwrap();
    let decision = p.decide("one").unwrap();
    peer.apply(decision).unwrap();
    // Response to the caller was lost; primary has not applied its decision yet.
    assert!(p.view().unwrap().places.is_empty());
    let mut gate = Coordinator::new(p, peer).unwrap();
    gate.write(batch("one")).unwrap();
    gate.write(batch("one")).unwrap();
    assert_eq!(gate.view().unwrap().places.len(), 1);
    assert_eq!(gate.local_status().unwrap().entries.len(), 1);
}

struct ChildPeer {
    child: std::process::Child,
    address: std::net::SocketAddr,
    http_address: Option<std::net::SocketAddr>,
}
impl ChildPeer {
    fn start(dir: &Path, address: std::net::SocketAddr) -> Self {
        Self::start_http(dir, address, false)
    }
    fn start_http(dir: &Path, address: std::net::SocketAddr, http: bool) -> Self {
        Self::start_mode(dir, address, http, false)
    }
    fn start_mode(dir: &Path, address: std::net::SocketAddr, http: bool, quarantine: bool) -> Self {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vesta-peer"));
        command
            .arg(dir.join("child.vesta"))
            .arg(address.to_string())
            .arg(dir.join("server.der"))
            .arg(dir.join("key.der"))
            .arg(dir.join("ca.der"))
            .arg(dir.join("primary.der"));
        if http {
            command.arg("127.0.0.1:0");
        }
        if quarantine {
            command.arg("--require-bootstrap");
        }
        Self::command(command)
    }
    fn command(mut command: std::process::Command) -> Self {
        use std::io::BufRead;
        let child = command
            .env("VESTA_PROTOTYPE_PASSPHRASE", "network fixture passphrase")
            .env_remove("VESTA_PROTOTYPE_CRASH_APPLY")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let mut peer = Self {
            child,
            address: "127.0.0.1:0".parse().unwrap(),
            http_address: None,
        };
        let output = peer.child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let result = std::io::BufReader::new(output).read_line(&mut line);
            let _ = tx.send((result, line));
        });
        let (result, line) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(result.unwrap() > 0);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        peer.address = value["address"].as_str().unwrap().parse().unwrap();
        peer.http_address = value["http_address"].as_str().map(|s| s.parse().unwrap());
        peer
    }
}
impl Drop for ChildPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn actual_peer_process_kill_and_rejoin_restores_writes() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let server = certs.leaf("secondary.test");
    for (name, bytes) in [
        ("server.der", &server.certificate),
        ("key.der", &server.private_key),
        ("ca.der", &server.ca),
        ("primary.der", &client.certificate),
    ] {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    let child = ChildPeer::start(dir.path(), "127.0.0.1:0".parse().unwrap());
    let address = child.address;
    let tls = ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap();
    let peer =
        TlsReplica::new(address, tls.clone(), identity(), Duration::from_millis(500)).unwrap();
    let primary = Node::open(
        dir.path().join("p.vesta"),
        Role::Primary,
        identity(),
        "network fixture passphrase",
    )
    .unwrap();
    let mut gate = Coordinator::new(primary, peer).unwrap();
    gate.write(batch("one")).unwrap();
    drop(child);
    assert_eq!(
        gate.write(batch("two")).unwrap_err().outcome,
        Outcome::NotAccepted
    );
    assert_eq!(gate.view().unwrap().places.len(), 1);
    let _child = ChildPeer::start(dir.path(), address);
    gate.write(batch("two")).unwrap();
    gate.write(batch("two")).unwrap();
    let mut peer = TlsReplica::new(address, tls, identity(), Duration::from_millis(500)).unwrap();
    assert_eq!(gate.view().unwrap(), peer.view().unwrap());
    assert_eq!(gate.local_status().unwrap().entries.len(), 2);
}

#[test]
fn network_snapshot_bootstrap_then_tail_and_invalid_batch() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let (mut p, _old, mut old_peer) = pair(dir.path());
    commit(&mut p, &mut old_peer, batch("one")).unwrap();
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let server = certs.leaf("secondary.test");
    let replacement = Server::start(
        &dir.path().join("replacement.vesta"),
        ServerTls::new(&server, fingerprint(&client.certificate)).unwrap(),
    );
    let mut peer = TlsReplica::new(
        replacement.address,
        ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap(),
        identity(),
        Duration::from_millis(500),
    )
    .unwrap();
    peer.install(p.snapshot().unwrap()).unwrap();
    assert_eq!(p.view().unwrap(), peer.view().unwrap());
    let mut gate = Coordinator::new(p, peer).unwrap();
    gate.write(batch("two")).unwrap();
    let mut invalid = batch("three");
    invalid.changes.push(Change::PutFeature {
        id: "missing".into(),
        place_id: "not-found".into(),
        geojson: "{}".into(),
    });
    assert_eq!(gate.write(invalid).unwrap_err().status_code, 400);
    assert_eq!(gate.local_status().unwrap().entries.len(), 2);
    assert_eq!(gate.view().unwrap().places.len(), 2);
    thread::sleep(Duration::from_millis(1100));
    assert!(!gate.capabilities().writable);
    gate.write(batch("two")).unwrap();
    assert!(gate.capabilities().writable);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn axum_routes_use_real_mtls_and_report_degraded_state() {
    let _serial = NETWORK_TEST_SERIAL.lock().await;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let (p, server, peer) = pair(dir.path());
    let api = terrapi_vesta_replication::api::Api::new(Coordinator::new(p, peer).unwrap()).unwrap();
    let app = api.router();
    let request = |id: &str| {
        Request::post("/transactions")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&batch(id)).unwrap()))
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request("one")).await.unwrap().status(),
        200
    );
    drop(server);
    let failure = app.clone().oneshot(request("two")).await.unwrap();
    assert_eq!(failure.status(), 503);
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(failure.into_body(), 2048).await.unwrap()).unwrap();
    assert_eq!(value["retry_same_operation_id"], true);
    let response = app
        .oneshot(Request::get("/view").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let view: View =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(view.places.len(), 1);
}

#[test]
fn full_http_api_and_mtls_peer_binaries_survive_replica_restart() {
    let _serial = NETWORK_TEST_SERIAL.blocking_lock();
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    fn http(
        address: std::net::SocketAddr,
        path: &str,
        body: Option<String>,
    ) -> (u16, serde_json::Value) {
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let method = if body.is_some() { "POST" } else { "GET" };
        let body = body.unwrap_or_default();
        write!(socket,"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len()).unwrap();
        socket.flush().unwrap();
        let mut bytes = String::new();
        socket.read_to_string(&mut bytes).unwrap();
        let (head, body) = bytes.split_once("\r\n\r\n").unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (
            status,
            serde_json::from_str(body).unwrap_or(serde_json::Value::Null),
        )
    }
    fn write_transaction(address: std::net::SocketAddr, id: &str) -> (u16, serde_json::Value) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let response = http(
                address,
                "/transactions",
                Some(serde_json::to_string(&batch(id)).unwrap()),
            );
            if response.1["reason"] != "writer_busy" {
                return response;
            }
            assert!(Instant::now() < deadline, "writer never became available");
            thread::sleep(Duration::from_millis(20));
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let certs = Certs::new();
    let client = certs.leaf("primary.test");
    let server = certs.leaf("secondary.test");
    for (name, bytes) in [
        ("server.der", &server.certificate),
        ("key.der", &server.private_key),
        ("ca.der", &server.ca),
        ("primary.der", &client.certificate),
        ("client-key.der", &client.private_key),
    ] {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    let secondary = ChildPeer::start_http(dir.path(), "127.0.0.1:0".parse().unwrap(), true);
    let peer_address = secondary.address;
    assert_eq!(
        http(secondary.http_address.unwrap(), "/health/ready", None).0,
        503
    );
    assert_eq!(http(secondary.http_address.unwrap(), "/view", None).0, 503);
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vesta-api"));
    command
        .arg(dir.path().join("api.vesta"))
        .arg("127.0.0.1:0")
        .arg(peer_address.to_string())
        .arg(dir.path().join("primary.der"))
        .arg(dir.path().join("client-key.der"))
        .arg(dir.path().join("ca.der"))
        .arg(dir.path().join("server.der"))
        .arg("secondary.test");
    let primary = ChildPeer::command(command);
    assert_eq!(write_transaction(primary.address, "one").0, 200);
    assert_eq!(
        http(secondary.http_address.unwrap(), "/view", None).1["places"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        write_transaction(secondary.http_address.unwrap(), "rejected").0,
        503
    );
    drop(secondary);
    assert_eq!(write_transaction(primary.address, "two").0, 503);
    assert_eq!(http(primary.address, "/health/ready", None).0, 200);
    assert_eq!(
        http(primary.address, "/capabilities", None).1["writable"],
        false
    );
    assert_eq!(
        http(primary.address, "/view", None).1["places"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let replacement = ChildPeer::start_http(dir.path(), peer_address, true);
    assert_eq!(write_transaction(primary.address, "two").0, 200);
    assert_eq!(write_transaction(primary.address, "two").0, 200);
    assert_eq!(
        http(primary.address, "/view", None).1["places"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    drop(primary);
    let address = replacement.http_address.unwrap();
    assert_eq!(http(address, "/health/ready", None).0, 200);
    assert_eq!(
        http(address, "/view", None).1["places"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(http(address, "/capabilities", None).1["writable"], false);
    assert_eq!(write_transaction(address, "three").0, 503);
    drop(replacement);
    let restarted = ChildPeer::start_http(dir.path(), peer_address, true);
    assert_eq!(
        http(restarted.http_address.unwrap(), "/view", None).1["places"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        http(restarted.http_address.unwrap(), "/health/ready", None).0,
        200
    );
    drop(restarted);
    let quarantined = ChildPeer::start_mode(dir.path(), peer_address, true, true);
    assert_eq!(
        http(quarantined.http_address.unwrap(), "/health/ready", None).0,
        503
    );
    drop(quarantined);
    let awaiting = ChildPeer::start_http(dir.path(), peer_address, true);
    assert_eq!(http(awaiting.http_address.unwrap(), "/view", None).0, 503);
    let mut p = Node::open(
        dir.path().join("api.vesta"),
        Role::Primary,
        identity(),
        "network fixture passphrase",
    )
    .unwrap();
    let mut peer = TlsReplica::new(
        peer_address,
        ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap(),
        identity(),
        Duration::from_millis(500),
    )
    .unwrap();
    recover(&mut p, &mut peer).unwrap();
    assert_eq!(
        http(awaiting.http_address.unwrap(), "/health/ready", None).0,
        200
    );
    assert_eq!(
        http(awaiting.http_address.unwrap(), "/view", None).1["places"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}
