use super::*;
use crate::coordinator::{Coordinator, Outcome};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use std::{sync::mpsc, thread};

#[cfg(feature = "demo-api")]
#[tokio::test]
async fn snapshot_begin_and_finish_publish_unready_before_ack() {
    for materialized in [false, true] {
        use axum::{
            body::Body,
            http::{Request as HttpRequest, StatusCode},
        };
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
        let mut s =
            Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
        s.confirm_checkpoint(p.checkpoint().unwrap()).unwrap();
        let api = crate::secondary::ReadOnlyApi::default();
        api.refresh(&s).unwrap();
        let ready = || {
            api.router().oneshot(
                HttpRequest::get("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        assert_eq!(ready().await.unwrap().status(), StatusCode::OK);
        let (client, tls) = tls();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let projection = api.clone();
        let handle = thread::spawn(move || {
            serve_with_observer(
                &listener,
                &mut s,
                &tls,
                Duration::from_secs(2),
                &shutdown,
                |node| projection.refresh(node),
            )
            .unwrap()
        });
        let mut peer =
            TlsReplica::new(address, client, identity(), Duration::from_secs(2)).unwrap();
        let token = if materialized {
            peer.materialized_begin(p.materialized_manifest().unwrap())
                .unwrap()
                .token
        } else {
            peer.snapshot_begin(p.snapshot_manifest().unwrap())
                .unwrap()
                .token
        };
        assert_eq!(
            ready().await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        if materialized {
            peer.materialized_finish(token).unwrap();
        } else {
            peer.snapshot_finish(token).unwrap();
        }
        assert_eq!(
            ready().await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        peer.confirm_checkpoint(p.checkpoint().unwrap()).unwrap();
        assert_eq!(ready().await.unwrap().status(), StatusCode::OK);
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
    }
}

fn identity() -> Identity {
    Identity {
        cluster: "test".into(),
        tenant: "one".into(),
        epoch: 1,
        schema: 1,
    }
}
fn batch() -> Batch {
    Batch {
        identity: identity(),
        operation_id: "one".into(),
        changes: vec![Change::PutPlace {
            id: "one".into(),
            name: "Airport".into(),
        }],
    }
}
pub(super) fn tls() -> (ClientTls, ServerTls) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let ca = params.self_signed(&key).unwrap();
    let leaf = |name: &str| {
        let k = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.into()])
            .unwrap()
            .signed_by(&k, &ca, &key)
            .unwrap();
        Credentials {
            certificate: cert.der().to_vec(),
            private_key: k.serialize_der(),
            ca: ca.der().to_vec(),
        }
    };
    let client = leaf("primary.test");
    let server = leaf("secondary.test");
    (
        ClientTls::new(&client, "secondary.test", fingerprint(&server.certificate)).unwrap(),
        ServerTls::new(&server, fingerprint(&client.certificate)).unwrap(),
    )
}

#[cfg(feature = "experimental-recovery")]
pub(crate) fn tls_with_pins() -> (ClientTls, ServerTls, [u8; 32], [u8; 32]) {
    let (client, server) = tls();
    let candidate = server.pin;
    let survivor = client.pin;
    (client, server, candidate, survivor)
}

#[test]
fn frame_parser_rejects_oversize_truncation_and_invalid_json_without_allocation() {
    assert!(
        read_frame::<Envelope>(&mut ((MAX_FRAME + 1) as u32).to_be_bytes().as_slice()).is_err()
    );
    assert!(read_frame::<Envelope>(&mut 0u32.to_be_bytes().as_slice()).is_err());
    assert!(read_frame::<Envelope>(&mut [0, 0, 0, 3, b'{'].as_slice()).is_err());
    assert!(read_frame::<Envelope>(&mut [0, 0, 0, 1, b'!'].as_slice()).is_err());
    let mut out = Vec::new();
    assert!(write_frame(&mut out, &"x".repeat(MAX_MESSAGE + 1)).is_err());
    assert!(out.is_empty());
}

#[test]
fn absolute_deadline_cannot_be_extended_by_slow_drip_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        for _ in 0..20 {
            if socket.write_all(&[0]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let start = Instant::now();
    let mut stream = DeadlineStream {
        socket: TcpStream::connect(address).unwrap(),
        deadline: start + Duration::from_millis(90),
    };
    assert!(stream.read_exact(&mut [0; 100]).is_err());
    assert!(start.elapsed() < Duration::from_millis(300));
    server.join().unwrap();
}

#[test]
fn interrupted_multichunk_request_never_stages_partial_data() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture").unwrap();
    let mut b = batch();
    b.changes = vec![Change::PutPlace {
        id: "one".into(),
        name: "x".repeat(300_000),
    }];
    let entry = p.prepare(b).unwrap();
    let mut wire = Vec::new();
    write_frame(
        &mut wire,
        &Envelope {
            version: VERSION,
            identity: identity(),
            schema_contract: p.schema_contract().unwrap(),
            request: Request::Stage(entry.clone()),
        },
    )
    .unwrap();
    assert!(wire.len() > MAX_FRAME);
    let (client, server) = tls();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture").unwrap();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        assert!(serve_one(socket, &mut s, &server, Duration::from_secs(10)).is_err());
        assert!(s.status().unwrap().entries.is_empty());
        assert!(s.view().unwrap().places.is_empty());
        assert!(s.verified_view().unwrap().is_none());
        let (socket, _) = listener.accept().unwrap();
        serve_one(socket, &mut s, &server, Duration::from_secs(10)).unwrap();
        assert_eq!(s.status().unwrap().entries.len(), 1);
        assert!(s.view().unwrap().places.is_empty());
    });
    let socket = TcpStream::connect(address).unwrap();
    let mut io = DeadlineStream {
        socket,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    let mut conn = ClientConnection::new(client.config.clone(), client.name.clone()).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut io).unwrap();
    }
    verify_pin(conn.peer_certificates(), client.pin).unwrap();
    let mut stream = StreamOwned::new(conn, io);
    stream.write_all(&wire[..wire.len() - 1]).unwrap();
    stream.flush().unwrap();
    drop(stream);
    let mut peer = TlsReplica::new(address, client, identity(), Duration::from_secs(10)).unwrap();
    peer.stage(entry).unwrap();
    handle.join().unwrap();
}

#[test]
fn lost_stage_or_apply_ack_is_reconciled_without_duplicate() {
    // This tests durable ACK loss, not a 150 ms storage/TLS SLA. Other tests
    // independently prove the absolute slow-drip deadline. Normal RPCs need
    // headroom while the suite runs encrypted KDF/I/O work in parallel.
    let rpc_timeout = Duration::from_secs(5);
    for (after_apply, delay) in [
        (false, Duration::ZERO),
        (true, Duration::ZERO),
        (true, Duration::from_secs(6)),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("s.vesta");
        let path = sp.clone();
        let (client, server) = tls();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        // Opening a database performs KDF/I/O, not a network readiness check.
        // Own the ready database before spawning; listener.bind already admits
        // the connection backlog, so no timed readiness channel is necessary.
        let mut node = Node::open(path, Role::Secondary, identity(), "test passphrase").unwrap();
        let handle = thread::spawn(move || {
            loop {
                let (socket, _) = listener.accept().unwrap();
                let mut stream = accept_tls(socket, &server, rpc_timeout).unwrap();
                let envelope: Envelope = read_frame(&mut stream).unwrap();
                let target = if after_apply {
                    matches!(envelope.request, Request::Apply(_))
                } else {
                    matches!(envelope.request, Request::Stage(_))
                };
                let result = dispatch(&mut node, envelope).map_err(|e| e.to_string());
                if target {
                    assert!(result.is_ok());
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                    // Durable stage/apply happened, but the TLS response never reaches primary.
                    drop(stream);
                    break;
                }
                write_frame(
                    &mut stream,
                    &Reply {
                        version: VERSION,
                        identity: identity(),
                        schema_contract: node.schema_contract().unwrap(),
                        result,
                    },
                )
                .unwrap();
            }
            assert_eq!(node.view().unwrap().places.len(), usize::from(after_apply));
            done_tx.send(()).unwrap();
            server
        });
        let p = Node::open(
            dir.path().join("p.vesta"),
            Role::Primary,
            identity(),
            "test passphrase",
        )
        .unwrap();
        let peer = TlsReplica::new(address, client.clone(), identity(), rpc_timeout).unwrap();
        let mut gate = Coordinator::new(p, peer).unwrap();
        let failure = gate.write(batch()).unwrap_err();
        assert_eq!(
            failure.outcome,
            if after_apply {
                Outcome::Unknown
            } else {
                Outcome::NotAccepted
            }
        );
        assert_eq!(failure.status_code, 503);
        assert!(!gate.capabilities().writable);
        assert!(gate.view().unwrap().places.is_empty());
        done_rx.recv_timeout(Duration::from_secs(15)).unwrap();
        let server = handle.join().unwrap();
        // Restart the same replica at the same address. Lost ACK cannot erase its durable apply.
        let listener = TcpListener::bind(address).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let path = sp.clone();
        let mut s = Node::open(path, Role::Secondary, identity(), "test passphrase").unwrap();
        let handle = thread::spawn(move || {
            serve(&listener, &mut s, &server, rpc_timeout, &shutdown).unwrap();
        });
        gate.write(batch()).unwrap();
        gate.write(batch()).unwrap();
        assert_eq!(gate.local_status().unwrap().entries.len(), 1);
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        let s = Node::open(sp, Role::Secondary, identity(), "test passphrase").unwrap();
        assert_eq!(gate.view().unwrap(), s.view().unwrap());
    }
}

#[test]
fn wrong_version_or_tenant_never_reaches_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Node::open(
        dir.path().join("s.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    assert!(dispatch(
        &mut s,
        Envelope {
            version: 99,
            identity: identity(),
            schema_contract: schema_contract::expected(&reference::Proximi).unwrap(),
            request: Request::Status
        }
    )
    .is_err());
    let mut wrong = identity();
    wrong.tenant = "other".into();
    assert!(dispatch(
        &mut s,
        Envelope {
            version: VERSION,
            identity: wrong,
            schema_contract: schema_contract::expected(&reference::Proximi).unwrap(),
            request: Request::Abort("one".into())
        }
    )
    .is_err());
    assert!(s.status().unwrap().entries.is_empty());
}

#[test]
fn schema_contract_is_required_before_network_mutation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut p = Node::open(dir.path().join("p"), Role::Primary, identity(), "fixture")?;
    let mut s = Node::open(dir.path().join("s"), Role::Secondary, identity(), "fixture")?;
    let entry = p.prepare(batch())?;
    s.stage(entry)?;
    let before = s.journal_head()?;
    let contract = p.schema_contract()?;
    for field in 0..6 {
        let mut wrong = contract.clone();
        match field {
            0 => wrong.format += 1,
            1 => wrong.schema.name.push('x'),
            2 => wrong.schema.version += 1,
            3 => wrong.fingerprint_version += 1,
            4 => wrong.catalog_digest.push('x'),
            _ => (),
        }
        assert!(dispatch(
            &mut s,
            Envelope {
                version: if field == 5 { 11 } else { VERSION },
                identity: identity(),
                schema_contract: wrong,
                request: Request::Abort("one".into()),
            }
        )
        .is_err());
        assert_eq!(s.journal_head()?, before);
    }
    let mut legacy = serde_json::to_value(Envelope {
        version: VERSION,
        identity: identity(),
        schema_contract: contract.clone(),
        request: Request::Abort("one".into()),
    })?;
    legacy.as_object_mut().unwrap().remove("schema_contract");
    assert!(serde_json::from_value::<Envelope>(legacy).is_err());
    dispatch(
        &mut s,
        Envelope {
            version: VERSION,
            identity: identity(),
            schema_contract: contract,
            request: Request::Abort("one".into()),
        },
    )?;
    assert!(s.status()?.entries.is_empty());
    // Persisted metadata must still be verified after the node was opened.
    s.connection(|c| {
        c.execute("DELETE FROM node_schema_contract", [])?;
        Ok(())
    })?;
    assert!(s.summary().is_err());
    assert!(dispatch(
        &mut s,
        Envelope {
            version: VERSION,
            identity: identity(),
            schema_contract: p.schema_contract()?,
            request: Request::Status,
        }
    )
    .is_err());
    Ok(())
}

#[test]
fn authenticated_reply_with_wrong_or_missing_contract_is_not_an_ack() -> Result<()> {
    let (client, server) = tls();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let handle = thread::spawn(move || {
        for field in 0..7 {
            let (socket, _) = listener.accept().unwrap();
            let mut stream = accept_tls(socket, &server, Duration::from_secs(2)).unwrap();
            let request: Envelope = read_frame(&mut stream).unwrap();
            let mut contract = request.schema_contract;
            match field {
                0 => contract.format += 1,
                1 => contract.schema.name.push('x'),
                2 => contract.schema.version += 1,
                3 => contract.fingerprint_version += 1,
                4 => contract.catalog_digest.push('x'),
                _ => (),
            }
            let mut reply = serde_json::to_value(Reply {
                version: if field == 6 { 11 } else { VERSION },
                identity: request.identity,
                schema_contract: contract,
                result: Ok(Response::Ack),
            })
            .unwrap();
            if field == 5 {
                reply.as_object_mut().unwrap().remove("schema_contract");
            }
            write_frame(&mut stream, &reply).unwrap();
        }
    });
    let mut peer = TlsReplica::new(address, client, identity(), Duration::from_secs(2))?;
    for _ in 0..7 {
        assert!(peer.abort("one").is_err());
    }
    handle.join().unwrap();
    Ok(())
}

#[test]
fn missing_client_certificate_and_oversized_wire_frame_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.vesta");
    let (client, server) = tls();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut s = Node::open(path, Role::Secondary, identity(), "test passphrase").unwrap();
        ready_tx.send(()).unwrap();
        // Missing certificate, oversized frame, then a valid request to prove the process survived.
        for expected_ok in [false, false, true] {
            let (socket, _) = listener.accept().unwrap();
            assert_eq!(
                serve_one(socket, &mut s, &server, Duration::from_secs(1)).is_ok(),
                expected_ok
            );
        }
        assert!(s.status().unwrap().entries.is_empty());
    });
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let mut no_cert = client.clone();
    let mut config = (*no_cert.config).clone();
    #[derive(Debug)]
    struct NoCertificate;
    impl rustls::client::ResolvesClientCert for NoCertificate {
        fn resolve(
            &self,
            _: &[&[u8]],
            _: &[rustls::SignatureScheme],
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
        fn has_certs(&self) -> bool {
            false
        }
    }
    config.client_auth_cert_resolver = Arc::new(NoCertificate);
    no_cert.config = Arc::new(config);
    let mut peer =
        TlsReplica::new(address, no_cert, identity(), Duration::from_millis(500)).unwrap();
    assert!(peer.status().is_err());
    let socket = TcpStream::connect(address).unwrap();
    let mut io = DeadlineStream {
        socket,
        deadline: Instant::now() + Duration::from_secs(1),
    };
    let mut conn = ClientConnection::new(client.config.clone(), client.name.clone()).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut io).unwrap();
    }
    let mut stream = StreamOwned::new(conn, io);
    stream.write_all(b"VST3").unwrap();
    stream
        .write_all(&((MAX_MESSAGE + 1) as u32).to_be_bytes())
        .unwrap();
    stream.flush().unwrap();
    assert!(read_frame::<Reply>(&mut stream).is_err());
    drop(stream);
    assert!(
        TlsReplica::new(address, client, identity(), Duration::from_millis(500))
            .unwrap()
            .status()
            .is_ok()
    );
    handle.join().unwrap();
}

#[test]
fn cache_publication_failure_withholds_ack_and_retry_publishes_before_success() {
    let dir = tempfile::tempdir().unwrap();
    let (client, server) = tls();
    let mut p = Node::open(
        dir.path().join("p.vesta"),
        Role::Primary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    let mut s = Node::open(
        dir.path().join("s.vesta"),
        Role::Secondary,
        identity(),
        "test passphrase",
    )
    .unwrap();
    s.stage(p.prepare(batch()).unwrap()).unwrap();
    let decision = p.decide("one").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let published = Arc::new(AtomicBool::new(false));
    let observed = published.clone();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        assert!(
            serve_one_observed(socket, &mut s, &server, Duration::from_secs(1), &mut |_| {
                Err("publication fixture failure".into())
            })
            .is_err()
        );
        assert_eq!(s.view().unwrap().places.len(), 1);
        let (socket, _) = listener.accept().unwrap();
        serve_one_observed(
            socket,
            &mut s,
            &server,
            Duration::from_secs(1),
            &mut |node| {
                assert_eq!(node.view()?.places.len(), 1);
                observed.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
    });
    let mut peer =
        TlsReplica::new(address, client, identity(), Duration::from_millis(500)).unwrap();
    assert!(peer.apply(decision.clone()).is_err());
    assert!(!published.load(Ordering::SeqCst));
    peer.apply(decision).unwrap();
    assert!(published.load(Ordering::SeqCst));
    handle.join().unwrap();
}
