use std::future::IntoFuture;
use std::{
    io::Write,
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use terrapi_vesta_replication::{network::*, secondary::ReadOnlyApi, *};
#[tokio::main]
async fn main() -> Result<()> {
    let mut a: Vec<String> = std::env::args().collect();
    let require_bootstrap = a.last().is_some_and(|a| a == "--require-bootstrap");
    if require_bootstrap {
        a.pop();
    }
    if a.len() != 7 && a.len() != 8 {
        return Err("usage: vesta-peer <db> <listen-ip:port> <server-cert.der> <server-key.der> <ca.der> <allowed-primary-cert.der> [http-loopback-ip:port] [--require-bootstrap]; passphrase in VESTA_PROTOTYPE_PASSPHRASE".into());
    }
    let http_address: Option<SocketAddr> = a.get(7).map(|s| s.parse()).transpose()?;
    if http_address.is_some_and(|a| !a.ip().is_loopback()) {
        return Err("demo HTTP listener must be loopback".into());
    }
    let credentials = Credentials {
        certificate: std::fs::read(&a[3])?,
        private_key: std::fs::read(&a[4])?,
        ca: std::fs::read(&a[5])?,
    };
    let tls = ServerTls::new(&credentials, fingerprint(&std::fs::read(&a[6])?))?;
    let identity = Identity {
        cluster: "eu-pair".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: 1,
    };
    let mut node = Node::open(
        &a[1],
        Role::Secondary,
        identity,
        &std::env::var("VESTA_PROTOTYPE_PASSPHRASE")?,
    )?;
    if require_bootstrap {
        node.quarantine()?;
    }
    let listener = TcpListener::bind(&a[2])?;
    if let Some(address) = http_address {
        let api = ReadOnlyApi::default();
        api.refresh(&node)?;
        let http = tokio::net::TcpListener::bind(address).await?;
        println!(
            "{}",
            serde_json::json!({"address":listener.local_addr()?.to_string(),"http_address":http.local_addr()?.to_string()})
        );
        std::io::stdout().flush()?;
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let observer = api.clone();
        let mut replication = tokio::task::spawn_blocking(move || {
            serve_with_observer(
                &listener,
                &mut node,
                &tls,
                Duration::from_secs(2),
                &shutdown,
                |node| observer.refresh(node),
            )
            .map_err(|e| e.to_string())
        });
        tokio::select! {
            result=&mut replication=>{api.invalidate();result?.map_err(|e|->Box<dyn std::error::Error>{e.into()})?;}
            result=axum::serve(http,api.router()).into_future()=>{
                stop.store(true,Ordering::SeqCst);api.invalidate();
                replication.await?.map_err(|e|->Box<dyn std::error::Error>{e.into()})?;result?;
            }
        }
        return Ok(());
    }
    println!(
        "{}",
        serde_json::json!({"address":listener.local_addr()?.to_string()})
    );
    std::io::stdout().flush()?;
    serve(
        &listener,
        &mut node,
        &tls,
        Duration::from_secs(2),
        &AtomicBool::new(false),
    )
}
