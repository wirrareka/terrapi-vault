//! Loopback-only demonstration, deliberately without end-user authentication.
use std::{io::Write, net::SocketAddr, time::Duration};
use terrapi_vesta_replication::{api::Api, coordinator::Coordinator, network::*, *};
#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 9 {
        return Err("usage: vesta-api <db> <http-loopback-ip:port> <peer-ip:port> <client.der> <client-key.der> <ca.der> <expected-server.der> <server-name>; passphrase in VESTA_PROTOTYPE_PASSPHRASE".into());
    }
    let address: SocketAddr = a[2].parse()?;
    if !address.ip().is_loopback() {
        return Err(
            "demo HTTP listener must be loopback: end-user authentication is not implemented"
                .into(),
        );
    }
    let credentials = Credentials {
        certificate: std::fs::read(&a[4])?,
        private_key: std::fs::read(&a[5])?,
        ca: std::fs::read(&a[6])?,
    };
    let tls = ClientTls::new(&credentials, &a[8], fingerprint(&std::fs::read(&a[7])?))?;
    let identity = Identity {
        cluster: "eu-pair".into(),
        tenant: "tenant-a".into(),
        epoch: 1,
        schema: 1,
    };
    let primary = Node::open(
        &a[1],
        Role::Primary,
        identity.clone(),
        &std::env::var("VESTA_PROTOTYPE_PASSPHRASE")?,
    )?;
    let peer = TlsReplica::new(a[3].parse()?, tls, identity, Duration::from_secs(1))?;
    let api = Api::new(Coordinator::new(primary, peer)?)?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!(
        "{}",
        serde_json::json!({"address":listener.local_addr()?.to_string()})
    );
    std::io::stdout().flush()?;
    let background = api.clone();
    let reconcile = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let _ = background.reconcile().await;
        }
    });
    let result = axum::serve(listener, api.router()).await;
    reconcile.abort();
    result?;
    Ok(())
}
