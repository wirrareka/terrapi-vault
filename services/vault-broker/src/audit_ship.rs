//! B3 audit shipping to group-local OpenSearch.
//!
//! Vault owns its audit (`source:"vault"`). The durable local JSONL sink is the source of
//! truth (written synchronously on every emit); shipping to OpenSearch is **best-effort**
//! and **non-blocking** — `emit` only enqueues, a background task bulk-indexes into
//! `audit-events-{group}-YYYY.MM`. A ship failure never blocks issuance (the event is
//! already durable locally).
//!
//! Shipping is enabled by `VAULT_AUDIT_OS_URL` (+ `_USER` / `_PASSWORD`, optional
//! `_INSECURE_TLS=1`). Absent → local-only. Redaction holds by construction: `AuditEvent`
//! has no secret field.

use crate::config::BrokerConfig;
use std::sync::Arc;
use tokio::sync::mpsc;
use vault_transport::audit::{AuditEvent, AuditSink, HashChainSink};

/// Composite sink: durable tamper-evident local hash chain + optional non-blocking ship queue.
pub struct ShippingSink {
    local: HashChainSink,
    tx: Option<mpsc::UnboundedSender<AuditEvent>>,
}

impl AuditSink for ShippingSink {
    fn emit(&self, event: &AuditEvent) {
        self.local.emit(event); // durable first
        if let Some(tx) = &self.tx {
            // best-effort: a closed/backed-up channel must never block the caller
            let _ = tx.send(event.clone());
        }
    }
}

/// Work handed to the background shipper.
pub struct ShipTask {
    rx: mpsc::UnboundedReceiver<AuditEvent>,
    client: reqwest::Client,
    base_url: String,
    user: String,
    password: String,
    group: String,
}

/// OpenSearch shipping config from `VAULT_AUDIT_OS_*`.
struct ShipConfig {
    base_url: String,
    user: String,
    password: String,
    insecure: bool,
}

impl ShipConfig {
    fn from_env() -> Option<Self> {
        let base_url = std::env::var("VAULT_AUDIT_OS_URL").ok()?;
        Some(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            user: std::env::var("VAULT_AUDIT_OS_USER").unwrap_or_else(|_| "admin".into()),
            password: std::env::var("VAULT_AUDIT_OS_PASSWORD").unwrap_or_default(),
            insecure: std::env::var("VAULT_AUDIT_OS_INSECURE_TLS").as_deref() == Ok("1"),
        })
    }
}

/// Build the broker's audit sink and, if shipping is configured, the background ship task.
#[must_use]
pub fn build(cfg: &BrokerConfig) -> (Arc<dyn AuditSink>, Option<ShipTask>) {
    let local = HashChainSink::new(cfg.audit_path.clone());
    let Some(ship) = ShipConfig::from_env() else {
        return (Arc::new(ShippingSink { local, tx: None }), None);
    };
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(ship.insecure)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vault-broker: audit shipper DISABLED (http client: {e})");
            return (Arc::new(ShippingSink { local, tx: None }), None);
        }
    };
    let (tx, rx) = mpsc::unbounded_channel();
    let task = ShipTask {
        rx,
        client,
        base_url: ship.base_url,
        user: ship.user,
        password: ship.password,
        group: cfg.residency_group.as_str().to_owned(),
    };
    eprintln!("vault-broker: audit shipping to OpenSearch enabled");
    (Arc::new(ShippingSink { local, tx: Some(tx) }), Some(task))
}

/// Drain the queue and bulk-index batches to OpenSearch until the broker shuts down.
pub async fn run(mut task: ShipTask) {
    while let Some(first) = task.rx.recv().await {
        let mut batch = vec![first];
        while let Ok(ev) = task.rx.try_recv() {
            batch.push(ev);
            if batch.len() >= 500 {
                break;
            }
        }
        let index = monthly_index(&task.group);
        if let Err(e) = ship_events(
            &task.client,
            &task.base_url,
            &task.user,
            &task.password,
            &index,
            &batch,
        )
        .await
        {
            // Best-effort: the events remain in the durable local JSONL.
            eprintln!("vault-broker: audit ship failed ({} events): {e}", batch.len());
        }
    }
}

/// `audit-events-{group}-YYYY.MM` for the current UTC month.
fn monthly_index(group: &str) -> String {
    let now = time::OffsetDateTime::now_utc();
    format!("audit-events-{group}-{:04}.{:02}", now.year(), u8::from(now.month()))
}

/// Bulk-index `events` into `index` via the OpenSearch `_bulk` NDJSON API.
///
/// # Errors
/// Returns a message if the request fails or the cluster reports a non-success status.
async fn ship_events(
    client: &reqwest::Client,
    base_url: &str,
    user: &str,
    password: &str,
    index: &str,
    events: &[AuditEvent],
) -> Result<(), String> {
    let mut body = String::with_capacity(events.len() * 256);
    let action = format!("{{\"index\":{{\"_index\":\"{index}\"}}}}\n");
    for ev in events {
        let doc = serde_json::to_string(ev).map_err(|e| e.to_string())?;
        body.push_str(&action);
        body.push_str(&doc);
        body.push('\n');
    }
    let resp = client
        .post(format!("{base_url}/_bulk"))
        .basic_auth(user, Some(password))
        .header("content-type", "application/x-ndjson")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("bulk request: {e}"))?;
    if !resp.status().is_success() {
        let code = resp.status();
        let detail = resp.text().await.unwrap_or_default();
        return Err(format!("bulk {code}: {detail}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_transport::audit::{Actor, ActorKind, Outcome, Target};

    fn sample(action: &str) -> AuditEvent {
        AuditEvent::vault(
            "2026-05-27T10:00:00.000Z".into(),
            "vault-eu-1".into(),
            Some("eu".into()),
            Actor {
                label: "vault-sweeper".into(),
                kind: ActorKind::System,
                id: Some("sweeper".into()),
                tenant: None,
            },
            action,
            Target { kind: "lease".into(), id: Some("id-1".into()) },
            Outcome::Success,
            None,
        )
    }

    #[test]
    fn monthly_index_shape() {
        let idx = monthly_index("eu");
        assert!(idx.starts_with("audit-events-eu-"));
        // audit-events-eu-YYYY.MM
        let date = idx.rsplit('-').next().unwrap();
        assert_eq!(date.len(), 7);
        assert_eq!(&date[4..5], ".");
    }

    /// Integration test: ship to a live OpenSearch and read the docs back. Skipped unless
    /// `VAULT_AUDIT_OS_TEST_URL` is set (docs/dev/opensearch-it.md for the docker cluster).
    #[tokio::test]
    async fn ships_events_into_an_index() {
        let Ok(url) = std::env::var("VAULT_AUDIT_OS_TEST_URL") else {
            eprintln!("skipping: VAULT_AUDIT_OS_TEST_URL unset");
            return;
        };
        let user = std::env::var("VAULT_AUDIT_OS_TEST_USER").unwrap_or_else(|_| "admin".into());
        let pass = std::env::var("VAULT_AUDIT_OS_TEST_PASSWORD").expect("VAULT_AUDIT_OS_TEST_PASSWORD");
        let base = url.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let index = format!("audit-events-it-{}", std::process::id());

        ship_events(
            &client,
            &base,
            &user,
            &pass,
            &index,
            &[sample("lease.expire"), sample("creds.revoke")],
        )
        .await
        .unwrap();

        // refresh so the docs are searchable, then count
        client
            .post(format!("{base}/{index}/_refresh"))
            .basic_auth(&user, Some(&pass))
            .send()
            .await
            .unwrap();
        let count: serde_json::Value = client
            .get(format!("{base}/{index}/_count"))
            .basic_auth(&user, Some(&pass))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(count["count"], 2);

        // cleanup
        let _ = client
            .delete(format!("{base}/{index}"))
            .basic_auth(&user, Some(&pass))
            .send()
            .await;
    }
}
