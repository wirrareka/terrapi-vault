//! B3 audit shipping to group-local OpenSearch.
//!
//! Vault owns its audit (`source:"vault"`). The durable tamper-evident hash chain
//! (`HashChainSink`) is the source of truth and the **shipping queue**: a background task
//! tails the chain file from a persisted byte **cursor**, bulk-indexes the new events'
//! B3 docs into `audit-events-{group}-YYYY.MM` (per the event's own timestamp), and only
//! advances the cursor once a batch is confirmed shipped.
//!
//! This gives durability + replay + drain for free: a ship failure (or crash/shutdown)
//! leaves the cursor unmoved, so the next tick — or the next process start — re-ships the
//! backlog. Shipping never blocks issuance (it reads the durable file out of band).
//!
//! Enabled by `VAULT_AUDIT_OS_URL` (+ `_USER` / `_PASSWORD`, optional `_INSECURE_TLS=1`).

use crate::config::BrokerConfig;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use vault_transport::audit::{AuditSink, HashChainSink};

/// How often the shipper tails the chain for new records.
const SHIP_INTERVAL_SECS: u64 = 5;

/// Work handed to the background shipper.
pub struct ShipTask {
    client: reqwest::Client,
    base_url: String,
    user: String,
    password: String,
    group: String,
    chain_path: PathBuf,
    cursor_path: PathBuf,
}

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

/// Build the durable audit sink and, if shipping is configured, the background ship task.
#[must_use]
pub fn build(cfg: &BrokerConfig) -> (Arc<dyn AuditSink>, Option<ShipTask>) {
    let sink: Arc<dyn AuditSink> = Arc::new(HashChainSink::new(cfg.audit_path.clone()));
    let Some(ship) = ShipConfig::from_env() else {
        return (sink, None);
    };
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(ship.insecure)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vault-broker: audit shipper DISABLED (http client: {e})");
            return (sink, None);
        }
    };
    let mut cursor_path = cfg.audit_path.clone();
    cursor_path.set_extension("shipped");
    eprintln!("vault-broker: audit shipping to OpenSearch enabled (tails the durable chain)");
    let task = ShipTask {
        client,
        base_url: ship.base_url,
        user: ship.user,
        password: ship.password,
        group: cfg.residency_group.as_str().to_owned(),
        chain_path: cfg.audit_path.clone(),
        cursor_path,
    };
    (sink, Some(task))
}

/// Tail the chain and ship new records every `SHIP_INTERVAL_SECS`, with a final flush on
/// shutdown. The persisted cursor makes a missed flush harmless (replayed next start).
pub async fn run(task: ShipTask) {
    let mut tick = tokio::time::interval(Duration::from_secs(SHIP_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = tick.tick() => ship_backlog(&task).await,
            _ = &mut shutdown => {
                ship_backlog(&task).await; // best-effort drain
                return;
            }
        }
    }
}

/// Ship every chain record past the cursor; advance the cursor only on success.
async fn ship_backlog(task: &ShipTask) {
    let from = read_cursor(&task.cursor_path);
    let Some((items, new_offset)) = read_new_records(&task.chain_path, from, &task.group) else {
        return;
    };
    if items.is_empty() {
        return;
    }
    let n = items.len();
    match bulk_ship(
        &task.client,
        &task.base_url,
        &task.user,
        &task.password,
        &items,
    )
    .await
    {
        Ok(()) => write_cursor(&task.cursor_path, new_offset),
        Err(e) => eprintln!("vault-broker: audit ship failed ({n} events): {e}"),
    }
}

/// Read complete chain lines after byte `from`; return `(index, event_json)` per record and
/// the new cursor offset (bytes up to and including the last complete line).
fn read_new_records(
    chain_path: &PathBuf,
    from: u64,
    group: &str,
) -> Option<(Vec<(String, String)>, u64)> {
    let mut f = std::fs::File::open(chain_path).ok()?;
    let len = f.metadata().ok()?.len();
    // File rotated/truncated below the cursor → re-ship from the start.
    let from = if from > len { 0 } else { from };
    f.seek(SeekFrom::Start(from)).ok()?;
    let mut buf = String::new();
    f.read_to_string(&mut buf).ok()?;
    Some(collect_backlog(&buf, from, group))
}

/// Pure backlog parse: split complete (newline-terminated) lines, extract each record's
/// event + its target index, and compute the new absolute cursor offset.
fn collect_backlog(buf: &str, from: u64, group: &str) -> (Vec<(String, String)>, u64) {
    let mut items = Vec::new();
    let mut consumed = 0usize; // bytes of complete lines within buf
    for line in buf.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break; // trailing partial line (mid-write) — stop, ship it next time
        }
        consumed += line.len();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((index, event)) = record_to_index_and_event(trimmed, group) {
            items.push((index, event));
        }
    }
    (items, from + consumed as u64)
}

/// Extract the shippable `(index, event_json)` from one chain line. The OpenSearch doc is
/// the inner B3 `event` (not the chain envelope); the index is derived from the event ts.
fn record_to_index_and_event(line: &str, group: &str) -> Option<(String, String)> {
    #[derive(serde::Deserialize)]
    struct Rec {
        event: Box<serde_json::value::RawValue>,
    }
    #[derive(serde::Deserialize)]
    struct TsOnly {
        ts: String,
    }
    let rec: Rec = serde_json::from_str(line).ok()?;
    let event_json = rec.event.get().to_owned();
    let ts: TsOnly = serde_json::from_str(&event_json).ok()?;
    Some((index_for(group, &ts.ts), event_json))
}

/// `audit-events-{group}-YYYY.MM` from an RFC3339 ts (`YYYY-MM-...`). Falls back to a
/// no-date index if the ts is malformed (should not happen).
fn index_for(group: &str, ts: &str) -> String {
    let ym = if ts.len() >= 7 && ts.as_bytes()[4] == b'-' {
        format!("{}.{}", &ts[0..4], &ts[5..7])
    } else {
        "unknown".to_string()
    };
    format!("audit-events-{group}-{ym}")
}

fn read_cursor(path: &PathBuf) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_cursor(path: &PathBuf, offset: u64) {
    if std::fs::write(path, offset.to_string()).is_ok() {
        restrict(path);
    }
}

#[cfg(unix)]
fn restrict(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict(_path: &PathBuf) {}

/// Bulk-index `(index, event_json)` items via the OpenSearch `_bulk` NDJSON API.
///
/// # Errors
/// A request failure or a non-success cluster status.
async fn bulk_ship(
    client: &reqwest::Client,
    base_url: &str,
    user: &str,
    password: &str,
    items: &[(String, String)],
) -> Result<(), String> {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(items.len() * 256);
    for (index, event) in items {
        let _ = writeln!(body, "{{\"index\":{{\"_index\":\"{index}\"}}}}");
        let _ = writeln!(body, "{event}");
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

    #[test]
    fn index_for_derives_year_month() {
        assert_eq!(
            index_for("eu", "2026-05-27T10:00:00.000Z"),
            "audit-events-eu-2026.05"
        );
        assert_eq!(
            index_for("uae", "2026-12-01T00:00:00Z"),
            "audit-events-uae-2026.12"
        );
    }

    #[test]
    fn collect_backlog_ships_complete_lines_only() {
        // two complete chain records + a trailing partial line
        let l1 = r#"{"seq":0,"prev":"00","hash":"aa","event":{"ts":"2026-05-01T00:00:00Z","action":"a"}}"#;
        let l2 = r#"{"seq":1,"prev":"aa","hash":"bb","event":{"ts":"2026-06-02T00:00:00Z","action":"b"}}"#;
        let partial = r#"{"seq":2,"prev":"bb""#; // no newline → not yet complete
        let buf = format!("{l1}\n{l2}\n{partial}");
        let (items, consumed) = collect_backlog(&buf, 100, "eu");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, "audit-events-eu-2026.05");
        assert_eq!(items[1].0, "audit-events-eu-2026.06");
        // consumed counts only the two newline-terminated lines, offset is absolute
        assert_eq!(consumed, 100 + (l1.len() + 1 + l2.len() + 1) as u64);
        // the shipped doc is the inner event, not the chain envelope
        assert!(items[0].1.contains("\"action\":\"a\""));
        assert!(!items[0].1.contains("\"seq\""));
    }

    #[test]
    fn cursor_roundtrip() {
        let p =
            std::env::temp_dir().join(format!("vault-ship-cursor-{}.shipped", std::process::id()));
        let _ = std::fs::remove_file(&p);
        assert_eq!(read_cursor(&p), 0); // missing → 0
        write_cursor(&p, 4096);
        assert_eq!(read_cursor(&p), 4096);
        let _ = std::fs::remove_file(&p);
    }

    /// Integration test: ship into a live OpenSearch and read the docs back. Skipped unless
    /// `VAULT_AUDIT_OS_TEST_URL` is set (docs/dev/opensearch-it.md for the docker cluster).
    #[tokio::test]
    async fn bulk_ships_events_into_an_index() {
        let Ok(url) = std::env::var("VAULT_AUDIT_OS_TEST_URL") else {
            eprintln!("skipping: VAULT_AUDIT_OS_TEST_URL unset");
            return;
        };
        let user = std::env::var("VAULT_AUDIT_OS_TEST_USER").unwrap_or_else(|_| "admin".into());
        let pass =
            std::env::var("VAULT_AUDIT_OS_TEST_PASSWORD").expect("VAULT_AUDIT_OS_TEST_PASSWORD");
        let base = url.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let index = format!("audit-events-it-{}", std::process::id());
        let items = vec![
            (
                index.clone(),
                r#"{"ts":"2026-05-27T00:00:00Z","action":"lease.expire"}"#.to_string(),
            ),
            (
                index.clone(),
                r#"{"ts":"2026-05-27T00:00:01Z","action":"creds.revoke"}"#.to_string(),
            ),
        ];
        bulk_ship(&client, &base, &user, &pass, &items)
            .await
            .unwrap();
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
        let _ = client
            .delete(format!("{base}/{index}"))
            .basic_auth(&user, Some(&pass))
            .send()
            .await;
    }
}
