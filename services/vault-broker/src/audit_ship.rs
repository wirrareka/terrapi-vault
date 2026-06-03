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

/// Max bytes of chain read per tick. Bounds the `_bulk` body + in-memory buffer so a large
/// post-outage backlog drains incrementally (a tick ships at most this much, advances the
/// cursor, and the next tick continues) instead of building one unbounded request that could
/// OOM or be rejected — which would leave the cursor stuck replaying the same giant batch.
const MAX_SHIP_BYTES: u64 = 4 * 1024 * 1024;

/// Max events shipped per tick (a second bound, for many tiny events under the byte cap).
const MAX_SHIP_ITEMS: usize = 500;

/// One shippable record: `(target_index, doc_id, event_json)`. `doc_id` is the chain record's
/// hash — a stable, content-derived `_id` so re-shipping a batch (after a partial `_bulk`
/// failure or a crash) is **idempotent** in OpenSearch (same `_id` overwrites, no duplicates).
type ShipItem = (String, String, String);

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
    ca_path: Option<String>,
}

impl ShipConfig {
    fn from_env() -> Option<Self> {
        let base_url = std::env::var("VAULT_AUDIT_OS_URL").ok()?;
        Some(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            user: std::env::var("VAULT_AUDIT_OS_USER").unwrap_or_else(|_| "admin".into()),
            password: std::env::var("VAULT_AUDIT_OS_PASSWORD").unwrap_or_default(),
            insecure: std::env::var("VAULT_AUDIT_OS_INSECURE_TLS").as_deref() == Ok("1"),
            ca_path: std::env::var("VAULT_AUDIT_OS_CA")
                .ok()
                .filter(|s| !s.is_empty()),
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
    let client = match crate::opensearch::build_os_client(
        ship.insecure,
        ship.ca_path.clone(),
        "VAULT_AUDIT_OS_CA",
    ) {
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
fn read_new_records(chain_path: &PathBuf, from: u64, group: &str) -> Option<(Vec<ShipItem>, u64)> {
    let mut f = std::fs::File::open(chain_path).ok()?;
    let len = f.metadata().ok()?.len();
    // File rotated/truncated below the cursor → re-ship from the start.
    let from = if from > len { 0 } else { from };
    f.seek(SeekFrom::Start(from)).ok()?;
    // Read at most one tick's worth, then parse only up to the last complete line — a newline
    // is a UTF-8 boundary, so this is safe even if the byte cap fell mid-record. The remainder
    // (and anything beyond the item cap) ships on a later tick.
    let mut buf = Vec::new();
    f.take(MAX_SHIP_BYTES).read_to_end(&mut buf).ok()?;
    let last_nl = buf.iter().rposition(|&b| b == b'\n')?;
    let text = std::str::from_utf8(&buf[..=last_nl]).ok()?;
    Some(collect_backlog(text, from, group))
}

/// Pure backlog parse: split complete (newline-terminated) lines, extract each record's
/// event + its target index, and compute the new absolute cursor offset.
fn collect_backlog(buf: &str, from: u64, group: &str) -> (Vec<ShipItem>, u64) {
    let mut items = Vec::new();
    let mut consumed = 0usize; // bytes of complete lines within buf
    for line in buf.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break; // trailing partial line (mid-write) — stop, ship it next time
        }
        if items.len() >= MAX_SHIP_ITEMS {
            break; // per-tick item cap — the cursor advances over `consumed`, rest ships next tick
        }
        consumed += line.len();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(item) = record_to_ship_item(trimmed, group) {
            items.push(item);
        }
    }
    (items, from + consumed as u64)
}

/// Extract the shippable `(index, doc_id, event_json)` from one chain line. The OpenSearch doc
/// is the inner B3 `event` (not the chain envelope); the index is derived from the event ts and
/// the `_id` is the chain record's `hash` (stable → idempotent re-ship).
fn record_to_ship_item(line: &str, group: &str) -> Option<ShipItem> {
    #[derive(serde::Deserialize)]
    struct Rec {
        hash: String,
        event: Box<serde_json::value::RawValue>,
    }
    #[derive(serde::Deserialize)]
    struct TsOnly {
        ts: String,
    }
    let rec: Rec = serde_json::from_str(line).ok()?;
    let event_json = rec.event.get().to_owned();
    let ts: TsOnly = serde_json::from_str(&event_json).ok()?;
    Some((index_for(group, &ts.ts), rec.hash, event_json))
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

/// Bulk-index `(index, _id, event_json)` items via the OpenSearch `_bulk` NDJSON API. The `_id`
/// is the chain-record hash, so a re-ship (after a partial failure or crash) overwrites rather
/// than duplicating.
///
/// # Errors
/// A request failure, a non-success cluster status, **or a per-item failure** (`_bulk` returns
/// `200` with `errors:true`) — the latter must be an error so the ship cursor does not advance
/// past events that never made it into the index.
async fn bulk_ship(
    client: &reqwest::Client,
    base_url: &str,
    user: &str,
    password: &str,
    items: &[ShipItem],
) -> Result<(), String> {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(items.len() * 256);
    for (index, id, event) in items {
        let _ = writeln!(
            body,
            "{{\"index\":{{\"_index\":\"{index}\",\"_id\":\"{id}\"}}}}"
        );
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
    let code = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !code.is_success() {
        return Err(format!("bulk {code}: {text}"));
    }
    if let Some(failed) = bulk_failures(&text) {
        return Err(format!(
            "bulk reported {failed} per-item failure(s) (errors:true)"
        ));
    }
    Ok(())
}

/// Inspect a `200` OpenSearch `_bulk` response body. `Some(n)` if it reported `errors:true`
/// (with `n` = items whose `status >= 300`); `None` if every item succeeded. `_bulk` returns
/// `200` even on per-item failure, so this is what actually decides success.
fn bulk_failures(body: &str) -> Option<usize> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if v.get("errors").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    let n = v
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map_or(0, |items| {
            items
                .iter()
                .filter(|it| {
                    // each item is `{ "<op>": { "status": <n>, ... } }`
                    it.as_object()
                        .and_then(|o| o.values().next())
                        .and_then(|op| op.get("status"))
                        .and_then(serde_json::Value::as_u64)
                        .is_none_or(|s| s >= 300)
                })
                .count()
        });
    Some(n)
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
        // the doc _id is the chain hash (stable → idempotent re-ship)
        assert_eq!(items[0].1, "aa");
        assert_eq!(items[1].1, "bb");
        // the shipped doc is the inner event, not the chain envelope
        assert!(items[0].2.contains("\"action\":\"a\""));
        assert!(!items[0].2.contains("\"seq\""));
    }

    #[test]
    fn bulk_failures_detects_partial_errors() {
        // errors:false → None (full success)
        let ok = r#"{"took":3,"errors":false,"items":[{"index":{"status":201}}]}"#;
        assert_eq!(bulk_failures(ok), None);
        // errors:true with one 201 and one 429 → Some(1)
        let partial = r#"{"took":3,"errors":true,"items":[{"index":{"status":201}},{"index":{"status":429,"error":{"type":"x"}}}]}"#;
        assert_eq!(bulk_failures(partial), Some(1));
        // unparseable → None (caller still treated 200 as success; conservative)
        assert_eq!(bulk_failures("not json"), None);
    }

    #[test]
    fn collect_backlog_caps_items_per_tick() {
        // More records than the per-tick cap: only MAX_SHIP_ITEMS ship, and `consumed` covers
        // exactly those lines so the cursor advances partially and the rest ships next tick.
        use std::fmt::Write as _;
        let mut buf = String::new();
        for i in 0..(MAX_SHIP_ITEMS + 7) {
            let _ = writeln!(
                buf,
                r#"{{"seq":{i},"prev":"00","hash":"aa","event":{{"ts":"2026-05-01T00:00:00Z","action":"a{i}"}}}}"#
            );
        }
        let (items, consumed) = collect_backlog(&buf, 0, "eu");
        assert_eq!(items.len(), MAX_SHIP_ITEMS);
        // `consumed` covers only the shipped lines — a real partial advance, less than the whole.
        assert!(consumed > 0 && consumed < buf.len() as u64);
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
                "id-1".to_string(),
                r#"{"ts":"2026-05-27T00:00:00Z","action":"lease.expire"}"#.to_string(),
            ),
            (
                index.clone(),
                "id-2".to_string(),
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
