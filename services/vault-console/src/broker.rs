//! Broker fan-out: the console's mTLS client to the group's brokers. Aggregates their read-only
//! `observe` API and tags each result with its source broker. No secret values transit (the
//! broker observe API surfaces state only).

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::config::{BrokerEndpoint, ConsoleConfig, ConsoleTls};

#[derive(Debug, thiserror::Error)]
pub enum HubError {
    #[error("io: {0}")]
    Io(String),
    #[error("tls: {0}")]
    Tls(String),
}

pub struct BrokerHub {
    client: reqwest::Client,
    brokers: Vec<BrokerEndpoint>,
    group: String,
}

impl BrokerHub {
    /// Build the hub: an mTLS client (prod) or an insecure dev client.
    ///
    /// # Errors
    /// `Io`/`Tls` if the mTLS material can't be read/parsed, or no TLS + not dev.
    pub fn new(cfg: &ConsoleConfig) -> Result<Self, HubError> {
        let client = match &cfg.tls {
            Some(tls) => build_mtls_client(tls)?,
            None if cfg.allow_insecure_dev => reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| HubError::Tls(e.to_string()))?,
            None => {
                return Err(HubError::Tls(
                    "no VAULT_CONSOLE_TLS_* and VAULT_CONSOLE_ALLOW_INSECURE_DEV is not set".into(),
                ))
            }
        };
        Ok(Self {
            client,
            brokers: cfg.brokers.clone(),
            group: cfg.residency_group.clone(),
        })
    }

    #[must_use]
    pub fn group(&self) -> &str {
        &self.group
    }

    async fn get(&self, addr: &str, path: &str) -> Result<Value, reqwest::Error> {
        self.client
            .get(format!("https://{addr}{path}"))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await
    }

    /// Per-broker reachability + seal state (`/v1/sys/seal-status`), for the `/api/v1/brokers` view.
    pub async fn brokers(&self) -> Vec<Value> {
        let mut out = Vec::with_capacity(self.brokers.len());
        for b in &self.brokers {
            let seal = self.get(&b.addr, "/v1/sys/seal-status").await.ok();
            let reachable = seal.is_some();
            let sealed = seal
                .as_ref()
                .and_then(|v| v.get("sealed")?.as_bool())
                .unwrap_or(false);
            let version = seal
                .as_ref()
                .and_then(|v| v.get("version")?.as_str())
                .map(str::to_string);
            out.push(json!({
                "id": b.id,
                "addr": b.addr,
                "group": self.group,
                "reachable": reachable,
                "sealed": reachable && sealed,
                "version": version,
            }));
        }
        out
    }

    /// Fan out a GET to `path` across reachable brokers; tag each item of every `arrays` key with
    /// its broker id and merge; carry `scalars` (numeric, e.g. `now`/`next_seq`) as the max seen.
    /// An unreachable/erroring broker is skipped (its data is simply absent).
    pub async fn observe(&self, path: &str, arrays: &[&str], scalars: &[&str]) -> Value {
        let mut merged: HashMap<&str, Vec<Value>> = HashMap::new();
        let mut maxes: HashMap<&str, u64> = HashMap::new();
        for b in &self.brokers {
            let Ok(v) = self.get(&b.addr, path).await else {
                continue;
            };
            merge_into(&v, arrays, &b.id, &mut merged);
            for s in scalars {
                if let Some(n) = v.get(*s).and_then(Value::as_u64) {
                    let e = maxes.entry(*s).or_insert(0);
                    *e = (*e).max(n);
                }
            }
        }
        let mut obj = Map::new();
        for s in scalars {
            obj.insert(
                (*s).to_string(),
                Value::from(maxes.get(*s).copied().unwrap_or(0)),
            );
        }
        for key in arrays {
            obj.insert(
                (*key).to_string(),
                Value::Array(merged.remove(*key).unwrap_or_default()),
            );
        }
        Value::Object(obj)
    }

    /// Object-store status is a per-broker scalar (`{configured}`); assemble an array of
    /// `{broker, configured}` (the SPA's `ObjectStoreResponse`).
    pub async fn object_store(&self) -> Value {
        let path = format!("/v1/{}/observe/object-store", self.group);
        let mut arr = Vec::with_capacity(self.brokers.len());
        for b in &self.brokers {
            if let Ok(v) = self.get(&b.addr, &path).await {
                let configured = v
                    .get("configured")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                arr.push(json!({ "broker": b.id, "configured": configured }));
            }
        }
        json!({ "brokers": arr })
    }
}

/// Tag every item of each `arrays` key in `v` with `broker` and append into `merged`.
fn merge_into<'a>(
    v: &Value,
    arrays: &[&'a str],
    broker: &str,
    merged: &mut HashMap<&'a str, Vec<Value>>,
) {
    for key in arrays {
        let Some(items) = v.get(*key).and_then(Value::as_array) else {
            continue;
        };
        let bucket = merged.entry(*key).or_default();
        for item in items {
            let mut tagged = item.clone();
            if let Some(obj) = tagged.as_object_mut() {
                obj.insert("broker".to_string(), Value::String(broker.to_string()));
            }
            bucket.push(tagged);
        }
    }
}

fn build_mtls_client(tls: &ConsoleTls) -> Result<reqwest::Client, HubError> {
    let read = |p: &Path, what: &str| {
        std::fs::read(p).map_err(|e| HubError::Io(format!("{what} {}: {e}", p.display())))
    };
    let cert = read(&tls.cert, "console client cert")?;
    let key = read(&tls.key, "console client key")?;
    let ca = read(&tls.client_ca, "fleet root CA")?;

    // reqwest's rustls `Identity` wants the leaf cert chain + private key in one PEM.
    let mut identity_pem = cert;
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(&key);
    let identity =
        reqwest::Identity::from_pem(&identity_pem).map_err(|e| HubError::Tls(e.to_string()))?;

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .identity(identity);
    for root in
        reqwest::Certificate::from_pem_bundle(&ca).map_err(|e| HubError::Tls(e.to_string()))?
    {
        builder = builder.add_root_certificate(root);
    }
    builder.build().map_err(|e| HubError::Tls(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_tags_items_with_broker() {
        let v = json!({ "leases": [{ "lease_id": "x" }, { "lease_id": "y" }] });
        let mut merged: HashMap<&str, Vec<Value>> = HashMap::new();
        merge_into(&v, &["leases"], "vault-eu-1", &mut merged);
        merge_into(&v, &["leases"], "vault-eu-2", &mut merged);
        let leases = &merged["leases"];
        assert_eq!(leases.len(), 4);
        assert_eq!(leases[0]["broker"], "vault-eu-1");
        assert_eq!(leases[3]["broker"], "vault-eu-2");
        assert_eq!(leases[0]["lease_id"], "x");
    }

    #[test]
    fn merge_ignores_missing_or_non_array() {
        let v = json!({ "other": 1 });
        let mut merged: HashMap<&str, Vec<Value>> = HashMap::new();
        merge_into(&v, &["leases"], "b", &mut merged);
        assert!(merged.get("leases").is_none_or(Vec::is_empty));
    }
}
