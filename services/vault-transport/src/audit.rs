//! Canonical B3 audit event (`source:"vault"`) + a best-effort local sink.
//!
//! Ownership decision (coordination/conventions/secrets-broker.md): the broker emits
//! its own B3 events; consumers do NOT double-record. Shipping to group-local
//! OpenSearch is layered on in Phase 2 and must never block an issuance — the durable
//! local store here is the source of truth, the index is a fan-out copy.
//!
//! **Redaction by construction:** `AuditEvent` has no field that can hold a secret
//! value, private key, password, or signed certificate. Only metadata (action, ids,
//! ttl, outcome) is representable, so a secret cannot be emitted by accident.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

/// Actor kind, mirroring `conventions/audit-event-schema.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    ApiToken,
    System,
    DevBypass,
}

/// Who performed the action. Never carries credential material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub label: String,
    pub kind: ActorKind,
    pub id: Option<String>,
    pub tenant: Option<String>,
}

/// What was acted on (a lease, a session, an SSH principal set, a role) — id only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: String,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
}

/// One canonical B3 audit document. `source` is fixed to `"vault"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// RFC3339 millis UTC.
    pub ts: String,
    pub schema_version: u8,
    pub source: &'static str,
    pub node: String,
    pub residency_group: Option<String>,
    pub actor: Actor,
    /// `<noun>.<verb>`, e.g. `ssh.sign`, `creds.issue`, `lease.revoke`, `session.end`.
    pub action: String,
    pub target: Target,
    pub outcome: Outcome,
    pub request_id: Option<String>,
}

impl AuditEvent {
    /// Build a vault-sourced event. `ts` is supplied by the caller (the broker passes an
    /// RFC3339 millis UTC string) so this crate stays clock-agnostic and test-friendly.
    // Mirrors the canonical B3 document field-for-field; a builder would obscure that.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn vault(
        ts: String,
        node: String,
        residency_group: Option<String>,
        actor: Actor,
        action: impl Into<String>,
        target: Target,
        outcome: Outcome,
        request_id: Option<String>,
    ) -> Self {
        Self {
            ts,
            schema_version: 1,
            source: "vault",
            node,
            residency_group,
            actor,
            action: action.into(),
            target,
            outcome,
            request_id,
        }
    }
}

/// A sink the broker emits audit events to.
pub trait AuditSink: Send + Sync {
    /// Best-effort: a failure here must never break the user-visible action.
    fn emit(&self, event: &AuditEvent);
}

/// Durable local sink: append one JSON line per event (the hash-chained store + the
/// OpenSearch shipper come in Phase 2). Errors are swallowed (best-effort) by design.
pub struct JsonlSink {
    path: PathBuf,
}

impl JsonlSink {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl AuditSink for JsonlSink {
    fn emit(&self, event: &AuditEvent) {
        let Ok(mut line) = serde_json::to_vec(event) else {
            return;
        };
        line.push(b'\n');
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = f.write_all(&line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditEvent {
        AuditEvent::vault(
            "2026-05-26T10:00:00.000Z".into(),
            "vault-eu-1".into(),
            Some("eu".into()),
            Actor {
                label: "demon@host".into(),
                kind: ActorKind::System,
                id: None,
                tenant: Some("11111111-1111-4111-8111-111111111111".into()),
            },
            "ssh.sign",
            Target {
                kind: "ssh_cert".into(),
                id: Some("serial-42".into()),
            },
            Outcome::Success,
            Some("req-1".into()),
        )
    }

    #[test]
    fn source_is_always_vault() {
        assert_eq!(sample().source, "vault");
        assert_eq!(sample().schema_version, 1);
    }

    #[test]
    fn serializes_without_any_secret_field() {
        let json = serde_json::to_string(&sample()).unwrap();
        // The type cannot represent secret material; assert the shape is metadata-only.
        assert!(json.contains("\"source\":\"vault\""));
        assert!(json.contains("\"action\":\"ssh.sign\""));
        assert!(!json.to_lowercase().contains("password"));
        assert!(!json.to_lowercase().contains("private_key"));
    }

    #[test]
    fn jsonl_sink_appends_line() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vault-audit-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sink = JsonlSink::new(&path);
        sink.emit(&sample());
        sink.emit(&sample());
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2);
        let _ = std::fs::remove_file(&path);
    }
}
