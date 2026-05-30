//! Small HTTP wire helpers shared by both service worlds. Deliberately framework-free
//! (serde + std only) so this crate stays axum/tokio-neutral — each service keeps its own
//! thin `err()`/handler glue around these shapes.

use serde::{Deserialize, Serialize};

/// Uniform error envelope returned by both services: a stable machine `error` code plus a
/// human-readable, non-contractual `detail`. The code enums are documented in each service's
/// OpenAPI spec (`spec/{broker,sync}-openapi.yaml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub detail: String,
}

/// Minimal success acknowledgement (`{"ok": true}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
}

/// Parse environment variable `key` into `T`, or `None` if it is unset/empty/unparseable.
/// The shared idiom behind every service's `from_env` config loader.
#[must_use]
pub fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok().and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body_roundtrips() {
        let e = ErrorBody {
            error: "replay".into(),
            detail: "seen".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, r#"{"error":"replay","detail":"seen"}"#);
        let back: ErrorBody = serde_json::from_str(&s).unwrap();
        assert_eq!(back.error, "replay");
    }

    #[test]
    fn ack_shape() {
        assert_eq!(
            serde_json::to_string(&Ack { ok: true }).unwrap(),
            r#"{"ok":true}"#
        );
    }

    #[test]
    fn env_parse_handles_missing_and_bad() {
        // A name that is almost certainly unset → None (not a panic).
        assert_eq!(
            env_parse::<u32>("VAULT_TRANSPORT_DEFINITELY_UNSET_XYZ"),
            None
        );
    }
}
