//! Shared scaffold for terrapi-vault network services.
//!
//! This crate holds the small, genuinely-common pieces of the two service worlds:
//! - **vault-broker** (Svet A — proximi.io platform): per-group, multi-tenant,
//!   residency-air-gapped, mTLS-over-WireGuard.
//! - **vault-sync** (Svet B — personal apps memento/probe): single-user, E2E,
//!   server-blind, device-keypair auth.
//!
//! NOTHING platform-specific (OpenSearch, RethinkDB, tenants, residency) leaks into
//! `vault-sync`; this crate only exposes primitives each service opts into. The HTTP
//! stack (axum/tokio/rustls) and the real B3 emitter land in Phase 1.

pub mod audit;
pub mod lease;

use serde::{Deserialize, Serialize};

/// Residency group. A broker instance is pinned to exactly one (per-instance constant);
/// structurally it cannot serve another group. Personal sync does not use this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidencyGroup {
    Eu,
    Uae,
}

impl ResidencyGroup {
    /// Lowercase wire form used in paths, JWTs, and audit events.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResidencyGroup::Eu => "eu",
            ResidencyGroup::Uae => "uae",
        }
    }
}

/// Hybrid logical clock tick — the ordering primitive shared by the broker lease tree
/// and the sync oplog. (Wall-clock millis, logical counter.) Real impl in Phase 1/3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn residency_wire_form() {
        assert_eq!(ResidencyGroup::Eu.as_str(), "eu");
        assert_eq!(ResidencyGroup::Uae.as_str(), "uae");
    }

    #[test]
    fn hlc_orders_by_wall_then_counter() {
        let a = Hlc {
            wall_ms: 1,
            counter: 9,
        };
        let b = Hlc {
            wall_ms: 2,
            counter: 0,
        };
        assert!(a < b);
    }
}
