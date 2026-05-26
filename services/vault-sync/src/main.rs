//! vault-sync — personal multi-device vault sync (memento/probe). Phase 0 skeleton.
//!
//! Phase 3 fleshes out: VPS-hosted, E2E (server stores only opaque encrypted ops),
//! device-keypair enrolment via the vault passphrase, row-level oplog (UUIDv7 + HLC,
//! per-row LWW). Deliberately carries no platform concerns. See planning doc §5.

use vault_transport::Hlc;

fn main() {
    // Reuses the same at-rest crypto lib as memento/probe — server stays blind to plaintext.
    let _kdf = terrapi_vault::KdfParams::default();
    let cursor = Hlc {
        wall_ms: 0,
        counter: 0,
    };
    println!(
        "vault-sync {} — skeleton (E2E oplog). start cursor={cursor:?}. \
         Device enrol + push/pull land in Phase 3.",
        env!("CARGO_PKG_VERSION"),
    );
}
