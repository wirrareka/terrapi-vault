#!/bin/sh
# build.sh — build the terrapi-vault broker release binary for FreeBSD.
#
# The broker ships as ONE self-contained binary (`vault-broker`). It bundles
# SQLCipher (rusqlite `bundled-sqlcipher`) and uses rustls (aws-lc-rs) for the
# mTLS-over-WireGuard listener — so the only runtime lib it needs beyond base is
# the CA trust store. No SAML / libxml caveats (unlike identity).
#
# Build via the FreeBSD builder (same host the fleet uses).
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVICES="${ROOT}/services"   # the broker lives in the separate services workspace

# --- Build-time prerequisites (FreeBSD 14.2-RELEASE; confirm version) --------
#   pkg install -y rust pkgconf cmake
#   # rust+cargo: the broker; pkgconf+cmake: aws-lc-rs (rustls crypto) + the
#   # bundled SQLCipher build (cc from base). No XML / OpenSSL-dev needed.

echo "==> building vault-broker (release) from ${SERVICES}"
cd "${SERVICES}"
cargo build --release -p vault-broker
# The lib crate stays at the repo root; the services workspace path-deps it.

# Install the binary (run as root, or copy into the jail via bastille cp):
#   install -m 755 services/target/release/vault-broker /usr/local/sbin/vault-broker
echo "==> built: ${SERVICES}/target/release/vault-broker"
echo "    install -m 755 services/target/release/vault-broker /usr/local/sbin/vault-broker"

# VERIFY it is self-contained enough (no surprise dynamic deps beyond base):
#   ldd /usr/local/sbin/vault-broker
#   # Expect libc/libthr/libgcc_s + base only; SQLCipher is statically bundled.
#
# Smoke (dev, NEVER prod): VAULT_ALLOW_INSECURE_DEV=1 ./vault-broker &
#   curl -s 127.0.0.1:8201/metrics   # vault_sealed gauge + audit counters
