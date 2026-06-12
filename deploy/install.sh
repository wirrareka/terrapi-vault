#!/bin/sh
# install.sh — terrapi-vesta broker operator runbook + idempotent installer (run
# INSIDE the jail, as root). Canonical install ORDER — read top to bottom.
#
#   ./install.sh eu
#   ./install.sh uae
#
# Pre-req: the jail exists (deploy/jail/provision.sh), the binary is built
# (deploy/build.sh) and present at /usr/local/sbin/vesta-broker, and infra has
# delivered: the server mTLS cert/key, the fleet Root CA bundle, and the
# audit-writer/OpenSearch-admin secret.
#
# INSTALL ORDER (do not reorder):
#   1) least-privilege user/dirs (also done by Bastillefile; idempotent)
#   2) zfs key   -> unlock the encrypted dataset BEFORE the broker
#   3) secrets   -> unseal.pass + os-admin.pass onto the dataset (mode 600)
#   4) config    -> vesta-broker.env (0600) + roles.json (0600) + tls/
#   5) rc enable -> zfskeys + vault_broker = YES
#   6) start     -> service zfskeys start ; service vault_broker start
set -eu

GROUP="${1:?usage: install.sh <eu|uae>}"
HERE="$(cd "$(dirname "$0")" && pwd)"          # deploy/
DATASET="${DATASET:-zroot/terrapi/vault}"
DATA="/var/db/terrapi-vesta"
ETC="/usr/local/etc/terrapi-vesta"

echo "=== terrapi-vesta broker install — group=${GROUP} ==="

# --- step 1: least-privilege + user/dirs + rc.d exec wrapper ----------------
sh "${HERE}/security/least-privilege.sh"
# Install the rc.d exec wrapper (sources the env drop-in, execs the broker).
install -d -m 755 /usr/local/libexec
install -m 755 "${HERE}/libexec/vesta-broker-run" /usr/local/libexec/vesta-broker-run

# --- step 2: unlock the encrypted dataset and verify (NEVER run sealed in prod) ---
echo "--> unlocking encrypted dataset ${DATASET}"
service zfskeys start || { echo "zfskeys start FAILED — abort"; exit 1; }
sh "${HERE}/zfs/check-encryption.sh" "${DATASET}" "${DATA}" || \
    { echo "encryption check FAILED — abort"; exit 1; }

# --- step 3: secrets onto the encrypted dataset (operator-provided) ----------
# unseal.pass — the broker's master-key passphrase (Argon2id → SQLCipher key).
#   Generate ONCE, back up to the offline encrypted-USB store, keep SEPARATE
#   from any store snapshot. mode 600, owned by the vault user.
if [ ! -f "${DATA}/unseal.pass" ]; then
    echo "ABORT: place the unseal passphrase at ${DATA}/unseal.pass (mode 600) first."
    echo "       e.g. head -c 32 /dev/random | b64encode -r - > ${DATA}/unseal.pass"
    exit 1
fi
install -d -o vault -g vault -m 700 "${DATA}/secrets"
# Two OpenSearch creds (least privilege):
#   os-credmgr.pass  — creds-engine (mint/delete ephemeral users); privileged security-API.
#   audit-writer.pass — write-only, for the broker's own source:"vault" B3 audit ship.
[ -f "${DATA}/secrets/os-credmgr.pass" ] || \
    echo "    NOTE: drop the OpenSearch creds-engine secret at ${DATA}/secrets/os-credmgr.pass (mode 600)."
[ -f "${DATA}/secrets/audit-writer.pass" ] || \
    echo "    NOTE: drop the write-only audit-writer secret at ${DATA}/secrets/audit-writer.pass (mode 600)."
chown vault:vault "${DATA}/unseal.pass"; chmod 600 "${DATA}/unseal.pass"

# --- step 4: config + roles + tls -------------------------------------------
install -d -m 755 "${ETC}" "${ETC}/tls"
# env + roles are 0640 root:vault — the broker reads them as the vault user.
if [ ! -s "${ETC}/vesta-broker.env" ]; then
    install -m 640 -o root -g vault "${HERE}/vesta-broker.env.sample" "${ETC}/vesta-broker.env"
    echo "--> wrote ${ETC}/vesta-broker.env from sample — EDIT it (group, WG IP, OS URL)."
fi
if [ ! -s "${ETC}/roles.json" ]; then
    install -m 640 -o root -g vault "${HERE}/roles.json.sample" "${ETC}/roles.json"
    echo "--> wrote ${ETC}/roles.json from sample — confirm the SAN→role/caps map."
fi
echo "    REQUIRED: ${ETC}/tls/{server.pem,server.key,fleet-root-ca.pem} from infra."
[ -f "${ETC}/tls/server.pem" ] && [ -f "${ETC}/tls/fleet-root-ca.pem" ] || \
    echo "    WARN: TLS material missing — the broker refuses to start in prod without it."
# The broker reads VESTA_TLS_KEY as the `vault` user → the key MUST be vault-readable.
# root-owned + group-readable (0640 root:vault): vault reads, cannot overwrite.
if [ -f "${ETC}/tls/server.key" ]; then
    chown root:vault "${ETC}/tls/server.key"; chmod 0640 "${ETC}/tls/server.key"
fi
[ -f "${ETC}/tls/server.pem" ] && chmod 0644 "${ETC}/tls/server.pem" || true

# --- step 5: enable services (zfskeys BEFORE vault_broker via rc REQUIRE) ----
sysrc zfskeys_enable=YES
sysrc vault_broker_enable=YES

# --- step 6: start + verify --------------------------------------------------
service vault_broker start
sleep 1
service vault_broker status || true
echo "--> readiness: curl -s http://\$VESTA_METRICS_BIND/metrics | grep vault_sealed  (expect 0)"

cat <<'RUNBOOK'

=== RUNBOOK ===
* UNSEAL (boot): the broker reads VESTA_UNSEAL_PASSPHRASE_FILE at start. If it
  boots SEALED, every mutating op 503s — check the dataset is unlocked and the
  passphrase file is correct. `GET /v1/sys/seal-status` shows {sealed:false} when ready.

* SSH-CA key / KMS KEKs: live INSIDE store.sqlcipher (encrypted at rest). Back up
  via `POST /v1/sys/store-snapshot` (online VACUUM INTO → ciphertext) + the .meta.json
  sidecar; ship both. NEVER co-locate a snapshot with the unseal passphrase.

* ROTATE a backup KEK: POST /v1/{group}/{tenant}/kms/{key_id}/rotate (old blobs keep
  unwrapping under their version).

* ROLES change: edit ${ETC}/roles.json (SAN→{role,caps}) and restart the broker.

* COMPROMISE-IR (host/store suspected exposed):
  1) Stop the broker; rotate the unseal passphrase + re-key the dataset.
  2) The SSH-CA key is the crown jewel — if exposed, mint a new CA, redistribute
     the trust anchor (GET /v1/{group}/ssh/ca), and add outstanding serials to the
     revocation list (GET /v1/{group}/ssh/revoked → build an sshd KRL).
  3) Rotate every brokered OpenSearch user (they are short-TTL; end sessions to
     cascade-delete). FIM/auditd: was unseal.pass / store read off-window?
RUNBOOK
echo "=== install complete ==="
