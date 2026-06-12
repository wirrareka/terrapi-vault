#!/bin/sh
# least-privilege.sh — hardening notes + idempotent setup for the broker host.
# Read as a runbook; the CMDs are safe to run as root on the jail host.
#
# Principle: the broker runs unprivileged; humans reach the box as `ops` + sudo;
# root SSH is disabled; the crown-jewel files are root/vault-owned, mode-600.
set -eu

# --- Service user: unprivileged, nologin, home on the encrypted dataset. ---
pw groupadd -n vault 2>/dev/null || true
pw useradd  -n vault -g vault -d /var/db/terrapi-vesta -s /usr/sbin/nologin \
    -c "terrapi-vesta broker" 2>/dev/null || true

# --- File ownership / modes (defense in depth on top of ZFS encryption). ---
#   /var/db/terrapi-vesta        : vault:vault 0700 (store + audit live here)
#   unseal.pass, secrets/*       : vault:vault 0600 (master-key passphrase, OS admin)
#   /usr/local/etc/terrapi-vesta : config dir; env + roles.json 0600 root:vault
install -d -o vault -g vault -m 0700 /var/db/terrapi-vesta          2>/dev/null || true
install -d -o vault -g vault -m 0700 /var/db/terrapi-vesta/secrets  2>/dev/null || true
install -d -o vault -g vault -m 0700 /var/db/terrapi-vesta/snapshots 2>/dev/null || true
[ -f /var/db/terrapi-vesta/unseal.pass ] && chown vault:vault /var/db/terrapi-vesta/unseal.pass && chmod 0600 /var/db/terrapi-vesta/unseal.pass || true
# env + roles: root-owned, group-READABLE (0640) — the broker reads them as the vault
# user (0600 root:vault would deny the vault read). No literal secrets in either file
# (the env references dataset paths via $(cat ...); roles is just SAN→{role,caps}).
[ -f /usr/local/etc/terrapi-vesta/vesta-broker.env ] && chown root:vault /usr/local/etc/terrapi-vesta/vesta-broker.env && chmod 0640 /usr/local/etc/terrapi-vesta/vesta-broker.env || true
[ -f /usr/local/etc/terrapi-vesta/roles.json ] && chown root:vault /usr/local/etc/terrapi-vesta/roles.json && chmod 0640 /usr/local/etc/terrapi-vesta/roles.json || true
# server.key: root-owned, group-READABLE (0640) — the broker reads it as the vault user
# but must not be able to overwrite it. (0600 root:vault would deny the vault read.)
[ -f /usr/local/etc/terrapi-vesta/tls/server.key ] && chown root:vault /usr/local/etc/terrapi-vesta/tls/server.key && chmod 0640 /usr/local/etc/terrapi-vesta/tls/server.key || true

# --- SSH: no root login, key-only, admin via `ops` + sudo. ---
# In /etc/ssh/sshd_config (apply by hand / config mgmt; shown here as intent):
#   PermitRootLogin no
#   PasswordAuthentication no
#   AllowUsers ops
pw groupadd -n ops 2>/dev/null || true
pw useradd  -n ops -g ops -G wheel -m -s /bin/sh -c "Operations admin" 2>/dev/null || true
# sudo (pkg install sudo): %wheel ALL=(ALL:ALL) ALL, require password + syslog.
# The vault service account gets NO sudo and NO shell.

echo "least-privilege applied. Set sshd PermitRootLogin no + restart sshd by hand."
echo "Reminder: unseal.pass + the SSH-CA key (in store.sqlcipher) are CROWN JEWELS —"
echo "          back them up to the offline encrypted-USB store, kept SEPARATE from snapshots."
