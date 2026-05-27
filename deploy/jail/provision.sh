#!/bin/sh
# provision.sh — host-side helper to stand up a terrapi-vault broker jail.
# Wraps the Bastillefile with the per-group arg + the dataset delegation that
# bastille templates can't express. Run as root on the bastille host.
#
#   ./provision.sh eu  10.200.0.0/24
#   ./provision.sh uae 10.210.0.0/24
#
# ASSUMPTIONS — confirm with operator:
#   FREEBSD_REL=15.0-RELEASE (medina) ; DATASET=zroot/terrapi/vault.
#
# NOTE: the fleet (kalista/opensearch) runs jails as **ip4=inherit + a WG /32 alias**,
# NOT `-V` VNET. Create the jail the inherit way and alias the WG /32 (10.200.0.101)
# onto it; this script's `bastille create -V` is a fallback — prefer the inherit
# pattern per the coordination decision. The broker only ever binds its WG /32.
set -eu

GROUP="${1:?usage: provision.sh <group> <wg-subnet/cidr>}"
WG_CIDR="${2:?missing WG subnet, e.g. 10.200.0.0/24}"
JAIL="vault-${GROUP}"
FREEBSD_REL="${FREEBSD_REL:-15.0-RELEASE}"
DATASET="${DATASET:-zroot/terrapi/vault}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"   # deploy/

echo "==> creating vnet jail ${JAIL} on ${WG_CIDR} (group=${GROUP})"
bastille create -V "${JAIL}" "${FREEBSD_REL}" "${WG_CIDR}" 2>/dev/null || \
    echo "    jail ${JAIL} exists, continuing"

echo "==> delegating encrypted dataset ${DATASET} into the jail"
zfs set jailed=on "${DATASET}" 2>/dev/null || true
bastille zfs "${JAIL}" jail "${DATASET}" 2>/dev/null || \
    echo "    (delegate manually if your bastille lacks 'zfs ... jail')"

echo "==> copying binary into jail (build per deploy/build.sh first)"
[ -f "${HERE}/jail/usr/local/sbin/vault-broker" ] || \
    echo "    WARN: place the built binary at deploy/jail/usr/local/sbin/vault-broker before templating"

echo "==> applying Bastillefile template"
bastille template "${JAIL}" "${HERE}/jail" --arg GROUP="${GROUP}"

echo "==> NEXT (inside jail): run deploy/install.sh ${GROUP} to lay config + enable + start"
echo "    bastille console ${JAIL}"
echo "==> firewall: apply deploy/security/pf.conf.snippet on the HOST (WG-only to :8200/:8201)"
echo "==> verify: bastille cmd ${JAIL} /usr/local/etc/terrapi-vault-deploy/check-encryption.sh ${DATASET} /var/db/terrapi-vault"
