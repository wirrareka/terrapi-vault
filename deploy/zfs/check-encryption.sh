#!/bin/sh
# check-encryption.sh — contract check: the terrapi-vault crown-jewel dataset is
# ZFS-native-encrypted, unlocked, and mounted at the expected mountpoint, and the
# unseal passphrase is present + mode-600.
#
# Run on the host (or inside the jail with zfs visibility). Exit 0 = pass. Wire
# into the boot self-check AND the "encryption-at-rest=off" alert
# (deploy/alerts/vault-broker-alerts.yml). A FAIL here is a CRITICAL page: the
# SSH-CA signing key + KMS KEKs would be sitting in cleartext.
set -eu

DATASET="${1:-zroot/terrapi/vault}"
EXPECT_MOUNT="${2:-/var/db/terrapi-vault}"

fail() { echo "FAIL: $1" >&2; exit 1; }

enc=$(zfs get -H -o value encryption "$DATASET" 2>/dev/null || echo "missing")
[ "$enc" = "missing" ] && fail "dataset $DATASET not found"
[ "$enc" = "off" ] && fail "dataset $DATASET is NOT encrypted (encryption=off) — at-rest broken"
case "$enc" in aes-256-gcm|aes-256-ccm|aes-128-gcm|aes-192-gcm|on) : ;; *) fail "unexpected encryption=$enc" ;; esac

ks=$(zfs get -H -o value keystatus "$DATASET" 2>/dev/null || echo "none")
[ "$ks" = "available" ] || fail "dataset $DATASET key not loaded (keystatus=$ks)"

mounted=$(zfs get -H -o value mounted "$DATASET" 2>/dev/null || echo "no")
[ "$mounted" = "yes" ] || fail "dataset $DATASET not mounted"

mp=$(zfs get -H -o value mountpoint "$DATASET" 2>/dev/null || echo "")
[ "$mp" = "$EXPECT_MOUNT" ] || fail "mountpoint $mp != expected $EXPECT_MOUNT"

# Unseal passphrase must be present + mode-600 (the broker reads it to unseal;
# without it the broker boots SEALED and every mutating op 503s).
[ -f "$EXPECT_MOUNT/unseal.pass" ] || fail "unseal passphrase missing at $EXPECT_MOUNT/unseal.pass"
perm=$(stat -f '%Lp' "$EXPECT_MOUNT/unseal.pass" 2>/dev/null || echo "")
[ "$perm" = "600" ] || fail "unseal.pass perms $perm != 600"

# The store may not exist yet on first boot (created on first unseal) — only
# check its perms if present.
if [ -f "$EXPECT_MOUNT/store.sqlcipher" ]; then
    sperm=$(stat -f '%Lp' "$EXPECT_MOUNT/store.sqlcipher" 2>/dev/null || echo "")
    case "$sperm" in 600|640) : ;; *) fail "store.sqlcipher perms $sperm not 600/640" ;; esac
fi

echo "PASS: $DATASET encryption=$enc keystatus=available mounted at $mp; unseal.pass 0600."
