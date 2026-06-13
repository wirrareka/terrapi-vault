# terrapi-vesta broker — FreeBSD deploy module

Ships the broker (Path A) on `medina` the same way the fleet ships kalista + identity:
a **release binary** + a **bastille vnet jail**, one per residency group (eu/uae), on the
per-group WireGuard mesh. Mirrors `quanto/identity/deploy/` conventions.

## Layout
- `build.sh` — build the `vesta-broker` release binary (`cargo build --release -p vesta-broker`).
- `jail/Bastillefile` + `jail/provision.sh` — stand up the vnet jail + delegate the
  encrypted dataset.
- `rc.d/vesta-broker` — service (unprivileged `vault` user; `REQUIRE zfskeys`).
- `zfs/zfskeys` — unlock the ZFS-encrypted crown-jewel dataset before the broker.
- `zfs/check-encryption.sh` — boot/monitoring self-check (encrypted + unlocked + unseal.pass).
- `vesta-broker.env.sample` — the env drop-in (`VESTA_*`, mode 0600, secrets from the dataset).
- `roles.json.sample` — `VESTA_ROLES_CONFIG`: SAN(dNSName) → {role, caps} (required in prod).
- `security/` — `pf.conf.snippet` (WG-only :8200/:8201), `fim-watchlist.txt`,
  `least-privilege.sh`, `audit_control.snippet`.
- `alerts/vesta-broker-alerts.yml` — email-first Prometheus rules (`vault_sealed`, scrape-up,
  encryption-off, issuance).
- `install.sh` — in-jail installer + operator runbook (unseal, snapshot/backup, rotation, IR).

## Install order
1. **host:** `jail/provision.sh <group> <wg-cidr>` — create the jail + delegate the dataset.
2. **build:** `build.sh`; copy the binary to `deploy/jail/usr/local/sbin/vesta-broker` before templating.
3. **host:** apply `security/pf.conf.snippet` (WG-only ingress to :8200/:8201).
4. **jail:** `install.sh <group>` — unlock dataset → drop secrets (`unseal.pass`, `os-admin.pass`)
   → config (`vesta-broker.env`, `roles.json`, `tls/`) → enable → start.

## What infra provides (kalista/identity pattern)
- WG IP `10.200.0.101` (eu); the server mTLS cert/key (fleet-Root-CA-signed, SAN
  `vault.eu.proximi.internal` + IP `10.200.0.101` — the convention dot form; a hyphen
  `vault-eu.proximi.internal` SAN MAY be retained for back-compat) + the fleet Root CA bundle;
  the client certs (`demon-operator`/`demon-system`, later `aether-backup`) already issued;
  the OpenSearch `audit-writer` secret; pf/FIM/auditd applied; `:8201` scrape.

## Crown jewels (encrypted ZFS dataset `zroot/terrapi/vault` → `/var/db/terrapi-vesta`)
- `store.sqlcipher` — the SSH-CA signing key + per-target KMS KEKs (encrypted at rest).
- `unseal.pass` — the master-key passphrase (mode 600). Back up to the offline encrypted-USB
  store, kept **separate** from any store snapshot (a combined backup defeats at-rest crypto).

## Ports (per `conventions/ports-env.md`)
- `:8200` broker API — mTLS-over-WireGuard vs the fleet Root CA, WG-only.
- `:8201` metrics — Prometheus text, WG /32 (on-box Prometheus jail), never `ext_if`.
