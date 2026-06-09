# terrapi-vault — Security Analysis (2026-06-09)

Multi-agent audit: 5 specializovaných agentov (core lib, vault-broker, vault-console+SPA,
vault-sync+transport, supply chain). Read-only analýza, žiadne zmeny kódu.

## Súhrnné hodnotenie per komponent

| Komponent | Riziko | Hlavný problém |
|---|---|---|
| core lib (root crate) | **LOW** | len hardening (KDF param floor) |
| vault-broker | **MODERATE** | lease persistence, authz granularita |
| vault-console + SPA | **LOW-MEDIUM** | login-CSRF, chýbajúce security headers |
| vault-sync + transport | **MODERATE-LOW** | neautentizovaný `/account`, žiadna device revocation |
| supply chain / CI | **LOW-MODERATE** | červený deny gate (rsa dev-dep), tag-pinned actions |

Žiadny nález nie je vzdialene zneužiteľný bez platného fleet certu na WG mesh-i
(broker) alebo bez prelomenia OIDC (console). Krypto jadro je nadpriemerne kvalitné.

---

## Nálezy podľa závažnosti

### HIGH
1. **broker — lease state len in-memory** (`services/vault-broker/src/state.rs:99`,
   `vault-transport/src/lease.rs:87`): pád/reštart brokera stratí všetky leases →
   osirelé OpenSearch internal users bez TTL a bez boot-reconciliation
   (`opensearch.rs:114`), čo popiera short-TTL garanciu. → Perzistovať lease ledger
   v sealed store (plánované v `config.rs:75`) alebo boot sweep `v-<role>-*` userov.
2. **supply chain — `cargo deny check advisories` FAILUJE**: RUSTSEC-2023-0071
   (Marvin, `rsa` 0.9.10) — `rsa` je teraz dev-dep vault-console (OIDC testy),
   komentár v `deny.toml` („cargo tree -i rsa je prázdny") už neplatí. → Odstrániť
   dev-dep alebo pridať re-zdôvodnený ignore + opraviť komentár.

### MEDIUM
3. **broker — lease/session ops bez ownership checku** (`http.rs:1340,1358,1304`):
   ľubovoľný principal s `leases`/`session` cap môže renew/revoke cudzie leases podľa ID.
   → Viazať na parent session/principal.
4. **broker — KMS JWT obchádza mTLS cap** (`http.rs:976-995`): pri nakonfigurovanom
   `kms_jwt` sa `Kms` capability vôbec nekontroluje — observe-only identita s ukradnutým
   tenant JWT môže wrap/unwrap. → Vyžadovať cap aj JWT súčasne.
5. **broker — SSH CA bez principal constraints** (`http.rs:294`, `ssh_ca.rs:123`):
   ľubovoľné `principals` (aj `root`), žiadne critical options. → Per-role allowlist
   principalov + `source-address`.
6. **broker — mTLS bez CRL** (`tls.rs:96`): kompromitovaný daemon cert platí do expiry.
   → CRL alebo krátka životnosť fleet certov.
7. **broker — OpenSearch creds zdieľajú jednu rolu** (`opensearch.rs:117-121`):
   `tenant` je len kozmetický atribút — cred tenanta A vie písať indexy tenanta B.
   → Per-tenant role templaty, alebo zdokumentovať ako accepted risk.
8. **console — login-CSRF / session fixation** (`http.rs:86,113`): `state` nie je
   viazaný na iniciujúci prehliadač — útočník vie obeti podstrčiť svoju session.
   → Pre-auth cookie `__Host-vc_auth=<state-hash>` pri `/auth/login`, overiť v callbacku.
9. **console — žiadne security headers** (`http.rs:31-48`, `ui.rs:20-38`): chýba CSP,
   frame-ancestors, nosniff, Referrer-Policy, `no-store` na `/api/*`. → Header layer.
10. **console — `VAULT_CONSOLE_ALLOW_INSECURE_DEV=1` vypína auth AJ broker TLS naraz**
    (`http.rs:58-63`, `broker.rs:37`): jedna env premenná v prode = úplne otvorená
    konzola. → Povoliť len na loopback binde; rozdeliť na dva flagy.
11. **sync — `/account` neautentizovaný a bez rate limitu** (`http.rs:364`): neobmedzené
    vytváranie účtov, disk-fill, a nonce-flood (100k cap je globálny → DoS legitímnych
    requestov na 10 min). → `challenge_rl` bucket na `/account`+`/enroll`, nonce cap
    per-device, storage quota.
12. **sync — LWW metadáta mimo AEAD** (`store.rs:125-137`, `dto.rs:18`): malicious server
    vie prepísať `hlc_wall` (tombstone resurrection/rollback) alebo ticho dropnúť ops.
    → Klient viaže `op_id`/`hlc`/`collection_id` ako AEAD AAD + per-device op hash-chain
    (protokol v2, koordinácia s memento/probe).
13. **sync — žiadna device revocation** (`store.rs`, + `INSERT OR REPLACE` :219):
    ukradnutý device key platí navždy; key replacement je tichý. → Revoke/list endpoint,
    key-replacement ako logovaný event.
14. **CI — third-party actions pinned tagom, nie SHA** (všetky 3 workflows): release
    pipeline má `contents: write`. → SHA-pin + Dependabot.
15. **web — 5 dev-dep vulns (1 critical: vitest)**, prod deps čisté; duálne lockfiles
    (npm + pnpm). → Bump vite/vitest toolchain, nechať len pnpm-lock.

### LOW (výber)
- broker: `VAULT_AUDIT_OS_INSECURE_TLS` nie je dev-gated (`audit_ship.rs:65`); audit
  emisia fail-open (`audit.rs:293`); `/tmp` defaulty pre store/chain (`config.rs:151`);
  `VAULT_ALLOW_INSECURE_DEV` funguje aj s TLS configom (`auth.rs:156`); session rebind
  nechá starú session žiť (`http.rs:1283`); handshake bez timeoutu (`tls.rs:41`);
  multi-SAN mapping nedeterministický (`tls.rs:124`).
- console: pending-auth map bez capu (DoS); logout cez GET (CSRF); raw IdP error do
  browsera; cookie bez `__Host-` prefixu.
- sync: `db_key` optional → plaintext SQLite s verifierom (offline dictionary attack);
  žiadne per-vault quoty; chýba `deny_unknown_fields` + length caps; audit `read_to_string`
  na neohraničenom súbore.
- core lib: KDF params bez dolného floor-u (tampered sidecar vie pinúť 8 KiB/t=1 pre
  nové sloty — `kdf.rs:64`, `vault.rs:334`); nezeroizované intermediates v `recovery.rs`;
  symlink-follow pri temp zápisoch (`note_export.rs:216`, `meta.rs:151`).
- deny.toml: len advisories — chýba `[licenses]`, `[bans]`, `[sources]`.

### Silné stránky (potvrdené auditmi)
- Core lib: Argon2id 64 MiB/t=2, OsRng všade, LUKS-style envelope s AAD anti-slot-swap,
  dôsledná zeroizácia, `#![forbid(unsafe_code)]`, fail-closed `EncryptionUnavailable`.
- Broker: residency/tenant izolácia strict (lowercase UUIDv4, `is_safe_segment`),
  presign TTL ≤900s so scope v podpise, tamper-evident audit hash-chain, layered
  hardening (body cap, rate limity, sealed Argon2id store, žiadny network unseal).
- Console: PKCE S256 + state/nonce server-side, alg allow-list ∩ discovery, acr=mfa
  hard-enforced, private_key_jwt, SPA bez XSS sinkov, read-only by construction.
- Sync: per-request ed25519 `verify_strict` s test vektorom, replay window korektný,
  constant-time proof compare, SQLCipher at-rest option.
- Supply chain: 0 prod vulns (Rust aj npm), jednotný rustls stack, aktuálne krypto
  crates, žiadne committed secrets, žiadny `pull_request_target`/`curl|sh`.

---

## Fázový plán vylepšení

### Fáza 0 — Quick wins / CI hygiena (≈1 deň, žiadne API zmeny)
- Opraviť deny gate: odstrániť `rsa` dev-dep (alebo scoped ignore + komentár). [HIGH #2]
- SHA-pin GitHub Actions + Dependabot; bump vite/vitest; zrušiť duálny lockfile. [#14,#15]
- Dev-gate `VAULT_AUDIT_OS_INSECURE_TLS`; odmietnuť `VAULT_ALLOW_INSECURE_DEV` pri TLS
  configu; fail-to-boot bez explicitných store/chain paths v non-dev. [LOW]
- Console: header layer (CSP, nosniff, frame deny, no-store), logout→POST, `__Host-`
  cookie, generický 401. [#9 + LOW]

### Fáza 1 — Authz korektnosť (≈1 týždeň, **pred UAE rolloutom**)
- Console: viazať OIDC `state` na pre-auth cookie (login-CSRF fix); cap + rate-limit
  pending-auth mapy; rozdeliť/loopback-gate insecure-dev flag. [#8,#10 + LOW]
- Broker: ownership check na lease renew/revoke + session delete; KMS = cap AND JWT;
  SSH CA per-role principal allowlist + critical options. [#3,#4,#5]
- Broker: session rebind ukončí starú session; single-SAN enforcement. [LOW]

### Fáza 2 — Operačná odolnosť brokera (≈1–2 týždne)
- Perzistencia lease ledgeru v sealed store + boot reconciliation osirelých OpenSearch
  userov. [HIGH #1]
- CRL podpora alebo formálne krátkoživotné fleet certy (koordinácia s infra/identity —
  zápis do `coordination/conventions/secrets-broker.md`). [#6]
- Audit fail-closed pre issuance ops; handshake timeout + per-peer cap. [LOW]
- Rozhodnúť per-tenant OpenSearch role vs. accepted risk (zdokumentovať). [#7]

### Fáza 3 — vault-sync hardening (≈1–2 týždne, časť = protokol v2)
- Server-side hneď: rate-limit `/account`+`/enroll`, per-device nonce scoping, per-vault
  quoty, `db_key` povinný mimo dev, `deny_unknown_fields` + length caps. [#11 + LOW]
- Device revocation + list endpoint; key-replacement ako explicitný logovaný event. [#13]
- Protokol v2 (koordinácia memento/probe cez `coordination/`): AEAD-bind `op_id`/`hlc`/
  `collection_id`, per-device op hash-chain, audience/host v canonical stringu,
  `collection_id` HMAC → MUST v spec/sync-openapi.yaml. [#12 + INFO]

### Fáza 4 — Defense-in-depth long-tail (priebežne)
- Core lib: KDF param floor (≥19456 KiB, t≥2) + clamp pre nové sloty; zeroize
  intermediates v recovery; `create_new` pre temp súbory; `subtle::ConstantTimeEq`;
  voliteľný MAC sidecaru pod DEK.
- deny.toml: `[licenses]` allow-list, `[bans] multiple-versions`, `[sources]`.
- Audit reader streaming (`BufReader`); length caps na free-form audit Strings.

Po Fáze 1 a 2 aktualizovať `coordination/CONTRACTS.md` riadok + inbox notes pre
dotknuté služby (demon — lease persistence/ownership; identity — KMS cap; infra — CRL).

---

## Remediation status (2026-06-09) — všetkých 5 fáz IMPLEMENTOVANÝCH

Všetky fázy 0–4 dokončené v jednom prechode; lib + services testy zelené (broker 78,
console 26, sync 24, transport 22, lib 78), `cargo deny check` plne zelený, web build +
13 testov, prod aj dev npm audit čisté. Detaily v `CHANGELOG.md` (Unreleased).

**Vyriešené:** oba HIGH (broker boot-reconcile orphaned OS userov; deny gate), všetky
MEDIUM (lease/session ownership, KMS cap+JWT, SSH principal allowlist, login-CSRF binding,
console security headers + dev-flag gating, sync `/account` rate-limit + device revocation),
a väčšina LOW (dev-gate insecure flags, fail-to-boot bez ciest, audit fail-closed, handshake
timeout+cap, `deny_unknown_fields`+length caps, db_key gate, KDF floor, recovery zeroize,
create_new temp, deny.toml policy, audit streaming).

**Koordinačné (vyžadujú iné tímy, publikované do `coordination/`):**
- CRL vs short-lived fleet certs → `inbox/infra/vault-crl-or-short-lived-fleet-certs.md` (rozhodnutie infra).
- vault-sync protokol v2 (AEAD-bind LWW metadát, op hash-chain, audience v canonical stringu,
  `collection_id` HMAC MUST) → `inbox/sync/...` (vyžaduje memento/probe klient zmeny).
- Single-SAN issuance + ssh_principals + KMS cap → notes pre demon/infra + `conventions/secrets-broker.md`.

**Vedome odložené (INFO / nízka hodnota vs. riziko na neutrálnej lib):** `subtle::ConstantTimeEq`
(existujúci constant_time_eq je korektný, len bez optimization barrier; nepridávať dep do
neutrálnej lib), MAC sidecaru pod DEK (voliteľné), per-tenant OpenSearch role templaty
(accepted risk, zdokumentované), length caps na free-form audit Strings (redaction-by-construction).
