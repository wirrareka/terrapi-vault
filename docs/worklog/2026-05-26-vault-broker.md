# Súhrn práce — terrapi-vault broker (2026-05-26)

Z embedded SQLCipher knižnice + holého skeletonu na **funkčný sieťový secrets-broker** s
celým v1 API implementovaným a (kde existuje backend) integračne otestovaným. 15 commitov,
~7000 riadkov, všetko na `main` (`origin/main` @ `7a36230`). Build/clippy `-D warnings`/
testy zelené počas celej práce.

## Východiskový stav (ráno)
- `306e3cc` Phase 0: workspace `services/` (`vault-transport`, `vault-broker`, `vault-sync`),
  axum skeleton, session/lease engine, B3 audit typy. `creds`/`ssh` boli `501` stuby.
- Koordinácia: demon žiadal sieťový broker (Path A) — v1 OpenAPI ešte nezamknuté.

## Čo sme spravili (chronologicky, po témach)

### 1. Kontrakt / OpenAPI v1
- `d187eeb` **zamknuté v1 OpenAPI** (`spec/broker-openapi.yaml` v1.0.0) — reusable params/
  responses, `x-implementation-status`, `x-audit-action`, seal-status, 503-sealed.
- `70ba2ac` korekcia rolí podľa infra: `audit-writer` (write-only), **zrušený**
  `os-metrics-reader` (metriky = Prometheus, nie OpenSearch).
- `63308b6` implementovaný `GET /v1/sys/seal-status` + `ttl_secs` zladené so spec.

### 2. Phase 1b — daemon auth + bootstrap
- `8ae5647` **master-key unseal** (Argon2id cez lib, zeroizing `SecretBox`) → mutujúce ops
  `503` kým sa neunsealne; **CSPRNG** session/lease id.
- `b5ba998` lib: re-export `kdf::derive_key` (aditívne, MSRV 1.83 čisté).
- `6925131` **rustls mTLS-over-WG terminácia** — povinný klientsky cert verifikovaný voči
  fleet Root CA, peer SAN → rola (dev ponecháva header fallback).

### 3. Phase 2 — SSH-CA
- `c6a1863` unseal je teraz **store-backed** (otvára `terrapi_vault::Vesta` SQLCipher store
  pasfrázou); **ed25519 SSH CA** per group, generovaná + uložená v store, podpisuje OpenSSH
  certy. `GET ssh/ca` + `POST ssh/sign` (session-bound lease, host-cert bez tenanta, 409 bez
  session).

### 4. Phase 3 — dynamic creds + OpenSearch engine
- `b9ec8c6` **CredEngine framework**: trait, role→engine registry, lease→teardown (revoke /
  session-cascade zmaže backend usera), `creds` odstub-ovaný; `MockEngine` pre dev/testy.
- `4b9a8a7` **OpenSearch RBAC engine** (`audit-writer`): ephemeral user cez security REST
  API (rustls), zmazaný na revoke/expiry. **Integračne otestované cez Docker OpenSearch.**
  CredEngine prerobený na async (`async_trait`).

### 5. Expiry + audit
- `b3754a4` **lease/session TTL+idle expiry sweeper** — engine je time-aware (absolútne
  deadliny, injektovaný `now`), `sweep()` exspiruje sessions (hard/idle) + leasy; 30 s
  background task maže backend users exspirovaných creds. (Predtým leasy umierali len na
  explicitný revoke.)
- `a13dc4b` **B3 audit shipping** do group-local OpenSearch — durable local first,
  best-effort non-blocking bulk-index. Integračne otestované.
- `f6471cb` **tamper-evident hash-chained audit store** — každý záznam SHA-256 reťazený na
  predošlý; `verify()` deteguje úpravy/preskupenie/zmazanie; tip sa obnoví po reštarte.
- `9eb2e47` shipper **tailuje durable chain** cez perzistentný kurzor → **replay** pri
  zlyhaní/reštarte + **drain** pri shutdowne zadarmo (žiadny stratový in-memory kanál).

### 6. RethinkDB — zrušené
- `7a36230` `rethinkdb-admin` cred engine **úplne odstránený** zo spec/plánu/kódu — legacy
  RethinkDB, ktorý beží, **nepoužíva auth**, takže ho broker nikdy nebrokuje. Jediný cred
  engine = OpenSearch `audit-writer`.

## Koordinácia (proximiio-infra/coordination/, vlastní iný agent)
- Vesta inbox vyčistený; demon notifikovaný pri každom míľniku (v1 publish, ssh-ca live,
  creds live, RethinkDB drop).
- Vyriešené s demonom: **two-principal model** (`demon-operator` + `demon-system`) pre
  autonómne SSH sessions — zaznamenané v `decisions/demon-vault-session-model.md`.
- Korekcie kontraktu: audit-writer rola, drop metrics-reader, RethinkDB legacy→drop.

## Pamäť
- `rethinkdb-legacy-only` — RethinkDB sa nebrokuje (legacy, bez auth).

## Aktuálny stav
Core broker je **kompletný**: mTLS-over-WG · unseal + at-rest store · SSH-CA · OpenSearch
creds · session-bound leasy + expiry sweeper · hash-chained audit + OpenSearch shipping
(replay/drain). Všetky v1 OpenAPI ops implementované a vynútené.

## Čo zostáva (nie blokujúce)
- `vault-sync` (Svet B — osobný E2E sync pre memento/probe) — zatiaľ len skeleton.
- Broker hardening podľa potreby: rate-limity, metriky/observability, ďalšie CredEngine
  adaptéry ak nejaký *moderný* datastore bude potrebovať brokované creds.
