# Vault — website presentation brief (for the web designer)

A brief for building the **Vault** showcase/landing section on the Terrapi website. Everything here
is grounded in the actual product/tech (the `terrapi-vault` at-rest library + the `vault-broker`
secrets broker + `vault-console`). **Do not invent security claims, audits, or compliance
certifications** — the wording below is what we can stand behind today. Flag anything you'd like
reworded; marketing owns final copy, this is the accurate substrate.

Note the audience is different from Memento's: Vault speaks to **platform / DevOps / security
engineers**, not consumers. Tone is technical, calm, infrastructure-grade — trust through
architecture, not adjectives.

---

## 1. What Vault is (the one-liner)

> **Terrapi Vault — the secrets boundary for your fleet. Short-lived credentials, hard data
> residency, an operator console that never shows a secret.**

Vault is a self-hostable **secrets broker**: services authenticate to it over mutual TLS and ask for
**short-TTL, revocable credentials** (SSH certificates, database / search-engine logins, signed
object-store URLs, KMS wrap/unwrap) instead of holding long-lived static secrets. It runs **one
instance per data-residency region**, so a credential can never resolve another region's data.

**Audience:** engineering teams that need a secrets layer they can run themselves, with real
regional isolation and a small, auditable trust boundary — not a black box and not "trust us."

---

## 2. Core message & pillars

Lead with **least privilege by construction**. Five pillars (pick 3–4 for the hero, the rest for a
"how it works" strip):

1. **Short-lived, not static.** Services lease credentials with a TTL; leases renew, revoke, and
   cascade (revoke a session and its child leases die with it). The goal is to minimise long-lived
   secrets, not to store more of them.
2. **Hard data residency.** One broker per region (e.g. EU and UAE run physically separated). The
   namespace is `<group>/<tenant>/<role>` — a credential is scoped so it cannot reach another
   tenant or region.
3. **Identity is the certificate.** Clients authenticate with mutual TLS over a private WireGuard
   network; the certificate's identity (its SAN) maps to a role and a set of capabilities. No
   shared API tokens floating around.
4. **The operator console never shows a secret.** The web console is **read-only observability** —
   it shows *state* (active leases, sessions, certificate serials, key inventory, audit trail),
   never a secret value. Operator login is OIDC with MFA required.
5. **Open & documented.** REST contracts are published as OpenAPI; the encrypted at-rest format is
   documented precisely enough for an independent compatible reader. Open-source core.

---

## 3. Feature highlights (all factual — safe to put on the page)

| Capability | One-line copy | Detail (tooltips / "learn more") |
|---|---|---|
| Leased credentials | "Credentials that expire by default." | TTL-bounded, renewable, revocable leases for service-admin logins (search-engine RBAC, databases); session-bound child leases cascade-revoke. |
| SSH certificate CA | "Sign SSH access, don't distribute keys." | Short-TTL OpenSSH signed certificates from a broker-held CA + a revocation list — no long-lived `authorized_keys` sprawl. |
| KMS (envelope encryption) | "Wrap data keys with a key that never leaves the broker." | Wrap / unwrap / rotate of data-encryption keys (XChaCha20-Poly1305); the key-encryption key stays in the broker. |
| Object-store presigning | "Time-boxed, single-object upload/download URLs." | The broker signs short-TTL, single-object presigned URLs (SigV4); the storage key never leaves the broker, and read vs write are separate capabilities. |
| mTLS over WireGuard | "Authenticate with a certificate, not a token." | Mutual TLS terminated over a private WireGuard mesh; the peer certificate's identity maps to a role → capabilities. |
| Per-region isolation | "One broker per region. No cross-region reach." | Separate instance per residency group; a credential is scoped to `<group>/<tenant>/<role>` and cannot resolve another region/tenant. |
| Read-only operator console | "See the state, never the secret." | Aggregates each region's brokers into a read-only web view: leases, sessions, SSH serials + revocations, key inventory, audit tail. OIDC + MFA login. |
| Tamper-evident audit | "Every issuance is on a hash-chained record." | Hash-chained audit events, redacted at the source (no secret values in the log), shipped to the region-local store. |
| Encrypted at rest | "The broker's own state is encrypted at rest." | Built on the `terrapi-vault` library: SQLCipher + Argon2id (RFC 9106) key derivation; the 256-bit key is held in memory only and zeroized on lock. |

---

## 4. Suggested page structure (sections)

1. **Hero** — the one-liner + a single tight diagram: *service → (mTLS/WireGuard) → Vault → short-TTL
   credential*, with a clock/expiry motif. One primary CTA (e.g. "Read the architecture" / "View the
   API contract").
2. **The problem** — long-lived secrets sprawl (API keys in env files, shared SSH keys, static DB
   passwords). One honest sentence each. Sets up the "expire by default" answer.
3. **How it works** — the 4–5 pillars as a horizontal strip with small icons.
4. **Capabilities grid** — the table in §3 as cards (icon + one-liner + a "learn more" expander).
5. **Data residency** — a two-region map/diagram (EU / UAE as separated columns, no line between
   them) — the strongest visual differentiator. Caption: "Separate brokers. No cross-region path."
6. **The operator console** — a screenshot/mock of the read-only console; caption leans on "shows
   state, never a secret value."
7. **Open & verifiable** — links to the OpenAPI contracts + the documented on-disk format +
   open-source repo. Credibility, not marketing.
8. **Footer CTA** — for the technical reader: repo, contracts, docs.

---

## 5. Tone & visual direction

- **Infrastructure-grade, calm, precise.** This is a security product — restraint reads as
  competence. Avoid hype words ("military-grade", "unhackable", "bank-level").
- **Palette:** cooler and more technical than Memento — deep slate/ink, a single confident accent,
  generous whitespace. Monospace for any keys/identifiers/code.
- **Motifs:** expiry/clock (short-TTL), a boundary/membrane (the "secrets boundary"), separated
  regions (residency), a certificate/key glyph. Keep diagrams schematic, not skeuomorphic.
- **Imagery:** prefer clean architecture diagrams over stock photos. If photos are used, lean
  data-center / network, not "hacker in a hoodie."

---

## 6. Honest constraints (so copy stays accurate — important)

- **Do not claim third-party audits or compliance certifications** (SOC 2, ISO, HIPAA, PCI, etc.) —
  none are claimed today. You *can* say the design follows least-privilege and data-residency
  principles and that contracts/formats are open.
- **"Self-hostable / open-source core" yes; "buy it today as a managed product" — only if marketing
  confirms** the go-to-market. Vault currently ships as part of the Terrapi/proximi.io stack; how it
  is offered externally is a marketing decision. Don't imply a pricing/SLA that doesn't exist.
- **Enterprise PKI (license-gated short-lived certificate issuance)** is on the roadmap / phased —
  describe as "coming" rather than shipped, unless told otherwise.
- **Don't over-promise revocation of presigned URLs:** a presigned object-store URL can't be
  revoked; its short TTL is the bound. (Fine to say "time-boxed," not "revocable," for that one.)
- Keep credential examples generic (SSH, database, search-engine, object store). Don't name specific
  internal services/tenants.
- Every number must be real: Argon2id is RFC 9106; the at-rest key is 256-bit and zeroized on lock.
  Don't invent throughput/latency figures.

---

## 7. Ready-to-use copy snippets (all grounded)

- Hero sub: *"Services ask Vault for a credential that expires. No static keys to leak, rotate by
  hand, or forget about."*
- Pillar: *"Identity is the certificate. Clients authenticate with mutual TLS over a private
  network; the cert maps to a role and exactly the capabilities that role is allowed."*
- Residency: *"Run one Vault per region. EU stays in EU, UAE stays in UAE — a credential issued in
  one region cannot reach another."*
- Console: *"The operator console shows you the state of the system — active leases, sessions,
  certificate serials, the audit trail — and never a secret value."*
- Audit: *"Every credential issued lands on a tamper-evident, hash-chained audit record, redacted at
  the source."*
- Closing/technical: *"Open contracts, a documented on-disk format, an open-source core. Verify it,
  don't take our word for it."*

---

## 8. Credibility links (for the technical reader / footer)

- Repo: `terrapi-vault` (open-source core + services).
- Broker API contract: `spec/broker-openapi.yaml` (OpenAPI).
- Sync API contract: `spec/sync-openapi.yaml` (the server-blind personal-sync sibling).
- At-rest format spec: `spec/vault-format.md` (documented precisely enough for an independent
  compatible reader).
- License: MIT OR Apache-2.0.

*(Replace the bare names with public URLs once the designer knows the final docs/site paths.)*
