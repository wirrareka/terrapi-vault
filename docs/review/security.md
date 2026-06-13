# terrapi-vault — Security review

_Defensive review of the team's own code. Crypto core is solid: Argon2id (RFC 9106),
ed25519 `verify_strict`, constant-time enrol-proof compare, AES-256-GCM envelope wrap,
raw-key SQLCipher path, redaction-by-construction audit type. Findings are at the edges._

## Findings (prioritized)

### High

**S1. vault-sync `enroll-challenge` is an unauthenticated oracle** — `services/vault-sync/src/http.rs:205-224`.
`GET /v1/sync/{vault_id}/enroll-challenge` needs no signature and returns the enrolment
`salt` + Argon2 `params` for any `vault_id`. Risk: account-existence oracle (200 vs 404)
plus handing an attacker the exact salt/params to mount an offline dictionary attack on the
enrolment passphrase — the only gate on enrolling a new device (`http.rs:289`).
**Fix:** uniform timed response on miss (no existence leak), hard per-IP rate-limit, ideally
require an out-of-band pairing token.

**S2. vault-sync never validates `vault_id`; unbounded memory growth (DoS)** —
`http.rs` (all handlers take `Path<String>` unchecked), `store.rs:85`, `state.rs:23/39`,
`auth.rs:104-122`. Unlike the broker (`is_uuid_v4_lower`, `http.rs:88`), sync accepts any
`vault_id`. `create_account` is gated only by self-signature (S3), so attackers create
unlimited accounts; the `tails` map and `ReplayGuard.seen` grow with attacker-chosen keys
(`seen` only prunes opportunistically, keeps every nonce within 300 s).
**Fix:** validate `vault_id` at the extractor; size-cap and evict `ReplayGuard.seen` + `tails`.

### Med

**S3. Self-signed account/enrol = TOFU with no binding to the human** —
`http.rs:226-262`, `316-355`. The first device is accepted on a self-signature over a key
chosen in the same request; only `enroll` (not `account`) is proof-gated, so vesta ownership
is first-come-first-served. **Fix:** gate `create_account` on the enrolment proof too.

**S4. Broker dev-bypass grants ALL caps to any unmapped SAN via a plaintext header** —
`services/vault-broker/src/auth.rs:112-143`. With `VAULT_ALLOW_INSECURE_DEV=1`, an unmapped
`X-Client-Cert-SAN` header yields a `dev` principal with `Capability::all()`. Single env var
→ total authz bypass if it leaks to staging. **Fix:** refuse to start when set with TLS /
non-loopback bind; prefer a separate dev binary.

**S5. OpenSearch engine can disable TLS verification; backend error bodies echoed to caller** —
`opensearch.rs:44-49,93-96,116-119`, surfaced at `http.rs:520`. `VAULT_OS_INSECURE_TLS=1`
disables verification on the link carrying the privileged admin password (MITM → credential
capture); raw backend error text is returned to clients. **Fix:** dev-only guard; map backend
errors to a generic client message, log detail locally.

**S6. KMS uses a 96-bit random nonce under a long-lived, manually-rotated KEK** —
`kms.rs:178-185,49-55`. Random GCM nonces are safe to ~2^32 wraps/key before collision risk
(nonce reuse is catastrophic for GCM); no wrap counter or auto-rotation. Latent for aether
volumes. **Fix:** per-KEK wrap counter with auto-rotate, or AES-GCM-SIV / XChaCha20-Poly1305.

**S7. Per-principal rate-limit bucket map is never evicted** —
`hardening.rs:30,51-68,94-102`. Bounded in prod (registered SANs) but in dev the key is the
attacker-controlled header → unbounded growth, and each new value gets a fresh full burst
(throttle bypass). **Fix:** LRU/TTL eviction; collapse header identities to one bucket in dev.

### Low

**S8. ReplayGuard boundary** — `auth.rs:112-121` vs skew `http.rs:113`: prune (`<=`) and
accept (`<=`) windows are equal, so a nonce can be pruned while a same-`ts` replay still passes
within a 1 s edge. **Fix:** prune with a strictly larger window than accept.

**S9. vault-sync metadata exposure** — `store.rs:264-280`, `dto.rs:19`. Content is genuinely
server-blind (vesta key never reaches the server; `encrypted_payload` never decrypted), but the
server sees op/device counts, cleartext `collection_id` (blinding is only a MAY), HLC
wall-clock, and op sizes. **Fix:** document in the threat model; consider mandatory HMAC
`collection_id` + size padding.

**S10. `rotate_key` compares derived keys with `!=`** — `src/vault.rs:185`: non-constant-time
key-material compare (local-process, mostly theoretical). **Fix:** `subtle::ConstantTimeEq`.

**S11. `store_snapshot` echoes absolute host paths** — `http.rs:381-463` (snapshot itself is
encrypted + capability-gated). **Fix:** return an opaque handle.

## Verified correct
Argon2id params + raw-key SQLCipher + zeroization/no-leak `Debug`; `verify_strict`;
constant-time enrol-proof; versioned newline-framed canonical sign string; KMS fail-closed;
residency `Group` extractor runs before body parse; tenant UUID enforcement +
`(group,tenant,key_id)` scoping; lease/session cascade revoke + backend teardown +
SSH-serial revocation + orphan-lease cleanup on sign failure; hash-chained tamper-evident
audit that advances only after durable append; route-template metrics (no tenant leak);
required-and-verified mTLS with SAN→role `403` on unregistered SANs.

## Top 5 fixes
1. Validate `vault_id` + bound sync in-memory state (S2).
2. Harden `enroll-challenge` against enumeration / offline-material leak (S1).
3. Fence the dev bypass + insecure-TLS footguns (S4, S5).
4. Gate `create_account` on the enrolment proof (S3).
5. KMS wrap-count rotation + evict rate-limit buckets (S6, S7).
