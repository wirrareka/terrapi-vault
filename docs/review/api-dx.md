# vault-broker / vault-sync — API & wire-DX review

Scope: developer experience of consuming the two HTTP contracts. There is no GUI;
"UX" here = how hard it is for a client dev (demon/aether on broker; memento/probe on
sync) to integrate correctly without reading the Rust. Citations are `file:line`.

Both services already share a flat `{error, detail}` body with a stable, machine-readable
`error` code — that is a strong baseline. Findings below are ranked by impact.

---

## High

### H1 — Sync error catalog is in the code, not the contract
**Location:** `services/vault-sync/src/http.rs:66-196` vs `spec/sync-openapi.yaml:67-70,90-180`.
The implementation distinguishes ~10 stable codes (`missing_device`, `bad_ts`,
`missing_nonce`, `bad_sig`, `stale_request`, `bad_signature`, `replay`, `unknown_device`,
`no_account`, `bad_proof`, `bad_body`, `store_error`). The spec's `ErrorBody`
(`spec/sync-openapi.yaml:67`) only says `{error, detail}` with no enum and no per-response
examples — every `401` is documented as the prose "unauthenticated". A client dev **cannot**
tell from the spec that 401 splits into bad-sig vs unknown-device vs replay vs stale, even
though the code already returns those discretely. This is the single biggest DX gap: the
distinctions exist on the wire but are invisible in the contract.

**Improvement:** make `error` an `enum` in the schema and attach examples per status.

```yaml
ErrorBody:
  type: object
  required: [error, detail]
  properties:
    error:
      type: string
      enum: [missing_device, bad_ts, missing_nonce, bad_sig, stale_request,
             bad_signature, replay, unknown_device, no_account, account_exists,
             bad_proof, device_mismatch, bad_body, store_error]
      description: stable machine-readable code; switch on this, not on `detail`.
    detail: { type: string, description: human-readable; may change, do not parse }
# and on each 401:
'401':
  description: unauthenticated
  content:
    application/json:
      schema: { $ref: '#/components/schemas/ErrorBody' }
      examples:
        bad_signature: { value: { error: bad_signature, detail: "request signature did not verify" } }
        unknown_device: { value: { error: unknown_device, detail: "device is not enrolled" } }
        replay:         { value: { error: replay, detail: "this (device, nonce) was already used" } }
        stale_request:  { value: { error: stale_request, detail: "X-Sync-Ts outside the accepted clock-skew window" } }
```

### H2 — The ed25519 signing scheme is under-specified for a non-Rust implementer
**Location:** `spec/sync-openapi.yaml:16-19` (a comment), canonical string defined in
`services/vault-sync/src/auth.rs:45`.
The canonical string `v1\n{METHOD}\n{path?query}\n{vault_id}\n{ts}\n{nonce}\n{sha256_hex(body)}`
lives only in a YAML **comment** (not a rendered schema/description), and the precise rules a
client must replicate are scattered or implicit:
- `METHOD` casing (the code uses `method.as_str()` → upper-case `GET`/`POST`).
- `path?query` is the **exact** raw `path_and_query` (`http.rs:198`) — so `since`/`limit`
  ordering and presence are signed; a client that re-orders query params breaks the sig.
- body hash for GET/empty-body calls = `sha256_hex(b"")` (spec only says "sign over an empty
  body" at `:146,163,177` — it never states it is still hashed, not omitted).
- `ts` is unix **seconds**; skew window is `MAX_SKEW_SECS` (`auth.rs`) — the numeric value is
  not published, so a client cannot size its retry/clock-sync behaviour.
- nonce uniqueness scope = `(device_id, nonce)` (`auth.rs:113`), and the replay store has a
  retention window — neither the scope nor the window is in the spec.
- signature encoding = **standard** base64 of 64 raw bytes (not base64url) — easy to get wrong.

**Improvement:** add a dedicated `## Request signing` section to `docs/sync-bootstrap.md`
with the exact byte recipe, a worked example (fixed key + request → expected base64 sig as a
test vector), the MAX_SKEW value, the nonce scope/retention, and an explicit "GET/empty body
is still hashed as SHA-256 of zero bytes" note. A test vector is the highest-leverage single
addition — it lets a client self-verify in any language.

### H3 — WS `/tail` frame shapes are not in the contract
**Location:** `spec/sync-openapi.yaml:171-180`; impl `services/vault-sync/src/http.rs:478-503`.
The spec's `/tail` only documents `101`/`401`. The actual wire protocol after upgrade is:
each new op is sent as a **text frame containing a JSON `StoredOp`** (`http.rs:494`), and a
lagged subscriber gets the literal text frame `{"resync":true}` (`http.rs:499`). None of that
— frame type (text vs binary), the StoredOp payload, the resync sentinel, or that the client
should respond by doing a full `pull` — is machine-readable. A client dev must read Rust to
build the consumer.

**Improvement:** document the two frame variants as a `oneOf` and describe the resync
contract in the description:

```yaml
# in description of /tail:
# After 101, the server sends UTF-8 text frames, each one of:
#   - a StoredOp object (a newly-appended op), OR
#   - {"resync": true}  — the subscriber lagged; drop the stream and do a full /pull,
#     then you MAY re-open /tail. Ops are NOT replayed on the socket.
# The client sends nothing except WebSocket control frames; a Close ends the stream.
components:
  schemas:
    TailFrame:
      oneOf:
        - { $ref: '#/components/schemas/StoredOp' }
        - { type: object, required: [resync], properties: { resync: { const: true } } }
```

---

## Med

### M1 — `push` response (`accepted`/`duplicates`/`latest_seq`) lacks idempotency narrative
**Location:** `spec/sync-openapi.yaml:124,137-139`; impl `dto.rs:88-93`, `http.rs:364-381`.
The summary says "Idempotent on op_id" and the response carries `accepted`+`duplicates`, which
is good. But the response fields are untyped beyond `integer` and there is no statement of the
**guarantee**: that re-sending the same `op_id` is safe (same final state, counted in
`duplicates`), that a partial batch can have both accepted and duplicate ops, and what
`latest_seq` means relative to *this* device's view (it is the vesta high-water after the
push). Clients building at-least-once push need that contract spelled out, plus a `403`
example for the `device_mismatch` case (`http.rs:371`, currently prose at `:141`).

**Improvement:** add a `PushResponse` schema with field descriptions and an idempotency note
in the operation description: "Re-submitting an op with an `op_id` already stored is a no-op,
returned in `duplicates`; you may safely retry a whole batch. `latest_seq` is the vesta's
server cursor after this call — use it to advance your local pull cursor."

### M2 — No request-id / correlation id on either service
**Location:** both `http.rs`; neither emits or echoes an `X-Request-Id`.
The broker emits B3 audit events server-side (`http.rs:4`) but the client gets no correlation
handle, so a failed call can't be tied to a server log line during support. For a
secrets/sync boundary this materially slows debugging.

**Improvement:** generate a request id per call, echo it in an `X-Request-Id` response header
(and into the audit B3 / log line), and add it to `ErrorBody` as optional `request_id`.
Document it once in both specs. Cheap, and it makes every other error far more actionable.

### M3 — Pagination contract (`since`/`limit`) is incomplete
**Location:** `spec/sync-openapi.yaml:148-149`, `pull` impl `http.rs`.
`since` defaults to 0 (good) but `limit` has **no default and no documented maximum**, and the
response (`:158`) returns `ops` + `latest_seq` with no `has_more`/`next_since` cursor. A client
can't tell "is this page full?" without comparing `limit` to `ops.length` and re-deriving the
next cursor from `max(seq)`. That works but is implicit.

**Improvement:** document `limit`'s server default and hard cap, state that the next cursor is
`max(ops[].seq)` (or echo `next_since`), and note that `ops` is ordered by ascending `seq` so
clients can rely on it for cursor advancement. If `latest_seq > max(ops.seq)`, more pages
remain — say so explicitly.

### M4 — Broker error codes also live only in code; spec lists them by example only
**Location:** `spec/broker-openapi.yaml:97-102`; impl codes at `http.rs:51,193,205,...`.
The broker spec's `Error.error` is a free `string` with "e.g. group_mismatch, sealed,
not_renewable" — but the impl has a much larger, stable set (`group_mismatch`, `forbidden`,
`sealed`, `host_cert_tenant`, `bad_tenant_id`, `no_active_session`, `unknown_role`,
`backend_error`, `bad_key_id`, `unwrap_failed`, `no_such_session`, `renew_failed`,
`revoke_failed`, `snapshot_failed`, `store_error`, `bad_dek`, `bad_wrapped`, `sign_failed`).
Same gap as H1: the codes are stable and switchable but the contract under-documents them, so
clients hardcode strings scraped from prose.

**Improvement:** promote `Error.error` to an `enum` mirroring the impl set, and tie specific
codes to the statuses where they appear (e.g. `403 forbidden` = capability denied,
`404 group_mismatch` = residency air-gap, `409 no_active_session`). This also future-proofs:
adding a code becomes a visible contract change.

---

## Low

### L1 — Cross-service shape consistency: align the two `ErrorBody`s explicitly
Both are `{error, detail}` (`broker dto.rs:6`, `sync dto.rs ErrorBody`) — good, but it is
coincidental, not contractual. A client lib that talks to both would benefit from one
documented shape. **Improvement:** state in both specs "error envelope is identical across
vesta services: `{error, detail[, request_id]}`" so a shared client error type is sanctioned.

### L2 — Wire naming is consistently snake_case — keep it, and say so
All wire fields are snake_case (`op_id`, `latest_seq`, `vault_id`, `lease_id`, `kek_id`);
headers are `X-Sync-*` / `X-Device-Id`. This is internally consistent. **Improvement:** add a
one-line "conventions" note to each spec (snake_case JSON bodies; `X-Sync-*` signing headers;
all paths `/v1/...`) so future endpoints don't drift to camelCase.

### L3 — No machine-readable version endpoint on sync; broker's is a stub
Broker has `/v1/sys/seal-status` carrying `version` (nullable, `broker-openapi.yaml:266`) and
`/healthz`. Sync has only `/healthz` returning `"ok"` (`sync-openapi.yaml:73`, `http.rs:48`)
and no version surface. **Improvement:** make `/healthz` return JSON `{status:"ok", version}`
on both (or add a tiny `/v1/version`), so clients can assert compatibility and so the seal
`version` isn't the only way to read the broker build.

### L4 — Enrolment flow is clear but the failure modes aren't enumerated
`docs/sync-bootstrap.md:42-52` has a clean endpoint table and the account→enroll-challenge→
enroll order is obvious. What's missing for "hard to misuse": what happens if two devices race
`/account` (one gets `409 account_exists` — code present at `http.rs:257` but not in the doc),
and that `/enroll-challenge` is intentionally unauthenticated because salt+params are
non-secret (stated in the table but worth a one-line "why" so an implementer doesn't add auth
and break new-device bootstrap). **Improvement:** add a 4-line "failure modes" subsection and
a tiny sequence diagram (account → challenge → enroll → push/pull) to the bootstrap doc.

---

## Top 5 (do these first)

1. **H1 / M4 — Publish the error-code enums in both specs** with per-status examples. The
   codes already exist and are stable in code; surfacing them is the highest-value, lowest-risk
   DX win and lets clients write `switch(error)` confidently.
2. **H2 — Fully specify the ed25519 signing scheme in `docs/sync-bootstrap.md`, with a test
   vector.** Move it out of a YAML comment; publish MAX_SKEW, nonce scope/retention, base64
   variant, and the "empty body is still SHA-256 hashed" rule. A worked vector lets any-language
   clients self-verify.
3. **H3 — Specify the `/tail` WebSocket frames** (`StoredOp` text frame vs `{"resync":true}`
   sentinel) as a `oneOf` plus a "lagged → full pull, no replay" narrative.
4. **M2 — Add `X-Request-Id`** (echoed header + audit/log + optional `ErrorBody.request_id`)
   across both services. Makes every error actionable in support.
5. **M3 / M1 — Finish the pagination + idempotency contracts**: document `limit` default/cap,
   the ascending-`seq` ordering and next-cursor derivation, and the push idempotency guarantee
   (safe full-batch retry; `duplicates` semantics; `latest_seq` meaning).
