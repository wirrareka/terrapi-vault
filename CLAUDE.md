# terrapi-vesta — Claude Code notes

Secrets / (future) KMS service for the quanto / proximi.io stack.

## Cross-service coordination (quanto / proximi.io stack)

This service integrates tightly with 4 siblings (identity / vault / kalista /
vulture / infra). Coordinate via **files**, not by relaying messages through the
human. The shared coordination dir is (temporarily) at:
`/Users/wired/proximi-admin/proximiio-infra/coordination/` (will move to a neutral
`quanto/contracts` repo later).

- **On start, check your inbox** `…/coordination/inbox/vault/` and resolve/ack
  each note (answer inline + flip `Status:`, or move a durable agreement to
  `…/coordination/decisions/`). Then delete/mark the handled note.
- **Read** `…/coordination/CONTRACTS.md` (where each service's LIVE contract is) and
  `…/coordination/conventions/` (shared agreements: jwt-claims, audit-event-schema,
  residency, ports-env).
- **When you change a boundary** (a JWT claim, route, port, header, endpoint, etc.):
  commit it to `…/coordination/` (update CONTRACTS.md / the relevant conventions
  file) AND drop a note in the affected service's inbox — don't only say it.
- **Never** put secrets or per-tenant data in `coordination/`. Contracts only.

### Your role in the circle (what vault OWNS)

You are the stack's **secrets boundary**. As of 2026-05-26 you are registered in
`CONTRACTS.md` as owner of the **"Secrets broker"** contract — now **COMMITTED
(Path A, phased)**. terrapi-vesta is today an embedded SQLCipher at-rest library and is
growing into a network secrets broker; the control-plane daemon **proximiio.demon** is
your first consumer (`inbox/vault/demon-{needs-brokering-service,brokered-creds-shape}.md`,
both answered). Plan: `docs/planning/01-vault-as-service.md`.

You own — and must publish to `coordination/` + this repo — this boundary
(see `conventions/secrets-broker.md`):
- **Daemon auth** = mTLS over WireGuard vs the fleet Root CA (SAN → role).
- **Short-TTL issuance**: SSH signed-cert CA + leased service-admin creds (OpenSearch
  RBAC / DB) — publish method + path + req/resp in the broker OpenAPI under `spec/`.
- **Lease model**: TTL / renew / revoke + session-bound child-lease cascade.
- **Object-store presign**: SigV4 presigned-URL signer for DO Spaces — `object-store` cap
  (PUT, publish) + `object-store-read` cap (GET, serve); stateless, per-tenant/single-object
  scoping in the signature, the Spaces key never leaves the broker.
- **Observe API**: read-only operator plane (`observe` cap) — `GET /v1/sys|{group}/observe/*`;
  state only (leases/sessions/roles/ssh/kms/object-store/audit), never secret values.
- **Namespace / residency**: per-group instance + `<group>/<tenant_id UUIDv4>/<role>`;
  a cred must not resolve another tenant/region. Honour `conventions/residency.md`
  (EU/UAE physical air-gap — one broker per group).
- **Audit**: emit canonical B3 (`source:"vault"`) to group-local OpenSearch; consumers
  do not double-record. Redact at emitter.

Services, one workspace (do not merge their data models):
- **vesta-broker** — the above (fleet creds), per residency group, port `8200`.
- **vesta-sync** — personal multi-device sync for memento/probe: E2E/server-blind,
  device-keypair auth, row-level oplog (CRDT/LWW). Not multi-tenant; not under the
  residency air-gap as scoped today (revisit if it ever serves tenant data).
- **vesta-console** — operator web/API console, one per group, port `8203`; read-only,
  aggregates the group's brokers' `observe` API over mTLS; React SPA in `web/`. Never
  surfaces a secret value. Plan: `docs/planning/02-vesta-console.md`.
- **vesta-transport** — shared transport/audit types for the services (no data model of its own).

Rules specific to you:
- Source of truth = spec/OpenAPI in this repo; `CONTRACTS.md` only points at it. When a
  boundary changes, update the `CONTRACTS.md` row + `conventions/{ports-env,secrets-broker}.md`.
- The lib crate stays at the repo **root** (memento/probe pin `../terrapi-vault`); the
  services are workspace members — never break that path dependency.
- `residency_group` is a per-instance constant. Minimise long-lived secrets: issue
  short-TTL revocable leased creds over static ones.

# context-mode — MANDATORY routing rules

You have context-mode MCP tools available. These rules are NOT optional — they protect your context window from flooding. A single unrouted command can dump 56 KB into context and waste the entire session.

## BLOCKED commands — do NOT attempt these

### curl / wget — BLOCKED
Any Bash command containing `curl` or `wget` is intercepted and replaced with an error message. Do NOT retry.
Instead use:
- `ctx_fetch_and_index(url, source)` to fetch and index web pages
- `ctx_execute(language: "javascript", code: "const r = await fetch(...)")` to run HTTP calls in sandbox

### Inline HTTP — BLOCKED
Any Bash command containing `fetch('http`, `requests.get(`, `requests.post(`, `http.get(`, or `http.request(` is intercepted and replaced with an error message. Do NOT retry with Bash.
Instead use:
- `ctx_execute(language, code)` to run HTTP calls in sandbox — only stdout enters context

### WebFetch — BLOCKED
WebFetch calls are denied entirely. The URL is extracted and you are told to use `ctx_fetch_and_index` instead.
Instead use:
- `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` to query the indexed content

## REDIRECTED tools — use sandbox equivalents

### Bash (>20 lines output)
Bash is ONLY for: `git`, `mkdir`, `rm`, `mv`, `cd`, `ls`, `npm install`, `pip install`, and other short-output commands.
For everything else, use:
- `ctx_batch_execute(commands, queries)` — run multiple commands + search in ONE call
- `ctx_execute(language: "shell", code: "...")` — run in sandbox, only stdout enters context

### Read (for analysis)
If you are reading a file to **Edit** it → Read is correct (Edit needs content in context).
If you are reading to **analyze, explore, or summarize** → use `ctx_execute_file(path, language, code)` instead. Only your printed summary enters context. The raw file content stays in the sandbox.

### Grep (large results)
Grep results can flood context. Use `ctx_execute(language: "shell", code: "grep ...")` to run searches in sandbox. Only your printed summary enters context.

## Tool selection hierarchy

1. **GATHER**: `ctx_batch_execute(commands, queries)` — Primary tool. Runs all commands, auto-indexes output, returns search results. ONE call replaces 30+ individual calls.
2. **FOLLOW-UP**: `ctx_search(queries: ["q1", "q2", ...])` — Query indexed content. Pass ALL questions as array in ONE call.
3. **PROCESSING**: `ctx_execute(language, code)` | `ctx_execute_file(path, language, code)` — Sandbox execution. Only stdout enters context.
4. **WEB**: `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` — Fetch, chunk, index, query. Raw HTML never enters context.
5. **INDEX**: `ctx_index(content, source)` — Store content in FTS5 knowledge base for later search.

## Subagent routing

When spawning subagents (Agent/Task tool), the routing block is automatically injected into their prompt. Bash-type subagents are upgraded to general-purpose so they have access to MCP tools. You do NOT need to manually instruct subagents about context-mode.

## Output constraints

- Keep responses under 500 words.
- Write artifacts (code, configs, PRDs) to FILES — never return them as inline text. Return only: file path + 1-line description.
- When indexing content, use descriptive source labels so others can `ctx_search(source: "label")` later.

## ctx commands

| Command | Action |
|---------|--------|
| `ctx stats` | Call the `ctx_stats` MCP tool and display the full output verbatim |
| `ctx doctor` | Call the `ctx_doctor` MCP tool, run the returned shell command, display as checklist |
| `ctx upgrade` | Call the `ctx_upgrade` MCP tool, run the returned shell command, display as checklist |
