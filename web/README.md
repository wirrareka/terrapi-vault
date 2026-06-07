# vault-console (web)

Operator web console for terrapi-vault — **read-only observability**, one per residency group.
Mirrors the Kalista web/API standard. **Never a secret editor** (state only; secret ingest stays
CLI). Plan: `../docs/planning/02-vault-console.md`.

> **Status: P1 SPA skeleton.** Builds against the console backend's `/api/v1/*` (the
> `services/vault-console` crate — not yet built; pending the identity OIDC client. infra side
> confirmed: port `:8203`, WG `10.200.0.110`, dual-EKU cert, optional Kalista edge). The backend
> aggregates the group's brokers' read-only `observe` API (broker OpenAPI ≥ 1.4.0) over mTLS.

## Stack
React 18 · TypeScript · Vite · Tailwind + shadcn/ui (New York) · TanStack Query · react-router-dom
· lucide-react · date-fns. EN-only. Dark by default.

## Develop
Requires **Node 24** (`.nvmrc`; `nvm use`). pnpm is the package manager.
```bash
pnpm install
pnpm dev          # Vite on :5273, proxies /api → http://127.0.0.1:8203 (override VITE_API_PROXY)
VITE_MOCK=1 pnpm dev   # standalone demo — fixture data from src/lib/mock.ts, no backend needed
pnpm typecheck
pnpm build        # → dist/  (embedded into the vault-console binary via rust-embed)
pnpm gen:api      # regenerate raw broker types from ../spec/broker-openapi.yaml
```

## Layout
- `src/lib/types.ts` — console API contract (broker observe DTOs + per-broker `broker` tag).
- `src/lib/api.ts` — fetch wrapper (cookie session; 401 → `/api/v1/auth/login`).
- `src/hooks/use-observe.ts` — TanStack Query hooks per observe view.
- `src/components/` — `ui.tsx` (lightweight shadcn-style primitives), `DataTable.tsx`
  (three-state table), `Layout.tsx` (sidebar shell + `PageHeader`).
- `src/pages/` — Overview + one page per observe view (Leases, Sessions, Roles, SSH, KMS,
  Object store, Audit).

## Auth (backend)
OIDC RP via identity (PKCE, `acr=mfa` required) + local break-glass. The SPA is unauthenticated
HTML; a 401 from the API bounces the browser to the backend login. Operator-only, single role
(infra maps the OIDC `roles` claim `platform-admin`).

## Not built yet
P2 mutations (revoke/rotate/reload) + viewer/operator split; cursor paging for audit; vitest +
playwright. shadcn components (dialogs/dropdowns) added via `npx shadcn@latest add` when P2 needs them.
