# Dev entry points for the two Cargo workspaces (root lib + services/) and the web SPA.
# Mirrors what CI runs (.github/workflows/ci.yml) so `make ci` locally ≈ green CI.

OS_PASSWORD := Vault-IT-Passw0rd!

.PHONY: ci lib services web fmt deny test os-up os-down it-os

ci: lib services web deny

lib:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test

services:
	cd services && cargo fmt --all --check
	cd services && cargo clippy --workspace --all-targets -- -D warnings
	cd services && cargo test --workspace

web:
	pnpm --dir web install
	pnpm --dir web lint
	pnpm --dir web typecheck
	pnpm --dir web test

fmt:
	cargo fmt
	cd services && cargo fmt --all

deny:
	cargo deny check
	cd services && cargo deny check

test:
	cargo test
	cd services && cargo test --workspace

# Throwaway OpenSearch for the gated integration tests (docs/dev/opensearch-it.md).
os-up:
	docker compose -f compose.dev.yaml up -d --wait

os-down:
	docker compose -f compose.dev.yaml down -v

it-os: os-up
	cd services && \
	VESTA_OS_TEST_URL='https://localhost:9200' \
	VESTA_OS_TEST_ADMIN_USER='admin' \
	VESTA_OS_TEST_ADMIN_PASSWORD='$(OS_PASSWORD)' \
	VESTA_OS_TEST_ROLE='readall' \
	VESTA_AUDIT_OS_TEST_URL='https://localhost:9200' \
	VESTA_AUDIT_OS_TEST_USER='admin' \
	VESTA_AUDIT_OS_TEST_PASSWORD='$(OS_PASSWORD)' \
	cargo test -p vesta-broker opensearch:: audit_ship:: -- --nocapture
