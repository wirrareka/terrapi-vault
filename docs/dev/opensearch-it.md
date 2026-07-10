# OpenSearch cred-engine integration test

The OpenSearch dynamic-cred engine (`vesta-broker/src/opensearch.rs`) has an integration
test that runs the full **create → exists → delete → gone** cycle against a live cluster
via the security REST API. It is **skipped** unless `VESTA_OS_TEST_URL` is set, so the
normal `cargo test` (and CI without a cluster) stays green.

## Spin up a throwaway OpenSearch (Docker)

The easy path — compose file with a health-check, plus a make target that runs both
gated tests with the env preset:

```sh
make os-up      # docker compose -f compose.dev.yaml up -d --wait
make it-os      # runs the opensearch:: and audit_ship:: integration tests
make os-down
```

Or by hand:

```sh
docker run -d --name vault-os-it -p 9200:9200 \
  -e discovery.type=single-node \
  -e OPENSEARCH_INITIAL_ADMIN_PASSWORD='Vault-IT-Passw0rd!' \
  -e OPENSEARCH_JAVA_OPTS='-Xms512m -Xmx512m' \
  opensearchproject/opensearch:2.13.0
```

Single-node, demo security config (admin user + self-signed TLS on 9200). Wait ~5–15 s
until `GET https://localhost:9200/_cluster/health` (basic auth `admin:…`, `-k`) is green.

## Run the test

```sh
cd services
VESTA_OS_TEST_URL='https://localhost:9200' \
VESTA_OS_TEST_ADMIN_USER='admin' \
VESTA_OS_TEST_ADMIN_PASSWORD='Vault-IT-Passw0rd!' \
VESTA_OS_TEST_ROLE='readall' \
cargo test opensearch::tests::issue_creates_and_revoke_deletes_a_real_user -- --nocapture
```

`VESTA_OS_TEST_ROLE` defaults to `readall` (a built-in role) so the security API validates
the role mapping without extra setup; in production the role is `audit-writer`
(`opensearch-infra/audit/security/audit-writer.role.json`).

### Audit shipping integration test

The B3 audit shipper (`audit_ship.rs`) has its own integration test against the same
cluster, gated on `VESTA_AUDIT_OS_TEST_URL`:

```sh
cd services
VESTA_AUDIT_OS_TEST_URL='https://localhost:9200' \
VESTA_AUDIT_OS_TEST_USER='admin' \
VESTA_AUDIT_OS_TEST_PASSWORD='Vault-IT-Passw0rd!' \
cargo test audit_ship::tests::ships_events_into_an_index -- --nocapture
```

It bulk-indexes two events into a throwaway index, refreshes, asserts the count, and
deletes the index.

## Tear down

```sh
docker rm -f vault-os-it
```

## Production runtime config (not the test)

The broker registers the OpenSearch engine when `VESTA_OS_URL` is set:
`VESTA_OS_URL`, `VESTA_OS_ADMIN_USER`, `VESTA_OS_ADMIN_PASSWORD`,
`VESTA_OS_ROLE` (default `audit-writer`), `VESTA_OS_MAX_TTL_SECS` (default 28800),
`VESTA_OS_INSECURE_TLS=1` (dev/self-signed only — never in prod).
