# OpenSearch cred-engine integration test

The OpenSearch dynamic-cred engine (`vault-broker/src/opensearch.rs`) has an integration
test that runs the full **create → exists → delete → gone** cycle against a live cluster
via the security REST API. It is **skipped** unless `VAULT_OS_TEST_URL` is set, so the
normal `cargo test` (and CI without a cluster) stays green.

## Spin up a throwaway OpenSearch (Docker)

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
VAULT_OS_TEST_URL='https://localhost:9200' \
VAULT_OS_TEST_ADMIN_USER='admin' \
VAULT_OS_TEST_ADMIN_PASSWORD='Vault-IT-Passw0rd!' \
VAULT_OS_TEST_ROLE='readall' \
cargo test opensearch::tests::issue_creates_and_revoke_deletes_a_real_user -- --nocapture
```

`VAULT_OS_TEST_ROLE` defaults to `readall` (a built-in role) so the security API validates
the role mapping without extra setup; in production the role is `audit-writer`
(`opensearch-infra/audit/security/audit-writer.role.json`).

## Tear down

```sh
docker rm -f vault-os-it
```

## Production runtime config (not the test)

The broker registers the OpenSearch engine when `VAULT_OS_URL` is set:
`VAULT_OS_URL`, `VAULT_OS_ADMIN_USER`, `VAULT_OS_ADMIN_PASSWORD`,
`VAULT_OS_ROLE` (default `audit-writer`), `VAULT_OS_MAX_TTL_SECS` (default 28800),
`VAULT_OS_INSECURE_TLS=1` (dev/self-signed only — never in prod).
