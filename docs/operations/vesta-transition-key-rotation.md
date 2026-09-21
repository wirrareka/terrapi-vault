# Vesta transition signing-key rotation qualification

Status: local encrypted-journal qualification. This is not a network rollout,
certificate-issuance service, fencing implementation, or production authority backend.

Transition signing keys authenticate authority-approved checkpoint-transition records.
They are separate from:

- Vesta database passphrase changes, which re-wrap a stable data-encryption key;
- mTLS certificates and member fingerprints, whose change can require member replacement;
- the external continuity/fencing policy that decides whether a new transition is allowed.

## Qualified behavior

`transition_key_rotation.rs` uses two actual P-256/ES256 keypairs and a real encrypted
transition `Journal`. Revision 1 is signed by the old key and completed after both member
ACKs. Revision 2 has contiguous bases/membership, is signed by the new key, and is likewise
completed. After close/reopen:

- both exact signed tokens and completion results remain verifiable;
- the expired revision-1 token remains historical evidence but cannot pass fresh issuance;
- removing the old historical public key makes journal open fail closed;
- restoring the complete external trust set makes the unchanged journal verifiable again;
- a wrong replacement key, wrong verification profile, or duplicate ambiguous key ID is
  rejected.

The test policy is a simulated authority fixture. Its successful callbacks are not evidence
of authenticated participants, durable external reservation, old-writer fencing, key
distribution, revocation propagation, or a safe production rollout.

## Operator requirements

1. Give every signing key a unique, stable key ID. Reject duplicate IDs even when their
   public bytes happen to match.
2. Add the new public key to every verifier before issuing a transition under it.
3. Keep every historical public key required by retained journal records. Token expiry does
   not remove the key needed to verify durable historical evidence.
4. Stop issuance under the old private key through the external authority system; deleting
   its public key from verifiers is not revocation and instead makes history unreadable.
5. Back up the trust profile/key set with the journal and restore it from an authenticated
   external source. Never load trust keys from a signed token or from journal payloads.
6. Validate the exact issuer, audience, token type, key ID, revision chain, bases, membership
   and completion evidence before enabling any dependent operation.

## Verification

From `replication/`:

```sh
cargo +1.89.0 test --locked -p terrapi-vesta-recovery \
  --test transition_key_rotation
```

Record the actual OS, architecture, Rust/SQLite/SQLCipher versions and test result. A local
pass does not qualify remote key distribution, hardware-backed signing, Linux/FreeBSD
runtime behavior or production fencing.
