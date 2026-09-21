# Permanent participant loss: authority transition proposal

Status: design and test plan only. The attempted persistent `transition_loss`
journal schema was rejected by the security gate and is not implemented.

## Proposed durable semantics

A new, purpose-separated ES256 decision would bind the authority and revision,
installation/region/scope/schema, current membership, last completed transition
certificate and cut, missing member and generation, verified survivor evidence,
replacement member and generation, and a nonzero external fencing reference.
The trusted signing profile and keys remain externally supplied and are never
accepted from the token or encrypted database.

The authority journal would persist one exact immutable request and token before
replacement work. Same-byte retries return the original decision; conflicting
requests or re-signed tokens fail. The missing member is never acknowledged and
its absence never reopens the old pair. A distinct survivor-evidence callback must
authenticate the actual durable survivor checkpoint and generation. Replacement
completion requires authenticated applied evidence for the replacement plus a
fresh continuity/fencing check. Historical certificates remain inspection-only.

## Threat and operational boundary

The library cannot establish fencing, leases, host death, authority continuity,
or a current monotonic revision. A production integration must reserve the new
revision, durably fence the missing generation, authenticate survivor and
replacement evidence, and reject restored/stale authority state. Local checksums,
encrypted storage, signed historical tokens, or caller booleans are not substitutes.

## Crash and retry invariants

- Before durable authority decision: no membership mutation.
- After decision but before replacement apply: old pair remains closed; exact retry.
- After replacement apply but before authority completion: admission remains closed.
- After completion: exact completion retry succeeds; conflicting completion fails.
- Reopen re-verifies the exact signature using externally supplied historical keys.
- Missing/corrupt record, stale revision, changed fencing reference, wrong survivor,
  wrong generation, or wrong source certificate fails closed.
- No path fabricates the missing participant ACK or clears it to resume the old pair.

## Required tests after explicit approval

1. Valid survivor evidence, fencing, replacement apply, completion, and reopen.
2. Lost replies at decision, apply acknowledgement, and completion.
3. Conflicting/resigned tokens and request-field mutation.
4. Missing/corrupt records and SQL rollback at every durable boundary.
5. Stale authority revision, failed continuity, absent fencing, wrong member or
   generation, wrong source certificate/cut, and untrusted signer.
6. Historical certificate can be inspected but cannot authorize a new transition.
7. Old pair never regains admission, including after restart or partial failure.

## Rejected patch scope

The rejected patch attempted to add a persistent `transition_loss` table to the
encrypted transition Journal. No such table or Journal mutation is present. Explicit
approval must cover this new durable schema and the termination/replacement state
machine before implementation resumes.
