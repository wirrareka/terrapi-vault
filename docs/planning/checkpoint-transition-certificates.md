# Checkpoint transition certificates

2026-09-15 — experimental verifier and encrypted journal, not yet an integrated compaction protocol.

`terrapi_vesta_recovery::transition` verifies an authority's signed assertion about a
checkpoint transition. It does not enable recovered-pair compaction, implement an
issuer, authenticate participant RPCs or replace the existing recovery validator.

## Implemented verification contract

- ES256 compact JWS, fixed-width signature, canonical unpadded base64url and dedicated
  `terrapi-checkpoint-transition+jwt` token type plus `compact_pair` action.
- Caller supplies the expected request, trusted issuer/audience profile and trusted
  key IDs with uncompressed SEC1 P-256 public keys. No network key discovery or
  trust in a key supplied by the certificate/database.
- Request binds authority identity/revision, installation, region, scope, schema, membership, recovery anchor,
  ordered primary/secondary members and generations, their possibly different old
  bases, identical new checkpoint, pair-plan digest and both publications.
- Sequence zero is permitted for an empty anchor/base. The target must advance past
  the source anchor and every present old base. Digests and incarnation IDs are nonzero.
- `verify_issuance` verifies the signature, exact request and active time window.
  `verify_historical` verifies the signature and intrinsic window consistency without
  testing current time. Their opaque result types differ deliberately.

Historical signature validity does not establish that issuance occurred while the
token was valid or that any participant applied it. Never treat it as permission for
new work. Both APIs authenticate only the trusted signer's exact assertion, not the
underlying storage facts. The durable decision journal establishes local admission and
commit history separately, through explicit integration policy checks.

External historical-key trust must be retained deliberately. A stored certificate is
not allowed to nominate its own trust root. Removing a trusted historical key or
changing the trust policy can intentionally invalidate old evidence; automatic key
rotation/revocation policy is not implemented here.

## Encrypted decision journal

`Journal::create/open` binds a dedicated encrypted database to `JournalScope`, including
authority, membership, profile, anchor and initial revision. Historical signatures are
checked with external trust. A local head marker detects missing history; it is not an
external rollback witness. Open/status are read-only validation, not live authorization.

`decide` requires a fresh signed request, current external continuity and validated
prepared evidence from both participants. There can be only one incomplete head. New
requests extend the completed cut with contiguous revisions, immutable participants
and unused request IDs. Exact current-head retries retain the original token bytes.

`acknowledge` validates applied evidence through policy callbacks. `complete` requires
both ACKs and a nonzero immutable completion ID. `fetch` can recover the exact current
token, ACKs and completion after restart, including an already completed head. An older
handle cannot modify a newer head. `status` is an observed local snapshot, not permission
to act; operational methods still check external continuity.

History is validated one record at a time, retaining the current record and an ID set,
not every historical token. Writes use transactions and reject silently ignored writes.
The integration must reserve revisions externally and serialize operations against
replacement; these callbacks do not themselves implement a distributed lock or fencing.

## Experimental typed read-side verifier

Typed nodes can receive an owned `TrustStore` through
`Node::open_with_transition_trust`; keys remain external, in memory. The internal
certificate reader binds signed requests to exact compaction plans, publication
manifests, participant continuity within the chain, history/root continuity and the
stored current base. This does not yet bind those participants to live active-member
state or prove authority completion.
It rejects orphan certificate metadata in existing formats.

This is not yet recovered-node admission: maintenance version 3 remains unsupported,
and the existing active-recovery anchor checks and original-only compaction guard
remain unchanged. The reader currently handles one completed membership chain, not
prepared phases, authority completion or archived chains across replacement cycles.
Its limit of 4096 certificate records is a defensive read bound; a future writer must
preflight capacity before committing. It is not a receipt-expiration policy.

## Required before recovered-node integration

1. An authority policy must authenticate both prepared participants, verify matching
   frozen cuts and current membership, and serialize issuance against replacement.
   Signing arbitrary caller-supplied JSON is not such a policy.
2. Wire the implemented encrypted journal to real authority continuity and prepared/
   applied evidence. Current external continuity must protect it from stale restored
   authority files; local signatures/checksums do not provide that protection alone.
3. Both nodes must durably prepare before any prune, bind the exact signed decision,
   apply atomically, and report authenticated ACKs. Completion needs both ACKs.
   Permanent participant loss requires an explicit authority-mediated resolution.
4. Node open/admission must obtain trust externally, verify signed lineage from the
   active recovery anchor to the actual base, and reject missing or mismatched evidence.
   A local `compacted` flag or checksummed plan must never skip anchor validation.
5. Active-member evidence publication must preserve complete recovery validation.
   Inactive sealed export must remain limited to its authorized baseline. Avoid requiring
   a certificate before the evidence needed to issue that certificate can be published.
6. Subsequent replacement must validate the survivor's signed transitions and bind its
   current cut into the new baseline. Candidate and survivor local history tables need
   not be identical; their authenticated checkpoint and membership must agree.
7. Add real recovered-pair repetition, crash/restart, stale-member, substituted lineage,
   lost-ACK and next-replacement tests before removing the existing explicit rejection.

Signatures do not provide an external rollback witness. An earlier valid certificate
remains cryptographically valid; online/current authority state must reject stale use.

The original grant protocol and root Vesta encrypted format are unchanged. Receipt
retention/capacity policy is unchanged. This module alone is not a release-readiness or
complete-product claim.
