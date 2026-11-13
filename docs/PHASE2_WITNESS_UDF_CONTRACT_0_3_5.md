# Phase 2 Gate 2.2 — Independent Witness Atomic UDF Contract

**Status:** Provider-neutral contract specification; implementation blocked pending Gigabrute's receipt-model decision  
**Milestone:** 0.3.5  
**Parent:** PR #17 architecture ADR  
**Scope:** Deterministic compare-and-append state machine and provider acceptance vectors

## 1. Purpose

Define the exact atomic state transition that any independent witness backend must implement. This contract is provider-neutral and does not assume that a local mock, application database, or test double is an independent immutable witness.

The contract is designed for the proposed Azure Confidential Ledger UDF implementation. Provider-specific SDK calls, UDF syntax and native receipt handling must be validated against a customer-controlled live ledger after Gigabrute approves the receipt trust model.

## 2. Security scope

Every checkpoint belongs to exactly one scope:

`(tenant_id, deployment_id, product)`

All state lookups, uniqueness constraints, append operations and receipt claims must include the full scope. No request-supplied scope may override the authenticated caller's authorized scope. The provider adapter must bind authenticated principal identity to allowed scope server-side.

The witness stores release metadata and cryptographic digests only. It must not store model binaries, raw customer events, secrets, credentials, or personal data.

## 3. Canonical request

The adapter submits the canonical PR #9 `WitnessCheckpoint` fields plus:

- `expected_previous_checkpoint_sha256`: null only for genesis; otherwise exact current head digest.
- `request_id`: transport correlation identifier only; it is not the idempotency key.
- `operation_id`: the checkpoint's stable idempotency key and unique across the entire scope history.

The canonical checkpoint digest is SHA-256 over the exact PR #9 canonical checkpoint bytes. The UDF must not reserialize an arbitrary client object and assume equivalent bytes. It must validate the submitted structured fields and digest using a documented canonicalization implementation or accept only canonical bytes and parse/validate them deterministically.

## 4. State model

Logical records (all immutable except the current-head pointer):

### Scope head
- `tenant_id`
- `deployment_id`
- `product`
- `release_sequence`
- `checkpoint_sha256`
- `operation_id`

### Operation index
Unique key: `(tenant_id, deployment_id, product, operation_id)`

Values:
- canonical checkpoint digest
- release sequence
- committed transaction identity / provider transaction reference

The operation index must be retained for the full lifetime of the witness history. Expiring idempotency records would permit old operation IDs to be reused.

### Checkpoint history
Unique key: `(tenant_id, deployment_id, product, release_sequence)`

Values:
- canonical checkpoint fields or canonical bytes
- checkpoint digest
- predecessor digest
- operation ID
- provider transaction identity

All three logical changes (checkpoint history, operation index, scope head) must commit atomically as one witness transaction. A partial write is a security failure.

## 5. Atomic compare-and-append algorithm

Within one provider-serialized atomic transaction:

1. Authenticate caller and derive its authorized scope independently of request body fields.
2. Validate all required fields, protocol version, identifier lengths, digest syntax, sequence integer semantics, and canonical checkpoint digest.
3. Confirm the request scope equals the authenticated scope.
4. Look up `operation_id` in the full-history operation index for this scope:
   - If found with identical checkpoint digest and identical canonical checkpoint content, return the original committed transaction identity as `IDEMPOTENT`; do not append.
   - If found with a different digest or content, return `OPERATION_ID_CONFLICT`.
5. Read the current scope head:
   - Empty scope: require sequence 1, null predecessor, and null expected predecessor.
   - Existing scope: require candidate sequence exactly current sequence + 1; candidate predecessor and expected predecessor must both equal current head digest.
6. Reject stale sequence, skipped sequence, wrong predecessor, cross-scope access, or malformed checkpoint.
7. Atomically append checkpoint history, operation index, and updated scope head.
8. Return a provider transaction identifier and a state result. The adapter must separately retrieve and cryptographically verify the provider-native commit receipt before acknowledging success to CyberShield.

The backend must serialize concurrent writes for a given scope. It must not rely on a read-then-write sequence outside the provider's atomic transaction boundary.

## 6. Deterministic outcome codes

| Code | Meaning | State mutation |
|---|---|---|
| `APPENDED` | New valid next checkpoint committed | Exactly one atomic append |
| `IDEMPOTENT` | Same operation ID and same canonical checkpoint already committed | None |
| `OPERATION_ID_CONFLICT` | Operation ID already used for different content | None |
| `SCOPE_DENIED` | Authenticated principal is not authorized for requested scope | None |
| `SCOPE_MISMATCH` | Checkpoint/request scope inconsistent with authorized scope | None |
| `STALE_SEQUENCE` | Candidate sequence is not the next sequence | None |
| `PREDECESSOR_MISMATCH` | Expected or checkpoint predecessor differs from current head | None |
| `INVALID_CHECKPOINT` | Canonicalization, digest, protocol or field validation failed | None |
| `RETRYABLE_UNAVAILABLE` | Provider cannot determine/complete operation | No acknowledgement; caller resolves same operation ID |

A provider timeout must never be translated into a definitive rejection unless the backend can prove the transaction did not commit.

## 7. Mandatory deterministic test vectors

Every provider implementation must pass these vectors against the same canonical fixture set.

| ID | Initial state | Candidate / action | Expected |
|---|---|---|---|
| WUDF-001 | Empty scope | Valid sequence 1, no predecessor | APPENDED |
| WUDF-002 | Sequence 1 | Exact retry of same operation ID and bytes | IDEMPOTENT; original transaction identity |
| WUDF-003 | Sequence 1 | Same operation ID, altered artifact digest | OPERATION_ID_CONFLICT |
| WUDF-004 | Sequence 1 | Sequence 3 | STALE_SEQUENCE |
| WUDF-005 | Sequence 1 | Sequence 2 with wrong predecessor | PREDECESSOR_MISMATCH |
| WUDF-006 | Sequence 1 | Sequence 2 with expected predecessor not current head | PREDECESSOR_MISMATCH |
| WUDF-007 | Scope A | Authenticated principal A submits scope B | SCOPE_DENIED |
| WUDF-008 | Scope A | Valid same sequence/digest submitted under scope B | Scope B remains independent; no cross-scope read |
| WUDF-009 | Sequence 1, operation X at sequence 1 | Sequence 2 with reused operation X and changed content | OPERATION_ID_CONFLICT (full-history uniqueness) |
| WUDF-010 | Sequence 1 | Two concurrent distinct candidates for sequence 2 | One APPENDED; other deterministic conflict; one head |
| WUDF-011 | Sequence 1 | Ten or more concurrent candidates for same next sequence | Exactly one new sequence-2 checkpoint; no fork |
| WUDF-012 | Unknown outcome after commit | Retry exact same operation ID and bytes | IDEMPOTENT; original transaction identity |
| WUDF-013 | Unknown outcome before commit | Retry exact same operation ID and bytes | One APPENDED; no duplicate |
| WUDF-014 | Sequence 2 | Candidate sequence 2 with different digest | STALE_SEQUENCE or explicit sequence conflict; no mutation |
| WUDF-015 | Any | Malformed digest, unsupported protocol, bool-as-integer sequence, noncanonical payload | INVALID_CHECKPOINT |
| WUDF-016 | Any | Attempt direct history/head/operation overwrite or deletion | Provider denies mutation; evidence retained |

The test harness must assert both returned outcome and persisted state after every vector. Merely asserting an exception is insufficient.

## 8. Receipt boundary

This contract intentionally does not define a provider receipt envelope. PR #9 v1 uses an Ed25519 signature over its own receipt claims. Azure Confidential Ledger's native write receipt uses a different proof format and trust root.

No implementation may:
- Treat an ACL native receipt as an Ed25519 signature.
- Sign an application-generated receipt and call it a provider witness receipt.
- Return success to CyberShield before independently verifying the committed provider receipt.
- Change PR #9 protocol v1 semantics without an approved versioned protocol change.

Gate 2.3 adapter work remains blocked until Gigabrute records approval of the provider-native receipt envelope or an alternative reviewed signing architecture.

## 9. Failure and recovery semantics

- **Timeout after possible commit:** resolve by the original `operation_id`; exact retry only.
- **Provider unavailable:** fail closed; do not advance PR #8 anchor or local release floor.
- **Application DB rollback:** reconstruct latest scope head from witness history and verified receipts; reconcile forward.
- **Anchor ahead of witness:** security incident; stop and preserve evidence.
- **Witness restore/replica recovery:** verify ledger integrity, transaction continuity and service identity before accepting writes.
- **Administrative change:** preserve immutable administrative evidence and alert an independently administered monitoring destination.

## 10. Gate 2.2 exit criteria

- [ ] Gigabrute reviews and accepts the state machine and test vectors.
- [ ] Provider UDF API and transaction guarantees are verified against current official provider documentation and a live test ledger.
- [ ] Canonical fixture set is generated from PR #9 v1 without changing its semantics.
- [ ] All deterministic vectors pass against a reference state-machine harness.
- [ ] Historical operation-ID uniqueness is proven, not merely current-head uniqueness.
- [ ] Cross-scope authorization is derived from authenticated identity, not client-supplied scope.
- [ ] Provider receipt trust-model decision is recorded before adapter implementation.
- [ ] No production or immutable-witness claim is made from contract tests or mocks.

## 11. Explicit status

This document specifies the required contract and acceptance suite. It is not a deployed UDF, not an Azure adapter, not a WORM certification, and not closure of GIGA-SEC-02. PR #8 and PR #9 remain untouched and under Gigabrute's review ownership.
