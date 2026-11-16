# CyberShield Phase 2 Gate 2.7 — Offline Receipt Tamper Acceptance

**Milestone:** 0.3.10  
**Parent:** Gate 2.6 adversarial receipt acceptance  
**Status:** Deterministic offline-envelope tests added; provider-native receipt verification and independent review remain required.

## Objective

Prove that the versioned offline receipt envelope rejects tampering with its claims, canonical checkpoint bytes, and independently pinned UDF identity before returning a trusted checkpoint.

## Acceptance cases

| ID | Attack / fault | Required outcome | Evidence |
|---|---|---|---|
| OFFLINE-001 | Modify tenant/scope data inside application claims after envelope creation | Reject claims digest mismatch | Unit test |
| OFFLINE-002 | Alter canonical checkpoint bytes while retaining envelope metadata | Reject checkpoint digest mismatch | Unit test |
| OFFLINE-003 | Supply a different independently pinned UDF digest | Reject UDF identity mismatch | Unit test |
| OFFLINE-004 | Supply wrong service identity certificate | Reject certificate fingerprint mismatch | Existing unit test |
| OFFLINE-005 | Supply revoked issuance identity | Reject trust-bundle membership | Existing unit test |
| OFFLINE-006 | Tamper with customer-signed rotation trust bundle | Reject signature verification | Existing unit test |
| OFFLINE-007 | Alter native CCF receipt proof or endorsements | Microsoft native verifier must reject | Requires genuine ACL receipt fixture and SDK |
| OFFLINE-008 | Replay an old valid receipt for another checkpoint | Claims digest / checkpoint binding must reject | Requires genuine ACL receipt fixture |

## Evidence boundary

The new tests use synthetic certificates and a deterministic verifier callback. They establish that the envelope's local binding checks execute as expected. They do not validate the CCF Merkle proof, service endorsement chain, real Azure certificate lifecycle, or authenticity of a provider receipt. Those require genuine customer-controlled Azure Confidential Ledger receipts and Microsoft's native receipt verifier.

## Required live-provider follow-up

1. Capture genuine committed receipt fixtures from the customer-controlled ledger.
2. Verify valid receipts using the pinned service identity certificate and the supported Azure SDK version.
3. Mutate proof, endorsement, transaction binding and application claims independently; require rejection.
4. Verify historical receipts across an approved rotation bundle and reject revoked identities.
5. Store redacted outputs and immutable evidence references in customer-approved evidence storage.

Never commit customer data, bearer tokens, private keys, or unredacted credentials.

## Exit criteria

- CI green on this exact PR head.
- All local tamper tests pass.
- Genuine provider receipt verification is demonstrated in the customer-controlled environment.
- Gigabrute approves the receipt trust model and independently reviews the evidence.
- PR #8 and PR #9 remain untouched; no merge or production certification is implied.

**Gate decision:** OPEN pending CI, live Azure evidence and independent review.
