# CyberShield Phase 2 — Independent Witness Architecture Decision

**Status:** Proposed reference architecture; not production-approved  
**Milestone:** 0.3.4 Phase 2 architecture gate  
**Parent baseline:** PR #9 witness protocol core  
**Security owner:** CEPHAS AI Solutions  
**Independent reviewer:** Gigabrute Cybersecurity Labs  
**Date:** 2026-11-13

## 1. Decision summary

Select **Azure Confidential Ledger (ACL)** as the first concrete provider candidate for the independent release witness, subject to the protocol compatibility gate in section 6.

Keep the CyberShield witness interface provider-neutral. The provider must be provisioned in a customer-controlled Azure subscription and administered under identities and operational controls separate from the CyberShield application database and release-anchor administrators.

ACL is preferred for the first reference adapter because it combines an append-only ledger, transaction receipts with cryptographic Merkle proofs, and user-defined functions (UDFs) that can perform conditional checks and writes inside the ledger trust boundary. ACL documents that UDF execution is atomic and runs on the primary replica to preserve transaction ordering and strong consistency. A failed UDF aborts the transaction.

This ADR does **not** claim that an ACL adapter is implemented, deployed, certified, or compatible with the current PR #9 receipt contract. Those are subsequent gates.

## 2. Provider assessment

### Azure Confidential Ledger — preferred candidate

Relevant documented capabilities:
- Customer-managed ledger created in the customer's Azure subscription.
- Append-only ledger records and immutable transaction history.
- Cryptographic transaction receipts based on Merkle proofs; receipts can be verified offline using the service identity certificate.
- UDFs can execute conditional validation and update application tables.
- UDF execution is atomic; UDF hooks run in the same context as the ledger write transaction.
- UDFs execute on the primary replica to preserve transaction ordering and strong consistency.

Reference documentation:
- https://learn.microsoft.com/en-us/azure/confidential-ledger/overview
- https://learn.microsoft.com/en-us/azure/confidential-ledger/user-defined-functions
- https://learn.microsoft.com/en-us/azure/confidential-ledger/write-transaction-receipts
- https://learn.microsoft.com/en-us/azure/confidential-ledger/verify-write-transaction-receipts

### Amazon S3 Object Lock — useful immutable archive, not the first atomic witness

S3 Object Lock Compliance mode protects an object version from overwrite or deletion during its retention period, including by the AWS account root user. Object Lock requires versioning. This is valuable for immutable evidence retention, but S3 Object Lock by itself does not provide the complete scope-aware, linearizable compare-and-append operation required by the witness protocol. A separate conditional state service and crash-recovery protocol would be needed. Therefore S3 Object Lock may be evaluated as a secondary archive/replication target, not treated as a drop-in witness implementation.

Reference documentation:
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html

## 3. Target architecture

Components and trust boundaries:

1. **CyberShield release verifier**
   - Verifies publisher signature and artifact/metadata integrity before any model deserialization.
   - Constructs a canonical `WitnessCheckpoint`.
   - Does not hold witness administrator credentials or signing keys.

2. **Witness adapter**
   - Implements the provider-neutral `ImmutableReleaseWitness` contract.
   - Authenticates to the customer-owned ACL endpoint using a dedicated workload identity.
   - Sends only checkpoint metadata and cryptographic digests; no model payloads, customer event data, credentials, or personal data.
   - Retrieves and independently verifies the provider transaction receipt before returning success.

3. **Azure Confidential Ledger**
   - Runs the compare-and-append UDF and stores witness state in an ACL application table.
   - Appends the checkpoint as a ledger transaction.
   - The UDF validates and updates the scope head and operation-id index in the same atomic ledger transaction.
   - The ledger returns a transaction ID; the adapter obtains the committed receipt and verifies its proof against the independently provisioned service identity certificate.

4. **PR #8 release-floor anchor**
   - Remains a separate customer-operated recovery/reference anchor.
   - It must not advance the local release floor until the external witness append is committed and its receipt has been verified.
   - ACL administration and recovery must remain independent from the anchor's PostgreSQL administrators.

5. **Independent evidence and monitoring**
   - Retain provider receipts, transaction IDs, checkpoint digests, timestamps, and verification outcomes in a customer-controlled evidence location.
   - Export administrative activity to a separately administered monitoring destination.
   - Never place secrets or raw customer data in the witness ledger.

## 4. Atomic compare-and-append semantics

The ACL UDF must implement the following state machine inside one ledger transaction.

Scope key:
`(tenant_id, deployment_id, product)`

Persisted application tables:
- `release_witness_heads`: one current sequence and checkpoint digest per scope.
- `release_witness_operations`: permanent mapping of `(scope, operation_id)` to canonical checkpoint digest and committed transaction identity.
- `release_witness_checkpoints`: immutable logical checkpoint records, keyed by scope and sequence.

For each request, the UDF must:
1. Validate protocol version, field bounds, canonical checkpoint digest, and complete scope.
2. Look up the operation ID across the full scope history.
3. If the operation ID exists with the same digest, return the original transaction identity as an idempotent retry; do not create a second checkpoint.
4. If the operation ID exists with a different digest, reject.
5. Read the current scope head.
6. Require the expected predecessor digest to equal the current head; for genesis, require sequence 1 and no predecessor.
7. Require sequence to advance exactly by one.
8. Write checkpoint, operation index, and new scope head in the same atomic UDF transaction.
9. Abort the entire transaction on any validation or write failure.

Concurrency acceptance requires competing requests to be serialized by the ledger's transaction ordering. A single winner may append a given next sequence. Every loser must receive a deterministic conflict or exact-idempotent result; no fork or skipped sequence is permitted.

The implementation must confirm the actual ACL UDF transaction API and custom-table semantics in a live test ledger before claiming this behavior.

## 5. Receipt and recovery flow

Required success flow:
1. Submit the checkpoint transaction with the compare-and-append UDF hook.
2. Wait for the transaction to reach committed status.
3. Retrieve the ACL write receipt.
4. Verify the receipt cryptographically against the independently obtained ACL service identity certificate.
5. Recompute and compare the application-claims digest against the exact canonical checkpoint bytes/digest.
6. Persist the receipt and transaction identity in the evidence store.
7. Only then return a verified witness acknowledgement to the release-floor integration.

Timeout after a possible commit:
- Never assume failure or create a new operation ID.
- Resolve the original operation ID against the ledger's operation index.
- If already committed, retrieve and verify the original transaction receipt.
- If not committed, retry the exact same checkpoint and operation ID.
- If outcome cannot be resolved, fail closed; do not advance the release floor.

Recovery:
- Rebuild current scope heads from immutable committed ledger history and operation index.
- Compare reconstructed heads with PR #8's PostgreSQL anchor.
- If the application database is behind the ledger, reconcile forward only after receipt verification.
- If the anchor claims a sequence/digest ahead of the ledger, stop and raise a security incident; never trust the database snapshot.
- Test backup/restore and account-level recovery separately from the application's database recovery.

## 6. Mandatory protocol compatibility gate — OPEN

PR #9 currently defines `WitnessReceipt` with a custom Ed25519 signature verified against an independently provisioned PEM public key. ACL's documented native receipt is a CCF/Merkle proof verified against the ACL service identity certificate. These are different receipt formats and trust models.

**Do not disguise an ACL native receipt as the existing Ed25519 receipt. Do not generate an application-side Ed25519 signature and claim it is a witness signature.**

Before implementing the production adapter, obtain Gigabrute's written decision on one of these paths:

A. Add a versioned provider-proof receipt envelope to the witness protocol. The envelope carries the provider identifier, ACL transaction ID, canonical claims, native receipt, service identity certificate/key identity, and verification metadata. Verification uses ACL's supported receipt-verification algorithm and independently pinned service identity. Preserve protocol v1 compatibility.

B. Retain the strict Ed25519 receipt contract and design a separately administered witness signing service that can produce that signature only after independently verifying the ACL commit receipt. This introduces another critical trust boundary and must be separately reviewed.

Preferred path for review: **A**, because the native ledger receipt is the provider's own cryptographic proof of commit and avoids inventing a second receipt-signing layer. This is a proposed protocol evolution, not a unilateral change to PR #9.

Gigabrute must approve the receipt trust model and signature/identity rotation policy before adapter implementation.

## 7. Security and operational controls

- Dedicated customer subscription, ledger, identities, and administrators.
- No shared administrator or credential between CyberShield application DB, PR #8 anchor, and witness ledger.
- Least-privilege workload identity: append and read/receipt operations only; no ledger administration or UDF update/delete privileges.
- UDF deployment/update is a controlled, separately approved administrative action; record code digest and version in the evidence pack.
- Pin and rotate the ACL service identity certificate through an explicit trust-bundle procedure; reject unknown or expired trust material.
- TLS validation and explicit endpoint allowlisting; no redirects or ambient credential fallback.
- Secrets from a customer-managed secret store; no credentials in configuration files, logs, or repository.
- Retention, region, data residency, service availability, cost, support, and disaster-recovery obligations must be approved by the customer.
- Fail closed on unverified receipt, unavailable ledger, unresolved commit, scope mismatch, stale sequence, operation-ID conflict, or trust-bundle failure.
- Emergency recovery requires multi-party authorization, immutable audit evidence, out-of-band alerting, and independent post-incident review.

## 8. Phase 2 implementation gates

| Gate | Deliverable | Exit evidence |
|---|---|---|
| 2.1 Architecture/protocol approval | This ADR and Gigabrute receipt-model decision | Written reviewer decision; no protocol ambiguity |
| 2.2 UDF contract and local tests | Versioned UDF source, schema, deterministic test vectors | Transition, idempotency, replay, scope and conflict tests |
| 2.3 Live ACL adapter | Provider adapter and customer-controlled test ledger | Append/read/receipt verification; exact retry; negative auth tests |
| 2.4 Concurrency and failure injection | Multi-client race and fault harness | At least 10 concurrent clients; no forks/skips; timeout-after-commit recovery |
| 2.5 Anchor integration | Witness-first release-floor update | Database rollback from sequence 15 to 10 recovers to 15; ahead-of-witness fails closed |
| 2.6 Adversarial acceptance | Delete/overwrite/admin separation/network partition/restore drills | Reproducible logs and evidence pack |
| 2.7 Independent reassessment | Gigabrute review against all eight acceptance gates | Written acceptance; scope and residual risks documented |

No gate is production certification by itself. Customer-specific identity, retention, availability, data-residency, recovery, and operational controls remain deployment acceptance requirements.

## 9. Explicit non-goals

- No automated device blocking or model release enforcement outside the approved release process.
- No storage of model artifacts or customer event data in the witness.
- No cross-customer data pooling.
- No claim that PR #8 or PR #9 is production-ready.
- No changes to Gigabrute-owned PR #8 or PR #9 branches.
- No production claims based solely on mocks, in-memory tests, or a local development ledger.

## 10. Acceptance decision requested

Gigabrute is requested to review:
1. ACL as the first concrete independent witness candidate.
2. The atomic UDF compare-and-append design.
3. The proposed versioned native-provider receipt envelope (path A).
4. The trust separation between CyberShield, PR #8 anchor, and the witness ledger.
5. The recovery and fault-injection acceptance gates.

Until this review is complete, the ADR is an architecture proposal and implementation remains blocked at Gate 2.1.
