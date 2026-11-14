# Phase 2 Gate 2.3 — Azure Confidential Ledger adapter and v2 receipt verifier

**Status:** Implementation candidate; live customer-ledger validation OPEN  
**Branch:** `milestone/cybershield-0.3.6-acl-provider-adapter-gate-2-3`  
**Parent:** PR #18 / Gate 2.2 contract  
**Reviewer authorization:** Gigabrute report `SEC-REV-CYBERSHIELD-PHASE2-034-035-FINAL`, 14 November 2026  
**Provider:** Azure Confidential Ledger (ACL)  
**Receipt decision:** Option A — native CCF/Merkle receipt inside versioned v2 envelope

## 1. Scope implemented in this branch

- Adds a minimal HTTPS JSON transport with explicit TLS trust bundle and injected short-lived bearer-token provider.
- Uses ACL REST API version `2026-02-23` for UDF operations and application claims.
- Verifies the deployed UDF source digest against a customer-pinned SHA-256 before every append.
- Sends each append with the named pre-hook and canonical checkpoint application claims.
- Waits for transaction status `Committed`; then polls until receipt state is `Ready`. `Pending`, `Loading`, unresolved timeouts and malformed responses never produce a witness acknowledgement.
- Adds a provider-specific v2 receipt envelope. PR #9 `WitnessReceipt` v1 is unchanged.
- Adds an offline verifier that checks the customer-pinned service identity certificate fingerprint, exact canonical checkpoint bytes, checkpoint SHA-256, scope and operation claims, required CCF receipt fields, the out-of-band expected UDF SHA-256, and the Microsoft ACL SDK receipt verifier.
- Adds adapter and offline-envelope unit tests using fake transport and an injected verifier, including exact retry reconciliation and conflicting operation-ID handling. These are not live ACL proof.

## 2. Important provider semantics and controls

Microsoft's ACL UDF documentation states that transaction hooks are explicitly named in each `POST /app/transactions` request; installing a UDF does not automatically attach it to every write. Therefore:

1. The adapter always sends the approved UDF as a pre-hook.
2. The normal application workload identity must be the only non-administrative identity permitted to write to the witness collection.
3. Human/operator identities are read-only for application data. UDF administration is a separately controlled administrator function.
4. No other application or service may be granted direct transaction-write access to the witness ledger.
5. The offline verifier rejects a receipt that lacks the expected application claims, checkpoint digest, write-set digest, or approved UDF identity evidence.
6. WUDF-017 must still be exercised against a live customer-controlled ledger to demonstrate the configured ACL access boundary and verifier rejection of a deliberately unhooked write. A UDF hook by itself is not a global write policy.

The adapter's caller must derive the authenticated tenant/deployment/product scope from server-side identity. The ACL UDF uses the ACL-authenticated `context.userId` and an administrator-provisioned principal-to-scope map; request JSON is not an authorization source.

## 3. Receipt envelope v2

The v2 envelope carries:
- `provider_type = azure-confidential-ledger`
- `envelope_version = 2`
- ACL `transaction_id`
- native CCF receipt, including leaf components and Merkle proof
- application claims containing the exact canonical PR #9 checkpoint bytes and digest
- SHA-256 fingerprint of the out-of-band pinned ACL service identity certificate
- UDF ID, UDF source digest and contract version

The customer-pinned service identity certificate is supplied separately to the offline verifier. The verifier does not contact Azure or dynamically fetch trust material. PR #9 v1 remains untouched.

## 4. Known limitations / Gate 2.3 items still open

- No customer Azure subscription, ACL endpoint, Entra workload identity, ACL user mapping, or customer-pinned service certificate was supplied in this engineering session. No live ledger request has been made.
- The actual deployed UDF source must be validated against the customer's ACL ledger and current CCF UDF runtime. The source uses the documented `context.userId`, `context.contents`, `context.collectionId`, `ccf.kv`, and CCF digest helpers; runtime compatibility is not certified by local Python tests.
- Retry reconciliation scans the collection and is bounded by a configurable page limit (default 1,000 pages). Very large collections may require an independently maintained transaction cursor or a dedicated UDE-backed indexed lookup before production deployment.
- The UDF hook is opt-in per transaction request. ACL role provisioning and the live WUDF-017 bypass test are mandatory; this code does not claim a global server-side hook policy.
- Exact idempotent retry and uncertain-write recovery are now implemented as a bounded, read-only scan of the approved ACL collection. The adapter accepts a retry only when exactly one ledger entry matches the operation ID, record type, full checkpoint object, and checkpoint digest; it then polls that original transaction to Committed, retrieves its native receipt, and verifies it before returning success. Conflicting operation IDs, duplicate matches, incomplete pagination, Loading timeouts, and unresolved scans fail closed. The pre-hook itself cannot know the ledger-assigned transaction ID: Microsoft documents that the ID is returned by the write endpoint, not exposed in the documented transaction-hook context. Live validation of this recovery path remains mandatory.
- Historical certificate rotation continuity, 10+ writer concurrency, timeout-after-commit, restore/failover, and air-gapped verification with the real ACL SDK/certificate chain remain Gate 2.4–2.6 evidence.
- The envelope's local `claims_digest` field is a diagnostic SHA-256 of canonicalized claims; the authoritative provider claims digest is verified by Microsoft's native receipt verifier.
- Offline verification now requires the expected UDF SHA-256 as an explicit out-of-band input; omitting that pin is not an accepted verification mode.
- This branch does not deploy Azure resources, manage subscriptions, set resource locks, configure PIM/RBAC, archive external root checkpoints, or export control-plane events to a separate SIEM.

## 5. Customer configuration required for live validation

- Dedicated customer-controlled Azure subscription and ACL ledger.
- Separate ACL application writer principal and independent ACL administrators.
- Out-of-band service identity certificate and TLS trust bundle.
- Entra token provider / workload identity for the adapter.
- ACL user registration and principal-to-scope mapping for each tenant/deployment/product.
- UDF deployment approval and recorded source SHA-256.
- Read-only verifier host with pinned certificate and `azure-confidentialledger` SDK installed.
- Customer-approved evidence store and monitoring destination.

## 6. Validation record

Local unit tests are added in:
- `tests/test_azure_confidential_ledger.py`
- `tests/test_witness_receipt_v2.py`

Live ACL validation: **NOT RUN**. No Azure credentials or customer ledger endpoint are available in the repository context. CI passing these tests would validate local adapter behavior only, not provider semantics or production security.

## 7. Official provider references

- ACL UDFs and per-request transaction hooks: https://learn.microsoft.com/en-us/azure/confidential-ledger/user-defined-functions
- ACL write receipts and committed transaction polling: https://learn.microsoft.com/en-us/azure/confidential-ledger/write-transaction-receipts
- Offline receipt verification: https://learn.microsoft.com/en-us/azure/confidential-ledger/verify-write-transaction-receipts
- Python receipt verifier API: https://learn.microsoft.com/en-us/python/api/azure-confidentialledger/azure.confidentialledger.receipt?view=azure-python

No production certification or GIGA-SEC-02 closure is claimed.
