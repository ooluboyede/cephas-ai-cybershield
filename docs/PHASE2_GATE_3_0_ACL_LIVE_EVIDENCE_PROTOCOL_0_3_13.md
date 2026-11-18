# Phase 2 Gate 3.0 — Azure ACL live-evidence intake and verification protocol (0.3.13)

## Purpose

Define a controlled, reproducible evidence package for the first customer-authorized Azure Confidential Ledger (ACL) non-production acceptance run. This gate is documentation and operator protocol only. It does not contact Azure, deploy a UDF, acquire credentials, write to a ledger, or claim live-provider validation.

The run must use a customer-controlled, disposable non-production ledger and customer-approved identities. Never use production ledger data for this exercise.

## Preconditions — hard stop unless all are true

- Customer owner has approved the non-production subscription, ledger, region, collection, test window, and named operators.
- A dedicated adapter workload identity and separate administrator/operator identities exist; permissions are least-privilege and independently reviewed.
- The exact UDF source has been approved and its SHA-256 digest is independently pinned. The deployed UDF source/configuration can be read back using an authorized read-only identity.
- The service identity certificate, private-key custody, independently provisioned SHA-256 certificate pin, CA bundle, and trust-bundle signer public key are provisioned through customer-controlled channels.
- The Microsoft ACL SDK version and verifier implementation are pinned in the test environment.
- Gigabrute has approved the provider-native receipt trust model and the test vectors for this execution.
- Clock synchronization, audit retention, evidence storage location, and incident/abort contacts are agreed.

Do not request, commit, upload to GitHub, or paste bearer tokens, private keys, client secrets, connection strings, or unredacted environment dumps. Operators must not include secret values in evidence.

## Evidence package layout

Create the package outside the repository in the customer's controlled evidence store. Use opaque identifiers, UTC timestamps, and SHA-256 hashes. The package index must identify the test run, ledger resource identifier (not credentials), region, SDK/package versions, UDF digest, collection identifier, operator roles, and evidence filenames.

| Evidence ID | Required artifact | Acceptance purpose |
|---|---|---|
| ACL-001 | Customer authorization and non-production resource inventory | Proves scope and authority |
| ACL-002 | Redacted preflight JSON plus exact source commit and command | Shows local configuration checks; not Azure acceptance |
| ACL-003 | Read-only UDF source read-back and independently calculated SHA-256 | Proves deployed source matches approved digest |
| ACL-004 | Redacted identity/RBAC role assignments and principal mapping | Shows separation of adapter, administrator, and reader permissions |
| ACL-005 | TLS chain validation result and certificate fingerprint comparison | Proves identity and TLS trust inputs used by this run |
| ACL-006 | Successful append transaction status and genuine native receipt | Establishes a committed provider transaction |
| ACL-007 | Offline Microsoft SDK verification output for the exact receipt bytes | Establishes provider-native receipt verification |
| ACL-008 | Negative authorization tests for reader/admin/other-scope identities | Shows raw-write bypass and cross-scope denial |
| ACL-009 | Concurrency run log with at least 10 independent writers and final ledger state | Tests ledger-side atomic compare-and-append |
| ACL-010 | Timeout-after-commit, process restart, and exact-retry recovery traces | Tests uncertain-write reconciliation without duplicate entries |
| ACL-011 | Pre-rotation and post-rotation receipts plus offline verification results | Tests historical trust continuity |
| ACL-012 | Explicit revocation test and rejection output | Proves revoked identity is not accepted as a trust anchor |
| ACL-013 | Evidence manifest with per-file SHA-256 and customer signature | Detects evidence alteration after capture |
| ACL-014 | Independent Gigabrute review and disposition | Records external acceptance, findings, and residual risk |

## Execution sequence

1. Freeze the candidate commit, dependency lock, SDK version, UDF source and approved digest. Record all versions before connecting.
2. Run `python scripts/acl_live_preflight.py --require-sdk` inside the customer-controlled environment. Preserve only the redacted JSON result and command metadata.
3. As a read-only administrator, retrieve the deployed UDF source/configuration. Independently hash the exact returned source bytes and compare with the approved digest. Stop on mismatch.
4. Capture redacted principal-to-scope mappings and ACL role assignments. Prove the adapter identity is the only principal permitted to invoke the approved write path; administrators and readers must not be able to bypass it with raw writes.
5. Append a unique, non-sensitive synthetic checkpoint in the dedicated test collection. Capture the actual transaction ID, committed status, and original provider receipt bytes. Never substitute a fabricated or reconstructed receipt.
6. Verify the exact receipt bytes offline with the pinned Microsoft SDK and the independently pinned service identity. Preserve verifier version, input hash, result, and redacted diagnostics.
7. Execute the negative authorization matrix, then the concurrency test with at least 10 independent writer processes/identities where supported. Assert exactly one winner for each shared predecessor and no duplicate operation IDs within the complete scope history.
8. Exercise timeout-after-commit, client process termination/restart, and exact retry. Assert recovery returns the original transaction/receipt and does not create a second ledger entry.
9. Rotate the service identity using the customer-signed trust bundle. Verify pre-rotation and post-rotation receipts offline; then explicitly revoke the old identity and prove that it is rejected for new trust decisions while historical audit evidence remains preserved.
10. Hash every artifact, create and sign the manifest using the customer's approved evidence-signing key, and store the package in the customer-controlled evidence repository.
11. Submit the complete package to Gigabrute for independent review. Record findings and remediation; do not self-approve.

## Pass/fail rules

- Missing artifact, ambiguous identity, unverifiable signature, digest mismatch, incomplete pagination, unexpected extra ledger entry, duplicate operation ID, unauthorized write success, invalid native receipt, or unexplained recovery outcome is a **FAIL**.
- A failed or inconclusive provider call is not converted into a pass by a fake-ledger test.
- Any credential or private-key disclosure in logs or evidence is an immediate **ABORT** and customer security incident.
- A run that cannot provide genuine provider receipts and exact deployed-UDF read-back is **NOT EXECUTED**, not passed.
- CI and local fixtures remain separate evidence classes and cannot substitute for any ACL-001 through ACL-014 live artifact.

## Evidence classification

- **Class A — local automated:** unit tests, fake-ledger tests, local preflight and synthetic certificates.
- **Class B — customer live provider:** genuine ACL resource, deployed UDF read-back, RBAC, transaction status, native receipt and SDK verification.
- **Class C — operational adversarial:** independent writers, timeout/restart, recovery, rotation and revocation in the customer non-production ledger.
- **Class D — independent assurance:** Gigabrute's written review of the complete immutable evidence package.

Only Classes B, C and D can close the live-provider and independent-assurance requirements. Class A is supporting evidence only.

## Exit criteria

- [ ] All hard-stop preconditions approved.
- [ ] ACL-001 through ACL-013 complete, signed, hash-verified, and retained by the customer.
- [ ] No secrets or private keys appear in repository, logs, or evidence package.
- [ ] All negative, concurrency, uncertain-write, rotation, and revocation assertions pass.
- [ ] Gigabrute issues a written Class D disposition with no unresolved critical/high findings.
- [ ] Any required remediation is completed and independently re-tested.

This protocol does not itself execute live Azure validation, close GIGA-SEC-02, or production-certify CyberShield. PRs #8 and #9 remain untouched. All PRs remain draft and unmerged pending independent review and explicit authorization.
