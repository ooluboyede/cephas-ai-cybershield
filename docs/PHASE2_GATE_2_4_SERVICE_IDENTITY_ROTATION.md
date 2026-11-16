# Phase 2 Gate 2.4 — Service identity rotation and historical receipt continuity

**Status:** Implementation candidate; offline test execution and live ACL validation OPEN  
**Branch:** `milestone/cybershield-0.3.7-service-identity-rotation-gate-2-4`  
**Parent:** Gate 2.3 / PR #19  
**Scope:** Customer-controlled service identity trust rotation, historical receipt recovery, and revocation handling

## 1. Implemented in this gate

- Adds `ServiceIdentityTrustBundle`, a versioned customer trust inventory for Azure Confidential Ledger service identity certificates.
- Requires an Ed25519 signature over canonical JSON and a separately pinned signer public key. The signer key is never trusted merely because it is carried alongside the bundle.
- Requires every certificate entry to carry a SHA-256 fingerprint that is recomputed from the PEM certificate.
- Requires exactly one active certificate matching `active_fingerprint_sha256`.
- Supports explicit `historical` and `revoked` states. Revoked certificates are excluded from verification anchors.
- Requires the receipt envelope's issuance identity fingerprint to exist in the signed customer bundle and not be revoked.
- Verifies the native ACL receipt against the active trust anchor first, then customer-approved historical anchors. The Microsoft ACL verifier validates the node certificate and ordered `serviceEndorsements` chain to the supplied anchor.
- Preserves the existing single-pinned-certificate verification path for backward compatibility.
- Adds tests for historical-anchor fallback, revoked issuance identity rejection, and trust-bundle signature tampering.

## 2. Trust model and operating procedure

1. Customer security administration obtains the current ACL service identity certificate through its approved control process.
2. Customer security administration maintains the active certificate plus explicitly approved historical certificates in a trust bundle.
3. The customer signs the canonical bundle JSON with its Ed25519 trust-bundle signing key.
4. The offline verifier receives the signed bundle and the trust-bundle signer public key through separate, independently authenticated channels. The signer public key must be pinned out of band.
5. On rotation, the customer publishes a newly signed bundle with exactly one active certificate; the prior active certificate becomes historical unless the customer revokes it.
6. On compromise, the customer marks the affected certificate revoked in a newly signed bundle. Receipts whose envelope issuance fingerprint is revoked are rejected.
7. The verifier never imports trust from `receipt.cert` or `serviceEndorsements` without a matching customer-trusted anchor.

Example payload shape (PEM values abbreviated):

```json
{
  "schema": "cephas.cybershield.acl-service-identity-trust.v1",
  "version": 1,
  "active_fingerprint_sha256": "<active-certificate-sha256>",
  "certificates": [
    {
      "fingerprint_sha256": "<active-certificate-sha256>",
      "certificate_pem": "<ACTIVE SERVICE CERTIFICATE PEM>",
      "status": "active"
    },
    {
      "fingerprint_sha256": "<prior-certificate-sha256>",
      "certificate_pem": "<HISTORICAL SERVICE CERTIFICATE PEM>",
      "status": "historical"
    }
  ]
}
```

## 3. Historical certificate time semantics

Microsoft's ACL receipt-verification guidance specifies that `serviceEndorsements` is ordered from oldest to latest and must be verified transitively from the signing node certificate to the trusted service identity. Its documented historical-recovery example disables certificate time checks because older service certificates may have expired while their historical signatures remain necessary to establish the trust chain. This gate therefore treats trust status and cryptographic endorsement as explicit customer policy; it does not silently equate certificate expiry with revocation.

The customer must preserve the signed trust bundle and signer-key custody records under its retention policy. This implementation does not independently establish a CA revocation feed, OCSP responder, or CRL service for ACL service identities.

## 4. Validation boundaries

- Tests are authored but have **not been executed** in this session.
- GitHub Actions remain paused at the user's request until Monday.
- No customer ACL endpoint, current/previous service certificates, actual service-endorsement chain, or customer trust-bundle signer key was supplied.
- The rotation tests use synthetic certificates and an injected native-verifier function. They validate bundle-signature handling, trust-state decisions, and anchor fallback logic; they do not prove a real Azure CCF endorsement chain.
- Live validation must use at least one receipt created before rotation and one after rotation, verify both offline against the customer-signed bundle, then mark a certificate revoked and confirm the expected historical-receipt rejection.
- A live test must also confirm the installed Azure SDK's actual `verify_receipt` behavior with the customer's receipt's `serviceEndorsements` ordering.
- Certificate validity dates are not treated as revocation. A customer compromise/revocation decision must be explicitly represented in a newly signed trust bundle.
- This gate does not establish independent ledger immutability, production certification, or closure of GIGA-SEC-02.

## 5. Provider reference

- Microsoft Learn — [Verify Azure Confidential Ledger write transaction receipts](https://learn.microsoft.com/en-us/azure/confidential-ledger/verify-write-transaction-receipts)
- Microsoft Learn — [Azure Confidential Ledger write transaction receipts](https://learn.microsoft.com/en-us/azure/confidential-ledger/write-transaction-receipts)
- Microsoft Learn — [Python receipt verification API](https://learn.microsoft.com/en-us/python/api/azure-confidentialledger/azure.confidentialledger.receipt?view=azure-python)

**Release status:** Draft implementation candidate; offline test execution, live Azure validation, and independent reassessment remain required.
