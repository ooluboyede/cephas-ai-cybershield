# Phase 2 Gate 2.8 — Azure Confidential Ledger live-validation readiness (0.3.11)

## Purpose

Prepare a safe, repeatable customer-controlled environment for the first genuine
Azure Confidential Ledger (ACL) integration run. This gate does **not** claim
that a live ledger has been tested. It adds a local preflight that validates
configuration without making network calls or printing credentials.

## Preflight

Run from the repository root:

```bash
python scripts/acl_live_preflight.py
```

To additionally require the Microsoft receipt-verification SDK:

```bash
python scripts/acl_live_preflight.py --require-sdk
```

The preflight checks these environment variables:

| Variable | Purpose |
|---|---|
| `CEPHAS_ACL_ENDPOINT` | HTTPS origin of a dedicated non-production ACL ledger |
| `CEPHAS_ACL_CA_BUNDLE` | Path to the trusted CA bundle used for TLS |
| `CEPHAS_ACL_SERVICE_IDENTITY_CERT` | Path to the independently pinned service identity certificate PEM |
| `CEPHAS_ACL_UDF_SHA256` | Independently approved lowercase SHA-256 digest of deployed UDF source |
| `CEPHAS_ACL_COLLECTION_ID` | Must be `cephas-release-witness-v2` |

The script checks presence, HTTPS-origin shape, readable certificate files,
TLS CA-bundle loadability, digest syntax, and the fixed collection identifier.
It prints only check names and status. It does not print values, read or request
bearer tokens, contact Azure, deploy a UDF, write ledger entries, or validate
the certificate's trust chain or identity binding.

The adapter's token provider must be supplied by the customer-controlled
application using its approved workload identity / managed identity mechanism.
Do not put bearer tokens, client secrets, private keys, or production credentials
in source control, issue comments, chat, test fixtures, or workflow logs. Use
customer-managed secret storage and least-privilege identities.

## Required live test environment

Before any live run, the customer must provision a dedicated non-production
ACL ledger and isolated collection, approve the exact UDF source and digest,
configure least-privilege service identity/RBAC, pin the service identity
certificate out of band, and arrange a supported Microsoft SDK version.
The live test must not target a production ledger or a customer data collection.

## Live acceptance sequence

1. Record ledger resource identity, region, API version, SDK version, and test
   window in the customer evidence register (never record credentials).
2. Confirm TLS trust and authenticated read-only access.
3. Read back the deployed UDF source and independently recompute its SHA-256;
   compare it to the approved digest.
4. Execute a single uniquely identified test append in the isolated collection.
5. Retrieve the committed transaction and genuine native receipt.
6. Verify the receipt with the supported Microsoft SDK and the pinned service
   identity; preserve the unmodified receipt and verifier output as restricted
   evidence.
7. Repeat with invalid identity, altered claims, wrong UDF digest, and revoked
   identity; each must fail closed.
8. Run controlled concurrent appends and timeout-after-commit recovery against
   the non-production ledger. Capture transaction IDs, timestamps, outcomes,
   and provider diagnostics with secrets redacted.
9. Have the independent reviewer assess the evidence, UDF semantics, ACL
   permissions, identity lifecycle, and operational recovery.

## Evidence classification

- **Local automated evidence:** preflight tests, fake-transport tests, deterministic
  receipt fixtures, lint and CI. This is what repository CI can establish.
- **Customer-controlled provider evidence:** real Azure endpoint, UDF read-back,
  RBAC, native receipt, Microsoft SDK verification, concurrency and recovery.
  This must be generated in the isolated customer environment.
- **Independent assurance:** written Gigabrute review and closure of findings.
  CI success is not a substitute.

## Gate 2.8 exit criteria

- [ ] Preflight passes in the customer-controlled non-production environment.
- [ ] Deployed UDF digest matches the independently approved source digest.
- [ ] Genuine ACL receipt verifies with the supported Microsoft SDK and pinned
      service identity.
- [ ] Negative identity/claims/digest tests fail closed.
- [ ] Live concurrency and uncertain-write recovery evidence is captured.
- [ ] Gigabrute has reviewed the provider evidence and documented findings.

Until all applicable criteria are evidenced and reviewed, the ACL provider
integration remains an implementation candidate, GIGA-SEC-02 is not declared
closed, and CyberShield is not production-certified.
