# Phase 2 Gate 2.9 — Azure ACL certificate pin preflight (0.3.12)

## Purpose

Strengthen Gate 2.8's local readiness check so the configured service identity
certificate is parsed as an actual X.509 PEM certificate and its SHA-256
fingerprint is compared with an independently provisioned pin. This remains a
local-only check: it does not contact Azure, authenticate, or prove that Azure
accepts the identity.

## Required configuration

The preflight now requires:

| Variable | Purpose |
|---|---|
| `CEPHAS_ACL_ENDPOINT` | HTTPS origin for a dedicated non-production ACL ledger; explicit port, if present, must be 443 |
| `CEPHAS_ACL_CA_BUNDLE` | Path to a loadable TLS CA bundle |
| `CEPHAS_ACL_SERVICE_IDENTITY_CERT` | Path to the service identity X.509 certificate in PEM format |
| `CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256` | Independently obtained lowercase SHA-256 fingerprint of the certificate's DER encoding |
| `CEPHAS_ACL_UDF_SHA256` | Independently approved lowercase SHA-256 digest of deployed UDF source |
| `CEPHAS_ACL_COLLECTION_ID` | Must be `cephas-release-witness-v2` |

Example fingerprint generation must occur in the customer's trusted provisioning
process, independently of the preflight. The configured pin must be delivered
through the customer's approved secret/configuration management channel; do not
derive and trust the pin from the same untrusted certificate file at runtime.

## Checks and limitations

The preflight validates the HTTPS endpoint shape, rejects credentials/query/
fragment/path and non-default ports, loads the CA bundle, parses the service
identity certificate with the cryptography X.509 parser, and compares its
SHA-256 fingerprint to the separately supplied pin. It also validates the UDF
digest syntax and fixed collection identifier.

It does **not** establish certificate validity dates, certificate-chain trust,
private-key possession, Azure RBAC, workload identity issuance, identity-to-
ledger authorization, UDF deployment correctness, or native receipt validity.
Those require the customer-controlled live acceptance sequence in Gate 2.8.

The command prints only check names and status. It does not print configured
values, certificate contents, tokens, or private keys, and performs no network
requests or ledger writes.

## Tests

Automated tests use a generated ephemeral self-signed X.509 fixture to exercise
valid parsing, malformed PEM rejection, fingerprint mismatch, malformed pin,
endpoint parsing, and secret non-disclosure. These fixtures are local test
evidence only and are not Azure-issued identity evidence.

## Exit criteria

- [ ] Local CI passes lint, unit, and PostgreSQL integration suites.
- [ ] Customer-provisioned certificate parses and matches an independently
      distributed fingerprint pin.
- [ ] Customer-controlled Azure live acceptance from Gate 2.8 is completed.
- [ ] Genuine native receipt, negative identity tests, concurrency/recovery,
      and provider evidence are independently reviewed by Gigabrute.

This gate does not close GIGA-SEC-02 and does not production-certify CyberShield.
PRs #8 and #9 remain untouched. This work is proposed in a separate draft PR
and must not be merged without the required review and explicit authorization.
