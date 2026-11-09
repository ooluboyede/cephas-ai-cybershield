# CyberShield Model Artifact Handling

## Model release files

CyberShield 0.3.3 model releases contain `isolation_forest.joblib`, `model_metadata.json`, and a detached `model_signature.json` document.

## Publisher signing

The publisher signs the exact metadata bytes together with the artifact digest and critical identity fields. The signature binds the model payload to its metadata, tenant scope, product/version and schemas. Changes to either model or metadata invalidate verification.

Generate an Ed25519 key pair outside the application host:

```sh
openssl genpkey -algorithm ED25519 -out cephas-model-signing-private.pem
openssl pkey -in cephas-model-signing-private.pem -pubout -out cephas-model-signing-public.pem
```

Keep the private key in an HSM, managed KMS or tightly controlled offline signing environment. Never commit private keys to source control, embed them in customer deployments, or distribute them with model artifacts.

Sign a release directory in the publisher-controlled pipeline:

```python
from pathlib import Path
from cybershield_ml.signing import sign_model

sign_model(
    "release/model",
    tenant_id="customer-tenant",
    private_key_pem=Path("cephas-model-signing-private.pem").read_bytes(),
    key_id="cephas-prod-2026",
)
```

## Customer-side verification

The customer application maintains an explicit trusted public-key ring, provisioned through a separately authenticated release/configuration channel. A public key delivered beside the model is not trusted automatically.

```python
from pathlib import Path
from cybershield_ml.model import load_model

trusted_publishers = {
    "cephas-prod-2026": Path("trusted/cephas-model-signing-public.pem").read_bytes(),
}
model = load_model(
    "installed/model",
    tenant_id="customer-tenant",
    trusted_public_keys=trusted_publishers,
)
```

Loading fails closed if the signature is absent, malformed, signed by an unknown key, or invalid. Ed25519 verification occurs before Joblib deserialization; artifact digest, tenant scope, model type, training fingerprint and feature count checks remain in place.

## Key lifecycle and limitations

- Keep private signing keys outside customer environments and application runtime.
- Prefer HSM/KMS or offline signing with dual-control access.
- Maintain key IDs, activation dates, rotation and revocation records.
- Distribute a new public key before signing with it; retain old keys only for supported releases.
- The library currently uses an explicit trusted-key allowlist. Automated revocation feeds, HSM/KMS integration, key rotation orchestration and audit reporting remain future hardening.
- Ed25519 proves possession of the private key and integrity of signed content. It does not establish publisher authority unless the customer independently trusts and securely provisions the public key.
- Joblib remains unsafe for untrusted files; signature verification is mandatory before loading.

Tenant scope in this ML package remains an application-layer safeguard. It does not replace authenticated server-side tenant context or database-enforced tenant isolation.


## Independent review regression evidence (GIGA-SEC-01 / GIGA-SEC-04)

The 0.3.3 regression suite additionally verifies that:
- Reordering metadata JSON keys without changing the parsed object invalidates the signature, because the signature binds the exact metadata file bytes.
- A whitespace-only metadata-byte change invalidates the signature.
- A signature key ID is resolved by exact lookup in the customer-provided trusted-key mapping. There is no fallback to another configured ID, even if another ID maps to the same public key.
- Signing rejects malformed key IDs, including empty values, whitespace, newline characters and identifiers longer than 128 characters.

These tests demonstrate the behavior of this implementation; they do not by themselves establish that the reviewer's complete attack scenarios have been addressed. Gigabrute is asked to identify the concrete input/path they consider exploitable if either finding remains open.


## Signed release sequencing and anti-rollback

Every newly produced model artifact carries a positive integer `release_sequence` in
`model_metadata.json`. The Ed25519 signature binds this sequence together with the
metadata bytes and artifact digest. A publisher must allocate monotonically increasing
sequences for each product release stream; do not reset the sequence when rotating keys
or rebuilding a package.

Model loading now requires a customer-supplied `ReleaseStateStore`. Its
`accept_release(...)` operation must be an atomic, durable compare-and-set keyed by
customer deployment, tenant and product. It must:

- reject a sequence lower than the stored minimum;
- treat the same sequence and same version as an idempotent reinstall;
- reject reuse of one sequence for a different version;
- persist the new accepted sequence before model deserialization;
- be shared by all service instances and survive restart, failover and restore;
- fail closed when the state store is unavailable.

The repository defines the interface only. A production customer deployment must
implement it using a transactional database or equivalent durable coordination store,
with authenticated tenant context, uniqueness/locking or compare-and-set semantics,
backups, access controls and an auditable administrative path. A process-local dictionary
or in-memory cache is not a production implementation. The test suite's in-memory
stand-in tests the contract; it is not evidence of a production database adapter.

Example integration shape:

```python
from cybershield_ml.model import load_model
from customer_platform.release_state import PostgresReleaseStateStore

model = load_model(
    "installed/model",
    tenant_id=authenticated_tenant_id,
    trusted_public_keys=trusted_publishers,
    release_state_store=PostgresReleaseStateStore(customer_database),
)
```

An emergency rollback must not lower or silently reset the stored floor. It requires a
separate customer-authorized, audited break-glass procedure that records the approver,
reason, target artifact digest and resulting floor. That administrative workflow is not
implemented by this ML library. The release sequence is a rollback control, not a
substitute for publisher key revocation or tenant/database isolation.

**Important limitation:** the state-store interface and its test double are implemented
here; a production PostgreSQL/customer deployment adapter, transactional concurrency
tests against that adapter, backup/restore behavior and the break-glass workflow remain
unimplemented and must be completed before production certification.
