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
