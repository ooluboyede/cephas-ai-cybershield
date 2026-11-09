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
from cybershield_ml.trust_context import DeploymentTrustContext, TrustedPublisherKeyring

# These values must come from the host's verified identity/session layer
# and separately authenticated customer key provisioning.
context = DeploymentTrustContext(
    tenant_id=verified_tenant_id,
    deployment_id=verified_deployment_id,
)
keyring = TrustedPublisherKeyring(
    tenant_id=context.tenant_id,
    deployment_id=context.deployment_id,
    public_keys=trusted_publishers,
)
model = load_model(
    "installed/model",
    tenant_id=context.tenant_id,
    trusted_public_keys=keyring.public_keys,
    release_state_store=customer_release_state_store,
    deployment_context=context,
    trusted_publisher_keyring=keyring,
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

The repository now includes a PostgreSQL DB-API adapter, `PostgresReleaseStateStore`,
using one atomic `INSERT ... ON CONFLICT ... DO UPDATE ... WHERE ... RETURNING`
statement keyed by `(tenant_id, product)`. The conditional update accepts a higher
sequence or an idempotent repeat of the same sequence/version, and rejects lower
sequences or same-sequence/different-version conflicts. The operation commits on
acceptance and rolls back on rejection or operational failure.

Provision the table through the customer's database migration process using
`POSTGRES_RELEASE_STATE_SCHEMA`. Example with a customer-owned psycopg connection
factory:

```python
import psycopg
from cybershield_ml.release_state import PostgresReleaseStateStore

def customer_connection():
    return psycopg.connect(customer_managed_dsn)

release_store = PostgresReleaseStateStore(customer_connection)
```

The connection factory, credentials, schema migration and database operations remain
under customer control. The adapter uses DB-API cursor/commit/rollback/close methods;
it does not create or manage customer infrastructure. The test suite includes a
DB-API contract double to verify SQL predicates, tenant/product scoping, commit and
rollback behavior. This is not a substitute for integration tests against a real
PostgreSQL server or multi-instance concurrency/restart/backup-restore testing.

An emergency rollback must not lower or silently reset the stored floor. It requires a
separate customer-authorized, audited break-glass procedure that records the approver,
reason, target artifact digest and resulting floor. That administrative workflow is not
implemented by this ML library. The release sequence is a rollback control, not a
substitute for publisher key revocation or tenant/database isolation.

**Important limitation:** the PostgreSQL adapter and DB-API contract tests are implemented,
but no live PostgreSQL integration/concurrency test has yet been run. Customer deployment
still needs migration execution, connection-pool/HA configuration, restart and backup/restore
validation, monitoring, access controls and an audited break-glass rollback procedure.
These operational controls remain prerequisites for production certification.


## Reproducible dependency installation

The repository commits `uv.lock`, generated with uv 0.9.5 on Python 3.11.
The lock records exact resolved package versions and distribution SHA-256 hashes.
CI verifies the lock is current with `uv lock --check --python 3.11`, installs
only the locked resolution using `uv sync --locked --all-extras --python 3.11`,
and runs Ruff and pytest through `uv run --locked`.

For a deliberate dependency update:

1. Review the proposed version-range changes in `pyproject.toml`.
2. Use the repository's pinned uv version and Python 3.11 to run `uv lock --python 3.11`.
3. Review the complete `uv.lock` diff, including package source, version and hashes.
4. Verify with `uv sync --locked --all-extras --python 3.11`, Ruff and the full test suite.
5. Submit the lockfile and manifest changes together for code review.

Do not edit package hashes manually or regenerate the lock as an unreviewed routine
CI side effect. The one-time bootstrap workflow has been removed after generating the
committed lockfile. CI itself is read-only and fails if the manifest and lock disagree.

The lockfile pins the Python application dependency resolution, including runtime and
development extras. It does not pin the GitHub-hosted runner image or third-party
GitHub Actions by immutable commit SHA; those remain separate supply-chain hardening
items. Revalidate and deliberately update the lock as part of the dependency review
cadence.


## Deployment-bound tenant trust context — GIGA-SEC-03

CyberShield 0.3.3 now requires a `DeploymentTrustContext` and a
`TrustedPublisherKeyring` when loading a model. The hosting application must create
that context only from its verified server-side authentication/session layer; never
accept tenant or deployment identifiers from an untrusted request body or model file.
The trusted publisher keyring is separately provisioned and scoped to the same
`tenant_id` and `deployment_id`. Model metadata includes the deployment ID, and the
Ed25519 signature binds it. A model copied from another deployment is rejected before
Joblib deserialization. A keyring for another tenant/deployment is rejected, and the
loader does not allow an unscoped key mapping to override the scoped keyring.

Example (the context below must be supplied by the authenticated host application):

```python
from cybershield_ml.model import load_model
from cybershield_ml.trust_context import DeploymentTrustContext, TrustedPublisherKeyring

context = DeploymentTrustContext(tenant_id=verified_tenant_id, deployment_id=verified_deployment_id)
keyring = TrustedPublisherKeyring(tenant_id=verified_tenant_id,
    deployment_id=verified_deployment_id, public_keys=customer_provisioned_keys)
model = load_model("installed/model", tenant_id=context.tenant_id,
    trusted_public_keys=keyring.public_keys, release_state_store=release_store,
    deployment_context=context, trusted_publisher_keyring=keyring)
```

**Security boundary:** these immutable value objects do not authenticate callers by
themselves. The web/API service remains responsible for deriving the context from a
trusted identity provider and protecting keyring provisioning. This change does not
implement PostgreSQL RLS, database tenant isolation, identity/MFA, or a production
release-state adapter. Cross-tenant and cross-deployment tests are required before
review closure.
