# CyberShield Model Artifact Handling

## Saving and loading

CyberShield 0.3.2 writes a model artifact (isolation_forest.joblib) and a JSON
metadata document (model_metadata.json). The metadata records product and software
versions, metadata and feature schema versions, algorithm, tenant scope, training
row count, training dataset fingerprint, artifact SHA-256 digest, and model parameters.

Load a model with an explicit tenant identifier:

    from cybershield_ml.model import load_model
    model = load_model("/secure/local/model-directory", tenant_id="customer-tenant")

The loader validates metadata shape and compatibility, confirms the requested
tenant matches the recorded single-tenant scope, and verifies the artifact digest
before deserializing the model. It then checks the deserialized model type, tenant
scope, training fingerprint, and feature count.

## Security boundary

**Only load model artifacts from a trusted, locally controlled source.** Joblib
uses Python serialization and deserialization can execute code. Checking a
SHA-256 digest against a colocated metadata file detects accidental corruption
and artifact/metadata mismatch, but it is not a digital signature: an attacker
who can replace both files can replace the model and its recorded digest.

Production deployment must protect the model directory with restrictive
filesystem permissions and a trusted release process. Cryptographic publisher
signatures, key rotation, secure key custody, and signed release verification
remain future hardening work; they are not implemented by this milestone.

Tenant scope in this ML package is an additional application-layer safeguard.
It does not replace authenticated server-side tenant context or database-enforced
tenant isolation.
