import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybershield_ml.release_witness import WitnessCheckpoint, WitnessReceipt


def checkpoint(**overrides):
    values = {
        "tenant_id": "tenant-a",
        "deployment_id": "deployment-a",
        "product": "CEPHAS AI CyberShield",
        "release_sequence": 45,
        "release_version": "0.3.45",
        "metadata_sha256": "a" * 64,
        "artifact_sha256": "b" * 64,
        "publisher_key_id": "publisher-2026-01",
        "publisher_signature_sha256": "c" * 64,
        "previous_checkpoint_sha256": "d" * 64,
        "operation_id": "op-45",
    }
    values.update(overrides)
    return WitnessCheckpoint(**values)


def test_checkpoint_digest_is_deterministic_and_scope_bound():
    first = checkpoint()
    second = checkpoint()
    other_tenant = checkpoint(tenant_id="tenant-b")

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.checkpoint_sha256 == second.checkpoint_sha256
    assert first.checkpoint_sha256 != other_tenant.checkpoint_sha256
    assert first.scope == ("tenant-a", "deployment-a", "CEPHAS AI CyberShield")


@pytest.mark.parametrize("field,value", [
    ("release_sequence", True),
    ("release_sequence", 0),
    ("artifact_sha256", "B" * 64),
    ("metadata_sha256", "not-a-digest"),
    ("operation_id", "contains spaces"),
    ("tenant_id", " tenant-a"),
    ("protocol_version", "2"),
])
def test_checkpoint_rejects_invalid_fields(field, value):
    with pytest.raises((TypeError, ValueError)):
        checkpoint(**{field: value})


def test_checkpoint_digest_changes_when_artifact_or_predecessor_changes():
    original = checkpoint()
    assert original.checkpoint_sha256 != checkpoint(artifact_sha256="e" * 64).checkpoint_sha256
    assert original.checkpoint_sha256 != checkpoint(previous_checkpoint_sha256="f" * 64).checkpoint_sha256


def test_receipt_verifies_exact_checkpoint_and_rejects_substitution():
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    candidate = checkpoint()
    unsigned = WitnessReceipt(
        witness_id="customer-witness-prod",
        checkpoint_sha256=candidate.checkpoint_sha256,
        tenant_id=candidate.tenant_id,
        deployment_id=candidate.deployment_id,
        product=candidate.product,
        release_sequence=candidate.release_sequence,
        previous_checkpoint_sha256=candidate.previous_checkpoint_sha256,
        receipt_signature="placeholder",
    )
    signature = base64.b64encode(private_key.sign(unsigned.signing_bytes())).decode("ascii")
    receipt = WitnessReceipt(
        witness_id=unsigned.witness_id,
        checkpoint_sha256=unsigned.checkpoint_sha256,
        tenant_id=unsigned.tenant_id,
        deployment_id=unsigned.deployment_id,
        product=unsigned.product,
        release_sequence=unsigned.release_sequence,
        previous_checkpoint_sha256=unsigned.previous_checkpoint_sha256,
        receipt_signature=signature,
    )

    receipt.verify(candidate, public_pem)
    with pytest.raises(ValueError, match="does not bind"):
        receipt.verify(checkpoint(tenant_id="tenant-other"), public_pem)


def test_receipt_rejects_invalid_signature():
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    candidate = checkpoint()
    receipt = WitnessReceipt(
        witness_id="customer-witness-prod",
        checkpoint_sha256=candidate.checkpoint_sha256,
        tenant_id=candidate.tenant_id,
        deployment_id=candidate.deployment_id,
        product=candidate.product,
        release_sequence=candidate.release_sequence,
        previous_checkpoint_sha256=candidate.previous_checkpoint_sha256,
        receipt_signature=base64.b64encode(b"x" * 64).decode("ascii"),
    )
    with pytest.raises(ValueError, match="signature verification failed"):
        receipt.verify(candidate, public_pem)
