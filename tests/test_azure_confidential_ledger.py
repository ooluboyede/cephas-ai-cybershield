import hashlib

import pytest

from cybershield_ml.azure_confidential_ledger import (
    ACLConflict,
    ACLProtocolError,
    ACLProviderError,
    AzureConfidentialLedgerAdapter,
)
from cybershield_ml.release_witness import WitnessCheckpoint


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.responses = []

    def request_json(self, method, path, body=None):
        self.calls.append((method, path, body))
        if not self.responses:
            raise AssertionError("unexpected ACL request")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def checkpoint():
    return WitnessCheckpoint(
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        product="CyberShield",
        release_sequence=1,
        release_version="0.3.6",
        metadata_sha256="a" * 64,
        artifact_sha256="b" * 64,
        publisher_key_id="publisher-2026",
        publisher_signature_sha256="c" * 64,
        previous_checkpoint_sha256=None,
        operation_id="gate23-op-1",
    )


def adapter(transport):
    return AzureConfidentialLedgerAdapter(
        transport=transport,
        service_identity_certificate_pem="pinned-cert",
        expected_udf_sha256="d" * 64,
        poll_interval_seconds=0,
        native_receipt_verifier=lambda *_args, **_kwargs: None,
    )


def test_adapter_checks_pinned_udf_then_posts_hook_and_claims():
    transport = FakeTransport()
    transport.responses = [
        {"code": "export function main() { return true; }"},
        {"transactionId": "2.42"},
        {"state": "Committed", "transactionId": "2.42"},
        {
            "state": "Ready",
            "transactionId": "2.42",
            "receipt": {
                "leafComponents": {"claimsDigest": "e" * 64, "writeSetDigest": "f" * 64}
            },
        },
    ]
    code = "export function main() { return true; }"
    instance = AzureConfidentialLedgerAdapter(
        transport=transport,
        service_identity_certificate_pem="pinned-cert",
        expected_udf_sha256=hashlib.sha256(code.encode()).hexdigest(),
        poll_interval_seconds=0,
        native_receipt_verifier=lambda *_args, **_kwargs: None,
    )
    result = instance.append(
        checkpoint(),
        expected_previous_checkpoint_sha256=None,
    )
    assert result.transaction_id == "2.42"
    assert transport.calls[0][0] == "GET"
    post = transport.calls[1][2]
    assert post["preHooks"] == [{"functionId": "cephasReleaseWitnessCompareAndAppend"}]
    assert post["applicationClaims"][0]["checkpoint_sha256"] == checkpoint().checkpoint_sha256


def test_adapter_fails_closed_on_udf_digest_mismatch():
    transport = FakeTransport()
    transport.responses = [{"code": "export function main() {}"}]
    with pytest.raises(ACLProtocolError, match="digest"):
        adapter(transport).append(
            checkpoint(),
            expected_previous_checkpoint_sha256=None,
        )


def test_adapter_rejects_loading_receipt_until_ready_then_fails_closed():
    transport = FakeTransport()
    code = "export function main() { return true; }"
    instance = AzureConfidentialLedgerAdapter(
        transport=transport,
        service_identity_certificate_pem="pinned-cert",
        expected_udf_sha256=hashlib.sha256(code.encode()).hexdigest(),
        receipt_poll_attempts=1,
        poll_interval_seconds=0,
        native_receipt_verifier=lambda *_args, **_kwargs: None,
    )
    transport.responses = [
        {"code": code},
        {"transactionId": "2.42"},
        {"state": "Committed", "transactionId": "2.42"},
        {"state": "Loading", "transactionId": "2.42"},
    ]
    from cybershield_ml.azure_confidential_ledger import ACLUnavailable
    with pytest.raises(ACLUnavailable, match="Loading"):
        instance.append(checkpoint(), expected_previous_checkpoint_sha256=None)



def test_adapter_recovers_exact_retry_from_ledger_collection():
    transport = FakeTransport()
    cp = checkpoint()
    entry_contents = {
        "record_type": "cephas-release-witness-checkpoint-v2",
        "checkpoint": cp.as_dict(),
        "checkpoint_sha256": cp.checkpoint_sha256,
        "operation_id": cp.operation_id,
        "udf_id": "cephasReleaseWitnessCompareAndAppend",
        "udf_sha256": "d" * 64,
        "contract_version": "0.3.5",
    }
    transport.responses = [
        {"code": "export function main() { return true; }"},
        ACLProviderError("pre-hook rejected exact operation replay"),
        {
            "state": "Ready",
            "entries": [{
                "contents": __import__("json").dumps(entry_contents),
                "transactionId": "2.77",
                "collectionId": "cephas-release-witness-v2",
            }],
        },
        {"state": "Committed", "transactionId": "2.77"},
        {
            "state": "Ready",
            "transactionId": "2.77",
            "receipt": {
                "leafComponents": {"claimsDigest": "e" * 64, "writeSetDigest": "f" * 64}
            },
        },
    ]
    result = adapter(transport).append(
        cp,
        expected_previous_checkpoint_sha256=None,
    )
    assert result.transaction_id == "2.77"
    assert transport.calls[2][0] == "GET"
    assert "collectionId=cephas-release-witness-v2" in transport.calls[2][1]


def test_adapter_rejects_reused_operation_id_with_different_checkpoint():
    transport = FakeTransport()
    cp = checkpoint()
    different = dict(cp.as_dict())
    different["artifact_sha256"] = "9" * 64
    entry_contents = {
        "record_type": "cephas-release-witness-checkpoint-v2",
        "checkpoint": different,
        "checkpoint_sha256": "9" * 64,
        "operation_id": cp.operation_id,
    }
    transport.responses = [
        {"code": "export function main() { return true; }"},
        ACLProviderError("pre-hook rejected conflicting operation"),
        {
            "state": "Ready",
            "entries": [{
                "contents": __import__("json").dumps(entry_contents),
                "transactionId": "2.78",
            }],
        },
    ]
    with pytest.raises(ACLConflict, match="different checkpoint"):
        adapter(transport).append(
            cp,
            expected_previous_checkpoint_sha256=None,
        )
