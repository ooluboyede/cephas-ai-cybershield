import base64
import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from cybershield_ml.release_witness import WitnessCheckpoint
from cybershield_ml.witness_receipt_v2 import WitnessReceiptEnvelopeV2
from cybershield_ml.service_identity_trust import (
    BUNDLE_SCHEMA,
    ServiceIdentityTrustBundle,
    certificate_fingerprint_sha256,
)


def make_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CEPHAS test ACL identity")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime(2026, 1, 1))
        .not_valid_after(__import__("datetime").datetime(2036, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


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


def claims(cp):
    return [{
        "schema": "cephas.cybershield.acl-witness-claims.v2",
        "checkpoint_sha256": cp.checkpoint_sha256,
        "checkpoint_canonical_utf8": cp.canonical_bytes().decode("utf-8"),
        "operation_id": cp.operation_id,
        "tenant_id": cp.tenant_id,
        "deployment_id": cp.deployment_id,
        "product": cp.product,
        "udf_id": "cephasReleaseWitnessCompareAndAppend",
        "udf_sha256": "d" * 64,
        "contract_version": "0.3.5",
    }]


def receipt():
    return {
        "cert": "node-cert",
        "leafComponents": {
            "claimsDigest": "f" * 64,
            "writeSetDigest": "e" * 64,
        },
        "proof": {},
        "signature": "signature",
        "serviceEndorsements": [],
    }


def envelope(cp, cert):
    claim = claims(cp)
    from cryptography.hazmat.primitives.serialization import Encoding
    parsed = x509.load_pem_x509_certificate(cert.encode("ascii"))
    cert_der = parsed.public_bytes(Encoding.DER)
    return WitnessReceiptEnvelopeV2(
        provider_type="azure-confidential-ledger",
        envelope_version=2,
        transaction_id="2.42",
        claims_digest=hashlib.sha256(
            __import__("json").dumps(
                {"applicationClaims": claim}, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest(),
        checkpoint_canonical_b64=base64.b64encode(cp.canonical_bytes()).decode("ascii"),
        receipt=receipt(),
        application_claims=claim,
        service_identity_sha256=hashlib.sha256(cert_der).hexdigest(),
        udf_id="cephasReleaseWitnessCompareAndAppend",
        udf_sha256="d" * 64,
    )


def test_v2_envelope_verifies_checkpoint_and_native_receipt_offline():
    cp = checkpoint()
    cert = make_certificate()
    called = {}
    def verifier(native, pinned, *, application_claims):
        called["native"] = native
        called["pinned"] = pinned
        called["claims"] = application_claims

    result = envelope(cp, cert).verify_offline(
        pinned_service_identity_certificate_pem=cert,
        native_receipt_verifier=verifier,
        expected_udf_sha256="d" * 64,
    )
    assert result == cp
    assert called["native"] == receipt()
    assert called["claims"] == claims(cp)


def test_v2_rejects_unhooked_or_claimless_receipt():
    cp = checkpoint()
    cert = make_certificate()
    item = envelope(cp, cert)
    with pytest.raises(ValueError, match="application claims"):
        WitnessReceiptEnvelopeV2(
            provider_type=item.provider_type,
            envelope_version=2,
            transaction_id=item.transaction_id,
            claims_digest=item.claims_digest,
            checkpoint_canonical_b64=item.checkpoint_canonical_b64,
            receipt=item.receipt,
            application_claims=[],
            service_identity_sha256=item.service_identity_sha256,
            udf_id=item.udf_id,
            udf_sha256=item.udf_sha256,
        )


def test_v2_rejects_wrong_pinned_service_identity():
    cp = checkpoint()
    item = envelope(cp, make_certificate())
    with pytest.raises(ValueError, match="fingerprint"):
        item.verify_offline(
            pinned_service_identity_certificate_pem=make_certificate(),
            native_receipt_verifier=lambda *_args, **_kwargs: None,
            expected_udf_sha256="d" * 64,
        )


def test_v2_rejects_receipt_without_write_set_or_claims_digest_at_construction():
    cp = checkpoint()
    cert = make_certificate()
    item = envelope(cp, cert)
    bad_receipt = {"leafComponents": {"claimsDigest": "f" * 64}}
    with pytest.raises(ValueError, match="writeSetDigest"):
        WitnessReceiptEnvelopeV2(
            provider_type=item.provider_type,
            envelope_version=2,
            transaction_id=item.transaction_id,
            claims_digest=item.claims_digest,
            checkpoint_canonical_b64=item.checkpoint_canonical_b64,
            receipt=bad_receipt,
            application_claims=item.application_claims,
            service_identity_sha256=item.service_identity_sha256,
            udf_id=item.udf_id,
            udf_sha256=item.udf_sha256,
        )


def signed_trust_bundle(active_cert, historical_cert, historical_status="historical"):
    private_key = ed25519.Ed25519PrivateKey.generate()
    payload = {
        "schema": BUNDLE_SCHEMA,
        "version": 1,
        "active_fingerprint_sha256": certificate_fingerprint_sha256(active_cert),
        "certificates": [
            {
                "fingerprint_sha256": certificate_fingerprint_sha256(active_cert),
                "certificate_pem": active_cert,
                "status": "active",
            },
            {
                "fingerprint_sha256": certificate_fingerprint_sha256(historical_cert),
                "certificate_pem": historical_cert,
                "status": historical_status,
            },
        ],
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    signature = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
    ).decode("ascii")
    return (
        ServiceIdentityTrustBundle(payload=payload, signature_b64=signature),
        public_key,
    )


def test_historical_receipt_verifies_with_customer_signed_rotation_bundle():
    old_cert = make_certificate()
    new_cert = make_certificate()
    cp = checkpoint()
    item = envelope(cp, old_cert)
    trust_bundle, signer_public_key = signed_trust_bundle(new_cert, old_cert)
    attempts = []

    def verifier(native, service_pem, *, application_claims):
        attempts.append(service_pem)
        if service_pem == new_cert:
            raise ValueError("simulated missing endorsement path to current identity")

    result = item.verify_offline(
        pinned_service_identity_certificate_pem=None,
        native_receipt_verifier=verifier,
        expected_udf_sha256="d" * 64,
        service_identity_trust_bundle=trust_bundle,
        pinned_trust_bundle_signer_public_key_b64=signer_public_key,
    )
    assert result == cp
    assert attempts == [new_cert, old_cert]


def test_rotation_bundle_rejects_revoked_issuance_identity():
    old_cert = make_certificate()
    new_cert = make_certificate()
    item = envelope(checkpoint(), old_cert)
    trust_bundle, signer_public_key = signed_trust_bundle(
        new_cert, old_cert, historical_status="revoked"
    )

    with pytest.raises(ValueError, match="absent from the customer trust bundle"):
        item.verify_offline(
            pinned_service_identity_certificate_pem=None,
            native_receipt_verifier=lambda *_args, **_kwargs: None,
            expected_udf_sha256="d" * 64,
            service_identity_trust_bundle=trust_bundle,
            pinned_trust_bundle_signer_public_key_b64=signer_public_key,
        )


def test_rotation_bundle_rejects_tampered_payload_signature():
    old_cert = make_certificate()
    new_cert = make_certificate()
    trust_bundle, signer_public_key = signed_trust_bundle(new_cert, old_cert)
    tampered = dict(trust_bundle.payload)
    tampered["active_fingerprint_sha256"] = "0" * 64
    invalid = ServiceIdentityTrustBundle(
        payload=tampered,
        signature_b64=trust_bundle.signature_b64,
    )

    with pytest.raises(ValueError, match="signature verification failed"):
        invalid.contains_issuance_identity(
            certificate_fingerprint_sha256(old_cert), signer_public_key
        )
