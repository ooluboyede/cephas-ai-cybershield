from __future__ import annotations

import json
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scripts.acl_live_preflight import validate_config


def make_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CEPHAS test identity")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before_utc(now - timedelta(minutes=1))
        .not_valid_after_utc(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM), certificate.fingerprint(
        hashes.SHA256()
    ).hex()


def valid_environment(tmp_path):
    ca_path = tmp_path / "ca.pem"
    system_ca = ssl.get_default_verify_paths().cafile
    assert system_ca is not None
    ca_path.write_text(Path(system_ca).read_text(encoding="utf-8"), encoding="utf-8")
    identity_path = tmp_path / "identity.pem"
    certificate_pem, fingerprint = make_certificate()
    identity_path.write_bytes(certificate_pem)
    return {
        "CEPHAS_ACL_ENDPOINT": "https://example.confidential-ledger.azure.com",
        "CEPHAS_ACL_CA_BUNDLE": str(ca_path),
        "CEPHAS_ACL_SERVICE_IDENTITY_CERT": str(identity_path),
        "CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256": fingerprint,
        "CEPHAS_ACL_UDF_SHA256": "a" * 64,
        "CEPHAS_ACL_COLLECTION_ID": "cephas-release-witness-v2",
    }


def test_preflight_accepts_valid_nonsecret_configuration(tmp_path):
    assert validate_config(valid_environment(tmp_path)) == []


def test_preflight_fails_closed_when_required_configuration_is_missing():
    errors = validate_config({})
    assert len(errors) == 6
    assert all(item.startswith("missing:") for item in errors)


def test_preflight_rejects_non_https_or_credential_bearing_endpoint(tmp_path):
    env = valid_environment(tmp_path)
    env["CEPHAS_ACL_ENDPOINT"] = "http://user:password@example.com/path"
    assert "invalid:CEPHAS_ACL_ENDPOINT" in validate_config(env)


def test_preflight_rejects_malformed_endpoint_authority(tmp_path):
    env = valid_environment(tmp_path)
    env["CEPHAS_ACL_ENDPOINT"] = "https://[invalid"
    assert "invalid:CEPHAS_ACL_ENDPOINT" in validate_config(env)


def test_preflight_rejects_wrong_udf_digest_and_collection(tmp_path):
    env = valid_environment(tmp_path)
    env["CEPHAS_ACL_UDF_SHA256"] = "not-a-digest"
    env["CEPHAS_ACL_COLLECTION_ID"] = "production"
    errors = validate_config(env)
    assert "invalid:CEPHAS_ACL_UDF_SHA256" in errors
    assert "invalid:CEPHAS_ACL_COLLECTION_ID" in errors


def test_preflight_rejects_malformed_certificate_pem(tmp_path):
    env = valid_environment(tmp_path)
    Path(env["CEPHAS_ACL_SERVICE_IDENTITY_CERT"]).write_text(
        "-----BEGIN CERTIFICATE-----\\nNOT-A-CERTIFICATE\\n-----END CERTIFICATE-----\\n",
        encoding="utf-8",
    )
    assert "invalid:CEPHAS_ACL_SERVICE_IDENTITY_CERT" in validate_config(env)


def test_preflight_rejects_certificate_fingerprint_mismatch(tmp_path):
    env = valid_environment(tmp_path)
    env["CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256"] = "0" * 64
    assert "mismatch:CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256" in validate_config(env)


def test_preflight_rejects_malformed_certificate_fingerprint(tmp_path):
    env = valid_environment(tmp_path)
    env["CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256"] = "not-a-fingerprint"
    assert "invalid:CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256" in validate_config(env)


def test_preflight_does_not_require_or_print_a_bearer_token(tmp_path):
    env = valid_environment(tmp_path)
    assert validate_config(env) == []
    assert "CEPHAS_ACL_BEARER_TOKEN" not in json.dumps(env)
