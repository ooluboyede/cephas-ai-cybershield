from __future__ import annotations

import json
import ssl

from scripts.acl_live_preflight import validate_config


def valid_environment(tmp_path):
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text(ssl.get_default_verify_paths().cafile and open(
        ssl.get_default_verify_paths().cafile, encoding="utf-8"
    ).read() or "", encoding="utf-8")
    identity_path = tmp_path / "identity.pem"
    identity_path.write_text(
        "-----BEGIN CERTIFICATE-----\nTEST-FIXTURE\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    return {
        "CEPHAS_ACL_ENDPOINT": "https://example.confidential-ledger.azure.com",
        "CEPHAS_ACL_CA_BUNDLE": str(ca_path),
        "CEPHAS_ACL_SERVICE_IDENTITY_CERT": str(identity_path),
        "CEPHAS_ACL_UDF_SHA256": "a" * 64,
        "CEPHAS_ACL_COLLECTION_ID": "cephas-release-witness-v2",
    }


def test_preflight_accepts_valid_nonsecret_configuration(tmp_path):
    assert validate_config(valid_environment(tmp_path)) == []


def test_preflight_fails_closed_when_required_configuration_is_missing():
    errors = validate_config({})
    assert len(errors) == 5
    assert all(item.startswith("missing:") for item in errors)


def test_preflight_rejects_non_https_or_credential_bearing_endpoint(tmp_path):
    env = valid_environment(tmp_path)
    env["CEPHAS_ACL_ENDPOINT"] = "http://user:password@example.com/path"
    assert "invalid:CEPHAS_ACL_ENDPOINT" in validate_config(env)


def test_preflight_rejects_wrong_udf_digest_and_collection(tmp_path):
    env = valid_environment(tmp_path)
    env["CEPHAS_ACL_UDF_SHA256"] = "not-a-digest"
    env["CEPHAS_ACL_COLLECTION_ID"] = "production"
    errors = validate_config(env)
    assert "invalid:CEPHAS_ACL_UDF_SHA256" in errors
    assert "invalid:CEPHAS_ACL_COLLECTION_ID" in errors


def test_preflight_does_not_require_or_print_a_bearer_token(tmp_path):
    env = valid_environment(tmp_path)
    assert validate_config(env) == []
    assert "CEPHAS_ACL_BEARER_TOKEN" not in json.dumps(env)
