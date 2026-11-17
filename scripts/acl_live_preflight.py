"""Fail-closed, secret-safe preflight for customer-controlled Azure ACL testing.

This script validates local configuration only. It performs no network requests,
does not acquire tokens, and never prints configured values or certificate data.
"""
from __future__ import annotations  # noqa: I001

import argparse
import json
import os
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes


REQUIRED = (
    "CEPHAS_ACL_ENDPOINT",
    "CEPHAS_ACL_CA_BUNDLE",
    "CEPHAS_ACL_SERVICE_IDENTITY_CERT",
    "CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256",
    "CEPHAS_ACL_UDF_SHA256",
    "CEPHAS_ACL_COLLECTION_ID",
)
EXPECTED_COLLECTION = "cephas-release-witness-v2"


def validate_config(env: dict[str, str] | None = None, *, require_sdk: bool = False) -> list[str]:
    values = os.environ if env is None else env
    errors: list[str] = []
    missing = [key for key in REQUIRED if not values.get(key, "").strip()]
    errors.extend(f"missing:{key}" for key in missing)

    endpoint = values.get("CEPHAS_ACL_ENDPOINT", "").strip()
    if endpoint:
        try:
            parsed = urlsplit(endpoint)
            valid_endpoint = (
                parsed.scheme == "https"
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and parsed.port in (None, 443)
                and parsed.path in ("", "/")
                and not parsed.query
                and not parsed.fragment
            )
        except ValueError:
            valid_endpoint = False
        if not valid_endpoint:
            errors.append("invalid:CEPHAS_ACL_ENDPOINT")

    ca_path = values.get("CEPHAS_ACL_CA_BUNDLE", "").strip()
    if ca_path:
        try:
            path = Path(ca_path)
            if not path.is_file() or not path.stat().st_size:
                raise OSError("CA bundle is not a non-empty file")
            ssl.create_default_context(cafile=str(path))
        except (OSError, ssl.SSLError):
            errors.append("invalid:CEPHAS_ACL_CA_BUNDLE")

    identity_path = values.get("CEPHAS_ACL_SERVICE_IDENTITY_CERT", "").strip()
    expected_fingerprint = values.get(
        "CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256", ""
    ).strip()
    if expected_fingerprint and not re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint):
        errors.append("invalid:CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256")

    if identity_path:
        try:
            certificate_bytes = Path(identity_path).read_bytes()
            certificate = x509.load_pem_x509_certificate(certificate_bytes)
            actual_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        except (OSError, ValueError):
            errors.append("invalid:CEPHAS_ACL_SERVICE_IDENTITY_CERT")
        else:
            if (
                expected_fingerprint
                and re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint)
                and actual_fingerprint != expected_fingerprint
            ):
                errors.append("mismatch:CEPHAS_ACL_SERVICE_IDENTITY_CERT_SHA256")

    udf_digest = values.get("CEPHAS_ACL_UDF_SHA256", "").strip()
    if udf_digest and not re.fullmatch(r"[0-9a-f]{64}", udf_digest):
        errors.append("invalid:CEPHAS_ACL_UDF_SHA256")

    collection = values.get("CEPHAS_ACL_COLLECTION_ID", "").strip()
    if collection and collection != EXPECTED_COLLECTION:
        errors.append("invalid:CEPHAS_ACL_COLLECTION_ID")

    if require_sdk:
        try:
            from azure.confidentialledger.receipt import verify_receipt  # noqa: F401
        except ImportError:
            errors.append("missing-sdk:azure-confidentialledger")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-sdk",
        action="store_true",
        help="also require the Microsoft Azure Confidential Ledger receipt verifier",
    )
    args = parser.parse_args()
    errors = validate_config(require_sdk=args.require_sdk)
    result = {
        "check": "azure-confidential-ledger-live-preflight",
        "status": "blocked" if errors else "configuration_valid",
        "network_accessed": False,
        "secrets_printed": False,
        "errors": errors,
    }
    print(json.dumps(result, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
