"""Fail-closed, secret-safe preflight for customer-controlled Azure ACL testing.

This script validates local configuration only. It performs no network requests,
does not acquire tokens, and never prints configured values or certificate data.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit


REQUIRED = (
    "CEPHAS_ACL_ENDPOINT",
    "CEPHAS_ACL_CA_BUNDLE",
    "CEPHAS_ACL_SERVICE_IDENTITY_CERT",
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
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            errors.append("invalid:CEPHAS_ACL_ENDPOINT")

    ca_path = values.get("CEPHAS_ACL_CA_BUNDLE", "").strip()
    if ca_path:
        path = Path(ca_path)
        if not path.is_file() or not path.stat().st_size:
            errors.append("invalid:CEPHAS_ACL_CA_BUNDLE")
        else:
            try:
                ssl.create_default_context(cafile=str(path))
            except (OSError, ssl.SSLError):
                errors.append("invalid:CEPHAS_ACL_CA_BUNDLE")

    identity_path = values.get("CEPHAS_ACL_SERVICE_IDENTITY_CERT", "").strip()
    if identity_path:
        path = Path(identity_path)
        try:
            certificate = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append("invalid:CEPHAS_ACL_SERVICE_IDENTITY_CERT")
        else:
            if (
                not certificate.strip()
                or "-----BEGIN CERTIFICATE-----" not in certificate
                or "-----END CERTIFICATE-----" not in certificate
            ):
                errors.append("invalid:CEPHAS_ACL_SERVICE_IDENTITY_CERT")

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
