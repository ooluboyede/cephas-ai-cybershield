"""Customer-signed trust bundle for Azure Confidential Ledger service identity rotation.

The bundle is an out-of-band trust input. Certificates copied from a receipt are never
added to trust automatically. Historical certificates are retained for offline recovery;
revoked certificates are never considered verification anchors.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding


BUNDLE_SCHEMA = "cephas.cybershield.acl-service-identity-trust.v1"


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def certificate_fingerprint_sha256(pem: str) -> str:
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


@dataclass(frozen=True)
class ServiceIdentityTrustBundle:
    """Signed trust inventory; signer public key must be pinned out of band."""

    payload: dict[str, Any]
    signature_b64: str

    def _verified_certificates(
        self, pinned_signer_public_key_b64: str
    ) -> list[tuple[str, str, str]]:
        try:
            signature = base64.b64decode(self.signature_b64, validate=True)
            public_key_raw = base64.b64decode(pinned_signer_public_key_b64, validate=True)
            public_key = Ed25519PublicKey.from_public_bytes(public_key_raw)
            public_key.verify(signature, _canonical_json(self.payload))
        except Exception as exc:
            raise ValueError("customer trust-bundle signature verification failed") from exc

        if self.payload.get("schema") != BUNDLE_SCHEMA or self.payload.get("version") != 1:
            raise ValueError("unsupported service identity trust-bundle schema or version")
        entries = self.payload.get("certificates")
        if not isinstance(entries, list) or not entries:
            raise ValueError("trust bundle must contain certificate entries")

        seen: set[str] = set()
        parsed: list[tuple[str, str, str]] = []
        active: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("trust-bundle certificate entry must be an object")
            fingerprint = entry.get("fingerprint_sha256")
            pem = entry.get("certificate_pem")
            status = entry.get("status")
            if (
                not isinstance(fingerprint, str)
                or len(fingerprint) != 64
                or any(ch not in "0123456789abcdef" for ch in fingerprint)
            ):
                raise ValueError("trust-bundle certificate fingerprint must be lowercase SHA-256")
            if fingerprint in seen:
                raise ValueError("duplicate certificate fingerprint in trust bundle")
            seen.add(fingerprint)
            if not isinstance(pem, str) or not pem.strip():
                raise ValueError("trust-bundle certificate PEM is required")
            if status not in {"active", "historical", "revoked"}:
                raise ValueError("certificate status must be active, historical, or revoked")
            actual = certificate_fingerprint_sha256(pem)
            if actual != fingerprint:
                raise ValueError("trust-bundle certificate fingerprint mismatch")
            if status == "active":
                active.append(fingerprint)
            if status != "revoked":
                parsed.append((fingerprint, pem, status))

        active_fingerprint = self.payload.get("active_fingerprint_sha256")
        if len(active) != 1 or active[0] != active_fingerprint:
            raise ValueError("trust bundle must identify exactly one active certificate")
        return parsed

    def contains_issuance_identity(
        self, fingerprint: str, pinned_signer_public_key_b64: str
    ) -> bool:
        """Require a customer-pinned signer and a trusted, non-revoked issuance identity."""
        return any(
            fp == fingerprint
            for fp, _pem, _status in self._verified_certificates(
                pinned_signer_public_key_b64
            )
        )

    def verify_native_receipt(
        self,
        receipt: dict[str, Any],
        application_claims: list[dict[str, Any]],
        verifier,
        pinned_signer_public_key_b64: str,
    ) -> str:
        """Verify against customer-trusted anchors; return the successful anchor fingerprint.

        The native ACL verifier validates the node certificate and the ordered
        serviceEndorsements chain up to each candidate customer-trusted anchor.
        Historical certificates are retained for receipts captured before rotation.
        """
        certificates = self._verified_certificates(pinned_signer_public_key_b64)
        # Try active first, then historical anchors. Revoked entries were excluded.
        certificates.sort(key=lambda item: item[2] != "active")
        failures: list[Exception] = []
        for fingerprint, pem, _status in certificates:
            try:
                verifier(receipt, pem, application_claims=application_claims)
                return fingerprint
            except Exception as exc:  # SDK exposes provider-specific verification errors.
                failures.append(exc)
        raise ValueError(
            "native ACL receipt did not verify against any customer-trusted, non-revoked "
            "service identity"
        ) from (failures[-1] if failures else None)
