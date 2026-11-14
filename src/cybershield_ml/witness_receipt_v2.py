"""Versioned Azure provider-proof receipt envelope (v2).

This is deliberately additive: PR #9 WitnessReceipt v1 is not modified.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography import x509

from .release_witness import WitnessCheckpoint, canonical_json


@dataclass(frozen=True)
class WitnessReceiptEnvelopeV2:
    provider_type: str
    envelope_version: int
    transaction_id: str
    claims_digest: str
    checkpoint_canonical_b64: str
    receipt: dict[str, Any]
    application_claims: list[dict[str, Any]]
    service_identity_sha256: str
    udf_id: str
    udf_sha256: str
    contract_version: str = "0.3.5"

    def __post_init__(self) -> None:
        if self.provider_type != "azure-confidential-ledger" or self.envelope_version != 2:
            raise ValueError("unsupported provider receipt envelope")
        if not self.transaction_id or len(self.transaction_id) > 256:
            raise ValueError("transaction_id is required")
        for name, value in (
            ("claims_digest", self.claims_digest),
            ("service_identity_sha256", self.service_identity_sha256),
            ("udf_sha256", self.udf_sha256),
        ):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError(f"{name} must be lowercase SHA-256 hex")
        if not isinstance(self.receipt, dict) or not self.receipt:
            raise ValueError("native receipt is required")
        if len(self.application_claims) != 1 or not isinstance(self.application_claims[0], dict):
            raise ValueError("exactly one structured application-claims object is required")
        leaf = self.receipt.get("leafComponents")
        if (
            not isinstance(leaf, dict)
            or not leaf.get("writeSetDigest")
            or not leaf.get("claimsDigest")
        ):
            raise ValueError("native receipt must contain writeSetDigest and claimsDigest")
        if not self.udf_id or not self.contract_version:
            raise ValueError("UDF identity and contract version are required")

    @classmethod
    def from_acl_result(
        cls,
        *,
        transaction_id: str,
        receipt_response: dict,
        application_claims: list[dict],
        service_identity_certificate_pem: str,
        udf_id: str,
        udf_sha256: str,
        contract_version: str = "0.3.5",
    ) -> WitnessReceiptEnvelopeV2:
        from cryptography.hazmat.primitives.serialization import Encoding

        if (
            receipt_response.get("state") != "Ready"
            or receipt_response.get("transactionId") != transaction_id
        ):
            raise ValueError(
                "receipt response must be Ready and bound to the supplied transaction ID"
            )
        if len(application_claims) != 1 or not isinstance(application_claims[0], dict):
            raise ValueError("exactly one structured application-claims object is required")
        claim = application_claims[0]
        if claim.get("udf_id") != udf_id or claim.get("udf_sha256") != udf_sha256:
            raise ValueError("application claims do not match the supplied UDF identity")
        if claim.get("contract_version") != contract_version:
            raise ValueError("application claims contract version mismatch")
        if claim.get("schema") != "cephas.cybershield.acl-witness-claims.v2":
            raise ValueError("unrecognized ACL application-claims schema")
        if claim.get("checkpoint_canonical_utf8") is None:
            raise ValueError("application claims omit canonical checkpoint bytes")
        cert = x509.load_pem_x509_certificate(service_identity_certificate_pem.encode("utf-8"))
        cert_der = cert.public_bytes(Encoding.DER)
        claim_bytes = canonical_json({"applicationClaims": application_claims})
        return cls(
            provider_type="azure-confidential-ledger",
            envelope_version=2,
            transaction_id=transaction_id,
            claims_digest=hashlib.sha256(claim_bytes).hexdigest(),
            checkpoint_canonical_b64=base64.b64encode(
                application_claims[0]["checkpoint_canonical_utf8"].encode("utf-8")
            ).decode("ascii"),
            receipt=receipt_response["receipt"],
            application_claims=application_claims,
            service_identity_sha256=hashlib.sha256(cert_der).hexdigest(),
            udf_id=udf_id,
            udf_sha256=udf_sha256,
            contract_version=contract_version,
        )

    def verify_offline(
        self,
        *,
        pinned_service_identity_certificate_pem: str,
        native_receipt_verifier=None,
        expected_udf_sha256: str,
    ) -> WitnessCheckpoint:
        """Verify envelope claims and provider proof without network access."""
        from cryptography.hazmat.primitives.serialization import Encoding

        cert = x509.load_pem_x509_certificate(
            pinned_service_identity_certificate_pem.encode("utf-8")
        )
        cert_digest = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
        if cert_digest != self.service_identity_sha256:
            raise ValueError("pinned service identity certificate fingerprint mismatch")

        expected_claims_digest = hashlib.sha256(
            canonical_json({"applicationClaims": self.application_claims})
        ).hexdigest()
        if expected_claims_digest != self.claims_digest:
            raise ValueError("envelope application-claims digest mismatch")
        canonical_bytes = base64.b64decode(self.checkpoint_canonical_b64, validate=True)
        if hashlib.sha256(canonical_bytes).hexdigest() != self.application_claims[0].get(
            "checkpoint_sha256"
        ):
            raise ValueError("canonical checkpoint digest mismatch")
        if canonical_bytes.decode("utf-8") != self.application_claims[0].get(
            "checkpoint_canonical_utf8"
        ):
            raise ValueError("receipt claim does not contain the exact canonical checkpoint bytes")

        parsed = json.loads(canonical_bytes.decode("utf-8"))
        checkpoint = WitnessCheckpoint(
            tenant_id=parsed["tenant_id"],
            deployment_id=parsed["deployment_id"],
            product=parsed["product"],
            release_sequence=parsed["release_sequence"],
            release_version=parsed["release_version"],
            metadata_sha256=parsed["metadata_sha256"],
            artifact_sha256=parsed["artifact_sha256"],
            publisher_key_id=parsed["publisher_key_id"],
            publisher_signature_sha256=parsed["publisher_signature_sha256"],
            previous_checkpoint_sha256=parsed["previous_checkpoint_sha256"],
            operation_id=parsed["operation_id"],
            protocol=parsed["protocol"],
            protocol_version=parsed["protocol_version"],
        )
        if checkpoint.canonical_bytes() != canonical_bytes:
            raise ValueError("checkpoint bytes are not canonical under PR #9 v1 rules")
        if len(self.application_claims) != 1 or not isinstance(self.application_claims[0], dict):
            raise ValueError(
                "receipt must contain exactly one structured application-claims object"
            )
        claim = self.application_claims[0]
        if claim.get("schema") != "cephas.cybershield.acl-witness-claims.v2":
            raise ValueError("missing approved CEPHAS ACL application-claims schema")
        if claim.get("udf_id") != self.udf_id or claim.get("udf_sha256") != self.udf_sha256:
            raise ValueError("application claims do not bind the envelope UDF identity")
        if claim.get("contract_version") != self.contract_version:
            raise ValueError("application claims contract version mismatch")
        if (
            len(expected_udf_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_udf_sha256)
            or expected_udf_sha256 != self.udf_sha256
        ):
            raise ValueError("UDF digest does not match the independently pinned expected digest")
        if claim.get("checkpoint_sha256") != checkpoint.checkpoint_sha256:
            raise ValueError("application claims do not bind the checkpoint digest")
        if claim.get("operation_id") != checkpoint.operation_id:
            raise ValueError("application claims operation ID mismatch")
        if claim.get("tenant_id") != checkpoint.tenant_id or claim.get(
            "deployment_id"
        ) != checkpoint.deployment_id or claim.get("product") != checkpoint.product:
            raise ValueError("application claims scope mismatch")

        leaf = self.receipt.get("leafComponents")
        if (
            not isinstance(leaf, dict)
            or not leaf.get("writeSetDigest")
            or not leaf.get("claimsDigest")
        ):
            raise ValueError("receipt is missing writeSetDigest or claimsDigest")
        if native_receipt_verifier is None:
            try:
                from azure.confidentialledger.receipt import verify_receipt
            except ImportError as exc:
                raise RuntimeError(
                    "install azure-confidentialledger for native offline receipt verification"
                ) from exc
            native_receipt_verifier = verify_receipt
        # Microsoft SDK verifies the CCF Merkle proof, service endorsement chain,
        # write-set digest and the supplied application-claims digest.
        native_receipt_verifier(
            self.receipt,
            pinned_service_identity_certificate_pem,
            application_claims=self.application_claims,
        )
        return checkpoint

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider_type": self.provider_type,
            "envelope_version": self.envelope_version,
            "transaction_id": self.transaction_id,
            "claims_digest": self.claims_digest,
            "checkpoint_canonical_b64": self.checkpoint_canonical_b64,
            "receipt": self.receipt,
            "application_claims": self.application_claims,
            "service_identity_sha256": self.service_identity_sha256,
            "udf_id": self.udf_id,
            "udf_sha256": self.udf_sha256,
            "contract_version": self.contract_version,
        }
