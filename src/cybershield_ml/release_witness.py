"""Provider-neutral immutable release-witness protocol primitives.

This module defines canonical checkpoint identity and receipt verification only.
It does not implement a durable witness backend and must not be treated as one.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_PROTOCOL = "cephas.cybershield.release-witness"
_PROTOCOL_VERSION = "1"
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _text(value: object, field: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized or normalized != normalized.strip() or len(normalized) > max_length:
        raise ValueError(f"{field} is empty, padded or too long")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in normalized):
        raise ValueError(f"{field} contains control characters")
    return normalized


def _digest(value: object, field: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not _HEX_256.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def canonical_json(value: dict) -> bytes:
    """Serialize a JSON object deterministically; reject non-JSON numeric values."""
    if not isinstance(value, dict):
        raise TypeError("canonical JSON input must be an object")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


@dataclass(frozen=True)
class WitnessCheckpoint:
    tenant_id: str
    deployment_id: str
    product: str
    release_sequence: int
    release_version: str
    metadata_sha256: str
    artifact_sha256: str
    publisher_key_id: str
    publisher_signature_sha256: str
    previous_checkpoint_sha256: str | None
    operation_id: str
    protocol: str = _PROTOCOL
    protocol_version: str = _PROTOCOL_VERSION

    def __post_init__(self):
        for field in ("tenant_id", "deployment_id", "product", "release_version"):
            object.__setattr__(self, field, _text(getattr(self, field), field))
        for field in ("publisher_key_id", "operation_id"):
            value = _text(getattr(self, field), field, max_length=128)
            if not _SAFE_ID.fullmatch(value):
                raise ValueError(f"{field} contains unsupported characters")
            object.__setattr__(self, field, value)
        if isinstance(self.release_sequence, bool) or not isinstance(self.release_sequence, int) or self.release_sequence < 1:
            raise ValueError("release_sequence must be a positive integer")
        for field in ("metadata_sha256", "artifact_sha256", "publisher_signature_sha256"):
            _digest(getattr(self, field), field)
        _digest(self.previous_checkpoint_sha256, "previous_checkpoint_sha256", optional=True)
        if self.protocol != _PROTOCOL or self.protocol_version != _PROTOCOL_VERSION:
            raise ValueError("unsupported witness protocol or version")

    def as_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "protocol_version": self.protocol_version,
            "tenant_id": self.tenant_id,
            "deployment_id": self.deployment_id,
            "product": self.product,
            "release_sequence": self.release_sequence,
            "release_version": self.release_version,
            "metadata_sha256": self.metadata_sha256,
            "artifact_sha256": self.artifact_sha256,
            "publisher_key_id": self.publisher_key_id,
            "publisher_signature_sha256": self.publisher_signature_sha256,
            "previous_checkpoint_sha256": self.previous_checkpoint_sha256,
            "operation_id": self.operation_id,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_dict())

    @property
    def checkpoint_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def scope(self) -> tuple[str, str, str]:
        return self.tenant_id, self.deployment_id, self.product


def validate_checkpoint_transition(
    current: WitnessCheckpoint | None, candidate: WitnessCheckpoint
) -> str:
    """Validate a proposed append against the currently observed scope head.

    Returns "append" for the single valid next checkpoint or "idempotent"
    when the candidate is byte-for-byte the current head. Durable backends
    must additionally enforce operation_id uniqueness over the full history
    and perform this check atomically with the append.
    """
    if current is None:
        if candidate.release_sequence != 1 or candidate.previous_checkpoint_sha256 is not None:
            raise ValueError("genesis checkpoint must be sequence 1 with no predecessor")
        return "append"

    if candidate.scope != current.scope:
        raise ValueError("checkpoint scope does not match current witness head")

    if candidate.checkpoint_sha256 == current.checkpoint_sha256:
        return "idempotent"

    if candidate.operation_id == current.operation_id:
        raise ValueError("operation_id was reused for a different checkpoint")
    if candidate.release_sequence <= current.release_sequence:
        raise ValueError("stale or conflicting release sequence")
    if candidate.release_sequence != current.release_sequence + 1:
        raise ValueError("release sequence must advance by exactly one")
    if candidate.previous_checkpoint_sha256 != current.checkpoint_sha256:
        raise ValueError("candidate predecessor does not match current witness head")
    return "append"


@dataclass(frozen=True)
class WitnessReceipt:
    witness_id: str
    checkpoint_sha256: str
    tenant_id: str
    deployment_id: str
    product: str
    release_sequence: int
    previous_checkpoint_sha256: str | None
    receipt_signature: str
    algorithm: str = "Ed25519"
    receipt_version: str = "1"

    def __post_init__(self):
        object.__setattr__(self, "witness_id", _text(self.witness_id, "witness_id", max_length=128))
        for field in ("tenant_id", "deployment_id", "product"):
            object.__setattr__(self, field, _text(getattr(self, field), field))
        _digest(self.checkpoint_sha256, "checkpoint_sha256")
        _digest(self.previous_checkpoint_sha256, "previous_checkpoint_sha256", optional=True)
        if isinstance(self.release_sequence, bool) or not isinstance(self.release_sequence, int) or self.release_sequence < 1:
            raise ValueError("receipt release_sequence must be a positive integer")
        if self.algorithm != "Ed25519" or self.receipt_version != "1":
            raise ValueError("unsupported witness receipt algorithm or version")
        if not isinstance(self.receipt_signature, str) or not self.receipt_signature:
            raise ValueError("receipt_signature is required")

    def signing_bytes(self) -> bytes:
        return canonical_json({
            "receipt_version": self.receipt_version,
            "algorithm": self.algorithm,
            "witness_id": self.witness_id,
            "checkpoint_sha256": self.checkpoint_sha256,
            "tenant_id": self.tenant_id,
            "deployment_id": self.deployment_id,
            "product": self.product,
            "release_sequence": self.release_sequence,
            "previous_checkpoint_sha256": self.previous_checkpoint_sha256,
        })

    def verify(self, checkpoint: WitnessCheckpoint, trusted_witness_public_key_pem: bytes | str) -> None:
        """Raise ValueError unless this receipt is signed and binds the exact checkpoint."""
        expected = (
            checkpoint.checkpoint_sha256,
            checkpoint.tenant_id,
            checkpoint.deployment_id,
            checkpoint.product,
            checkpoint.release_sequence,
            checkpoint.previous_checkpoint_sha256,
        )
        actual = (
            self.checkpoint_sha256,
            self.tenant_id,
            self.deployment_id,
            self.product,
            self.release_sequence,
            self.previous_checkpoint_sha256,
        )
        if actual != expected:
            raise ValueError("witness receipt does not bind the supplied checkpoint")
        pem = (
            trusted_witness_public_key_pem.encode("utf-8")
            if isinstance(trusted_witness_public_key_pem, str)
            else trusted_witness_public_key_pem
        )
        try:
            key = serialization.load_pem_public_key(pem)
        except (TypeError, ValueError) as exc:
            raise ValueError("trusted witness public key is invalid") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("trusted witness public key must be Ed25519")
        try:
            import base64
            key.verify(base64.b64decode(self.receipt_signature, validate=True), self.signing_bytes())
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ValueError("witness receipt signature verification failed") from exc


@runtime_checkable
class ImmutableReleaseWitness(Protocol):
    """Required contract for a real customer-approved witness backend.

    Implementations must provide linearizable compare-and-append, durable
    acknowledgements, exact idempotency and independently verifiable receipts.
    The backend must enforce operation_id uniqueness across the full scope history:
    an exact retry returns the original receipt, while reuse for different content
    is rejected. Sequence validation and append must be one atomic operation.
    Test doubles do not satisfy production acceptance.
    """

    def read_checkpoint(self, *, tenant_id: str, deployment_id: str, product: str):
        """Return the latest checkpoint and receipt, or None for an empty scope."""
        ...

    def compare_and_append(
        self,
        *,
        expected_previous_checkpoint_sha256: str | None,
        checkpoint: WitnessCheckpoint,
    ) -> WitnessReceipt:
        """Atomically append iff the current head matches the expected predecessor."""
        ...

    def verify_receipt(
        self, *, checkpoint: WitnessCheckpoint, receipt: WitnessReceipt
    ) -> None:
        """Verify a receipt against independently provisioned witness trust."""
        ...
