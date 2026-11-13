"""DIRCM device identity primitives.

This module is a domain-layer implementation. Production persistence and source
authentication are supplied by customer-hosted adapters; callers must construct
SourceTrustContext only from authenticated server-side connector registration.
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol


class IdentityAssurance(str, Enum):
    CRYPTOGRAPHICALLY_VERIFIED = "A"
    AUTHENTICATED_MANAGED = "B"
    PROBABILISTIC = "C"
    UNKNOWN = "D"


class IdentifierType(StrEnum):
    DEVICE_CERTIFICATE = "device_certificate"
    TPM_ATTESTATION = "tpm_attestation"
    MANAGED_AGENT_ID = "managed_agent_id"
    PROBABILISTIC_SIGNAL = "probabilistic_signal"


class ResolutionStatus(StrEnum):
    VERIFIED_DEVICE = "VERIFIED_DEVICE"
    MATCH_CANDIDATE = "MATCH_CANDIDATE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class SourceTrustContext:
    """Trusted connector claims, populated by server-side authentication middleware."""

    tenant_id: str
    source_id: str
    assurance: IdentityAssurance
    authenticated: bool

    def __post_init__(self) -> None:
        if not self.tenant_id.strip() or not self.source_id.strip():
            raise ValueError("tenant_id and source_id are required")
        if not self.authenticated:
            raise ValueError("device observations require an authenticated registered source")


@dataclass(frozen=True, slots=True)
class IdentityResolution:
    tenant_id: str
    status: ResolutionStatus
    assurance: IdentityAssurance
    device_id: str | None = None
    candidate_id: str | None = None
    identifier_digest: str | None = None
    reason: str = ""


class DeviceIdentityRegistry(Protocol):
    """Persistence port. Implementations must enforce tenant-scoped uniqueness."""

    def get_or_create_verified_device(
        self, *, tenant_id: str, source_id: str, identifier_type: str, identifier_digest: str
    ) -> str: ...

    def create_match_candidate(
        self, *, tenant_id: str, source_id: str, identifier_type: str, identifier_digest: str,
        observed_at: datetime
    ) -> str: ...


def _utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")
    return value.astimezone(timezone.utc)


def digest_device_identifier(
    *, tenant_id: str, source_id: str, identifier_type: IdentifierType,
    identifier_value: str, tenant_key: bytes
) -> str:
    """Return a tenant-keyed digest; never persist the raw stable identifier."""
    if len(tenant_key) < 32:
        raise ValueError("tenant_key must contain at least 32 bytes")
    if not tenant_id.strip() or not source_id.strip() or not identifier_value.strip():
        raise ValueError("tenant, source and identifier values are required")
    message = "\x00".join(
        ("cybershield-dircm-v1", tenant_id, source_id, identifier_type.value, identifier_value)
    ).encode("utf-8")
    return hmac.new(tenant_key, message, hashlib.sha256).hexdigest()


def resolve_device_identity(
    *,
    source: SourceTrustContext,
    identifier_type: IdentifierType,
    identifier_value: str,
    observed_at: datetime,
    tenant_key: bytes,
    registry: DeviceIdentityRegistry,
) -> IdentityResolution:
    """Resolve only A/B identities; C identities become reviewable candidates, never merges."""
    timestamp = _utc_timestamp(observed_at)
    if not identifier_value or not identifier_value.strip():
        raise ValueError("identifier_value is required")

    assurance = source.assurance
    if assurance in (IdentityAssurance.CRYPTOGRAPHICALLY_VERIFIED,
                     IdentityAssurance.AUTHENTICATED_MANAGED):
        allowed = {
            IdentityAssurance.CRYPTOGRAPHICALLY_VERIFIED: {
                IdentifierType.DEVICE_CERTIFICATE, IdentifierType.TPM_ATTESTATION
            },
            IdentityAssurance.AUTHENTICATED_MANAGED: {IdentifierType.MANAGED_AGENT_ID},
        }
        if identifier_type not in allowed[assurance]:
            raise ValueError("identifier type is not permitted for this source assurance class")
        digest = digest_device_identifier(
            tenant_id=source.tenant_id, source_id=source.source_id,
            identifier_type=identifier_type, identifier_value=identifier_value,
            tenant_key=tenant_key,
        )
        device_id = registry.get_or_create_verified_device(
            tenant_id=source.tenant_id, source_id=source.source_id,
            identifier_type=identifier_type.value, identifier_digest=digest,
        )
        return IdentityResolution(
            tenant_id=source.tenant_id, status=ResolutionStatus.VERIFIED_DEVICE,
            assurance=assurance, device_id=device_id, identifier_digest=digest,
            reason="Authenticated source supplied an identifier permitted for its assurance class.",
        )

    if assurance == IdentityAssurance.PROBABILISTIC:
        if identifier_type != IdentifierType.PROBABILISTIC_SIGNAL:
            raise ValueError("probabilistic sources may submit only probabilistic signals")
        digest = digest_device_identifier(
            tenant_id=source.tenant_id, source_id=source.source_id,
            identifier_type=identifier_type, identifier_value=identifier_value,
            tenant_key=tenant_key,
        )
        candidate_id = registry.create_match_candidate(
            tenant_id=source.tenant_id, source_id=source.source_id,
            identifier_type=identifier_type.value, identifier_digest=digest,
            observed_at=timestamp,
        )
        return IdentityResolution(
            tenant_id=source.tenant_id, status=ResolutionStatus.MATCH_CANDIDATE,
            assurance=assurance, candidate_id=candidate_id, identifier_digest=digest,
            reason="Probabilistic evidence is a candidate only; no device identity was merged or verified.",
        )

    return IdentityResolution(
        tenant_id=source.tenant_id, status=ResolutionStatus.UNKNOWN,
        assurance=IdentityAssurance.UNKNOWN,
        reason="Source does not provide sufficient assurance to resolve a device.",
    )


def new_device_id() -> str:
    """Generate an opaque, random, non-derived device identifier."""
    return str(uuid.uuid4())
