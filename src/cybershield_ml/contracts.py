"""Canonical, scope-aware telemetry contract for the CEPHAS shared security platform."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator


ClockQuality = Literal["verified", "estimated", "unknown"]
DataClassification = Literal["public", "internal", "confidential", "restricted"]


class TrustedProductScope(BaseModel):
    """Server-authenticated deployment scope; never construct from client claims alone."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=64)
    allowed_products: frozenset[str] = Field(min_length=1)
    business_unit_id: str | None = Field(default=None, max_length=128)


class SecurityTelemetryEvent(BaseModel):
    """Versioned product-neutral envelope; product payload remains source-owned."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    event_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    product_id: str = Field(min_length=1, max_length=96)
    environment: str = Field(min_length=1, max_length=64)
    business_unit_id: str | None = Field(default=None, max_length=128)
    entity_type: str = Field(min_length=1, max_length=64)
    entity_id: str = Field(min_length=1, max_length=256)
    event_type: str = Field(min_length=1, max_length=128)
    event_time: datetime
    ingested_at: datetime
    source_system: str = Field(min_length=1, max_length=128)
    source_version: str = Field(min_length=1, max_length=64)
    source_event_id: str | None = Field(default=None, max_length=128)
    clock_quality: ClockQuality = "unknown"
    data_classification: DataClassification = "internal"
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("event_time", "ingested_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("attributes")
    @classmethod
    def reject_non_finite_attributes(cls, value):
        for key, item in value.items():
            if isinstance(item, float) and not __import__("math").isfinite(item):
                raise ValueError(f"attribute {key!r} must be finite")
        return value


class ProductTelemetryAdapter(Protocol):
    """Adapter contract implemented by each CEPHAS product integration."""

    product_id: str
    adapter_version: str

    def normalize(self, source_event: object) -> SecurityTelemetryEvent:
        """Convert a source event into the canonical envelope."""
        ...


def validate_event_scope(
    event: SecurityTelemetryEvent,
    trusted_scope: TrustedProductScope,
) -> SecurityTelemetryEvent:
    """Reject scope claims that differ from server-authenticated deployment context."""
    if event.tenant_id != trusted_scope.tenant_id:
        raise ValueError("event tenant is outside the authenticated scope")
    if event.deployment_id != trusted_scope.deployment_id:
        raise ValueError("event deployment is outside the authenticated scope")
    if event.environment != trusted_scope.environment:
        raise ValueError("event environment is outside the authenticated scope")
    if event.product_id not in trusted_scope.allowed_products:
        raise ValueError("event product is not authorised for this deployment")
    if event.business_unit_id != trusted_scope.business_unit_id:
        raise ValueError("event business unit is outside the authenticated scope")
    return event


def event_fingerprint(event: SecurityTelemetryEvent) -> str:
    """Stable SHA-256 identity over the complete canonical envelope."""
    payload = event.model_dump(mode="json")
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
