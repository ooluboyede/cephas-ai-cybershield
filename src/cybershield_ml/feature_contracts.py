"""Versioned, product-scoped feature contracts for CEPHAS ESIP."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contracts import TrustedProductScope

FeatureValueType = Literal["count", "bytes", "ratio", "duration_ms", "score", "boolean"]
Aggregation = Literal[
    "count", "sum", "mean", "maximum", "minimum", "distinct_count", "ratio", "last"
]
MissingValuePolicy = Literal["zero", "omit", "quarantine", "not_applicable"]
QualityStatus = Literal["accepted", "quarantined"]


class FeatureDefinition(BaseModel):
    """Governed feature metadata; semantics belong to a product-owned definition."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    feature_set_version: str = Field(default="1.0.0", min_length=1, max_length=64)
    feature_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    product_id: str = Field(min_length=1, max_length=96)
    description: str = Field(min_length=8, max_length=512)
    value_type: FeatureValueType
    unit: str = Field(min_length=1, max_length=32)
    aggregation: Aggregation
    window_seconds: int = Field(ge=1, le=86400)
    source_event_types: frozenset[str] = Field(min_length=1)
    missing_value_policy: MissingValuePolicy
    minimum: float | None = None
    maximum: float | None = None

    @model_validator(mode="after")
    def validate_bounds(self):
        for name, bound in (("minimum", self.minimum), ("maximum", self.maximum)):
            if bound is not None and not math.isfinite(bound):
                raise ValueError(f"{name} must be finite")
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("minimum cannot exceed maximum")
        return self


class FeatureVector(BaseModel):
    """One bounded feature window, with all isolation dimensions carried forward."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    tenant_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=64)
    product_id: str = Field(min_length=1, max_length=96)
    business_unit_id: str | None = Field(default=None, max_length=128)
    entity_type: str = Field(min_length=1, max_length=64)
    entity_id: str = Field(min_length=1, max_length=256)
    feature_set_version: str = Field(min_length=1, max_length=64)
    window_start: datetime
    window_end: datetime
    source_event_count: int = Field(ge=1)
    features: dict[str, int | float | bool | None]
    quality_status: QualityStatus = "accepted"

    @field_validator("window_start", "window_end")
    @classmethod
    def normalize_window_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("feature window timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("features")
    @classmethod
    def validate_finite_feature_values(cls, values):
        for feature_id, value in values.items():
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError(f"feature {feature_id!r} must be finite")
        return values

    @model_validator(mode="after")
    def validate_window(self):
        if self.window_start >= self.window_end:
            raise ValueError("window_start must be earlier than window_end")
        return self


def validate_feature_vector(
    vector: FeatureVector,
    trusted_scope: TrustedProductScope,
    definitions: dict[str, FeatureDefinition],
) -> FeatureVector:
    """Validate scope, feature ownership, value types and missing-value policy."""
    if vector.tenant_id != trusted_scope.tenant_id:
        raise ValueError("feature tenant is outside the authenticated scope")
    if vector.deployment_id != trusted_scope.deployment_id:
        raise ValueError("feature deployment is outside the authenticated scope")
    if vector.environment != trusted_scope.environment:
        raise ValueError("feature environment is outside the authenticated scope")
    if vector.product_id not in trusted_scope.allowed_products:
        raise ValueError("feature product is not authorised for this deployment")
    if vector.business_unit_id != trusted_scope.business_unit_id:
        raise ValueError("feature business unit is outside the authenticated scope")

    unknown = set(vector.features) - set(definitions)
    if unknown:
        raise ValueError(f"undefined features are not accepted: {sorted(unknown)}")
    foreign = [
        feature_id
        for feature_id in vector.features
        if definitions[feature_id].product_id != vector.product_id
    ]
    if foreign:
        raise ValueError(f"features are owned by another product: {sorted(foreign)}")

    window_seconds = int((vector.window_end - vector.window_start).total_seconds())
    missing_quarantine_features = []
    for feature_id, definition in definitions.items():
        if definition.product_id != vector.product_id:
            continue
        if window_seconds != definition.window_seconds:
            raise ValueError(
                f"feature {feature_id!r} requires a {definition.window_seconds}-second window"
            )
        present = feature_id in vector.features and vector.features[feature_id] is not None
        if not present:
            if definition.missing_value_policy == "zero":
                raise ValueError(f"feature {feature_id!r} must explicitly provide zero")
            if definition.missing_value_policy == "quarantine":
                missing_quarantine_features.append(feature_id)
            continue

        value = vector.features[feature_id]
        if definition.value_type == "boolean":
            if type(value) is not bool:
                raise ValueError(f"feature {feature_id!r} must be boolean")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"feature {feature_id!r} must be numeric")
        if definition.value_type in ("count", "bytes") and (
            type(value) is not int or value < 0
        ):
            raise ValueError(f"feature {feature_id!r} must be a non-negative integer")
        if definition.minimum is not None and value < definition.minimum:
            raise ValueError(f"feature {feature_id!r} is below its minimum")
        if definition.maximum is not None and value > definition.maximum:
            raise ValueError(f"feature {feature_id!r} exceeds its maximum")

    if missing_quarantine_features and vector.quality_status != "quarantined":
        raise ValueError("missing quarantine-policy features require quarantined status")
    return vector
