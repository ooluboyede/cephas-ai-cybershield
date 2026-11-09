"""Product-neutral, scope-checked behavioural detector contracts and reference detectors.

This is a synchronous in-process engine. It is not a streaming runtime, graph
engine, supervised model service, or automated response system.
"""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contracts import TrustedProductScope
from .feature_contracts import (
    FeatureDefinition,
    FeatureVector,
    validate_feature_vector,
)

DetectorKind = Literal["rule", "robust_statistics", "peer_group"]
OutcomeStatus = Literal["evaluated", "skipped", "failed"]
BaselineKind = Literal["entity_history", "peer_group"]
Comparator = Literal["gt", "gte", "lt", "lte"]


class DetectorOutcome(BaseModel):
    """Auditable detector result; a failed/skipped detector is never a clean result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    detector_id: str = Field(min_length=1, max_length=128)
    detector_version: str = Field(min_length=1, max_length=64)
    detector_kind: DetectorKind
    status: OutcomeStatus
    triggered: bool | None = None
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    feature_id: str | None = None
    evidence: tuple[str, ...] = ()
    explanation: str = Field(min_length=1, max_length=1024)
    error_code: str | None = None

    @field_validator("risk_score")
    @classmethod
    def finite_risk_score(cls, value):
        if value is not None and not math.isfinite(value):
            raise ValueError("risk_score must be finite")
        return value

    @model_validator(mode="after")
    def status_consistency(self):
        if self.status == "evaluated":
            if self.triggered is None or self.risk_score is None:
                raise ValueError("evaluated outcomes require trigger and risk score")
            if self.error_code is not None:
                raise ValueError("evaluated outcomes cannot contain an error code")
        elif self.triggered is not None or self.risk_score is not None:
            raise ValueError("skipped/failed outcomes cannot imply a risk decision")
        if self.status == "failed" and not self.error_code:
            raise ValueError("failed outcomes require a stable error code")
        return self


class DetectorContext(BaseModel):
    """One validated feature vector and customer-scoped reference baselines."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    vector: FeatureVector
    trusted_scope: TrustedProductScope
    definitions: Mapping[str, FeatureDefinition]
    baselines: tuple[BaselineSnapshot, ...] = ()


class ThresholdRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    feature_id: str = Field(min_length=1, max_length=128)
    comparator: Comparator
    threshold: float
    risk_score: float = Field(default=0.8, ge=0.0, le=1.0)

    @field_validator("threshold")
    @classmethod
    def finite_threshold(cls, value):
        if not math.isfinite(value):
            raise ValueError("threshold must be finite")
        return value


class BaselineSnapshot(BaseModel):
    """Customer-provided reference values; never fetched across tenant/product scopes."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=64)
    product_id: str = Field(min_length=1, max_length=96)
    business_unit_id: str | None = Field(default=None, max_length=128)
    entity_id: str | None = Field(default=None, max_length=256)
    feature_id: str = Field(min_length=1, max_length=128)
    baseline_kind: BaselineKind
    peer_group_id: str | None = Field(default=None, max_length=128)
    values: tuple[float, ...] = Field(min_length=1, max_length=10000)

    @field_validator("values")
    @classmethod
    def finite_values(cls, values):
        if any(not math.isfinite(value) for value in values):
            raise ValueError("baseline values must be finite")
        return values

    @model_validator(mode="after")
    def peer_group_required(self):
        if self.baseline_kind == "peer_group" and not self.peer_group_id:
            raise ValueError("peer-group baselines require peer_group_id")
        if self.baseline_kind == "peer_group" and self.entity_id is not None:
            raise ValueError("peer-group baselines cannot specify entity_id")
        if self.baseline_kind == "entity_history" and self.peer_group_id is not None:
            raise ValueError("entity-history baselines cannot specify peer_group_id")
        if self.baseline_kind == "entity_history" and not self.entity_id:
            raise ValueError("entity-history baselines require entity_id")
        return self


class BehaviouralDetector(Protocol):
    """Common extension point for independently versioned detectors."""

    detector_id: str
    detector_version: str
    detector_kind: DetectorKind

    def detect(self, context: DetectorContext) -> DetectorOutcome:
        """Evaluate one validated feature vector."""
        ...


class ThresholdRuleDetector:
    detector_id = "core.threshold-rules"
    detector_version = "1.0.0"
    detector_kind: DetectorKind = "rule"

    def __init__(self, rules: Sequence[ThresholdRule]):
        self._rules = tuple(rules)
        if not self._rules:
            raise ValueError("at least one threshold rule is required")

    def detect(self, context: DetectorContext) -> DetectorOutcome:
        _validate_context(context)
        matches: list[tuple[ThresholdRule, float]] = []
        for rule in self._rules:
            value = context.vector.features.get(rule.feature_id)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"rule feature {rule.feature_id!r} must be numeric")
            if _compare(float(value), rule.comparator, rule.threshold):
                matches.append((rule, float(value)))
        if not matches:
            return _skipped(self, "No configured threshold rule matched an available feature.")
        rule, value = max(matches, key=lambda item: item[0].risk_score)
        return DetectorOutcome(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_kind=self.detector_kind,
            status="evaluated",
            triggered=True,
            risk_score=rule.risk_score,
            feature_id=rule.feature_id,
            evidence=(
                f"observed={value}",
                f"comparator={rule.comparator}",
                f"threshold={rule.threshold}",
                f"matched_rules={len(matches)}",
            ),
            explanation="A configured product-owned threshold rule matched; this is a triage signal.",
        )


class RobustDeviationDetector:
    """MAD-based deviation against entity history or an explicitly scoped peer group."""

    detector_id = "core.robust-deviation"
    detector_version = "1.0.0"
    detector_kind: DetectorKind = "robust_statistics"

    def __init__(
        self,
        *,
        baseline_kind: BaselineKind = "entity_history",
        minimum_samples: int = 5,
        robust_z_threshold: float = 3.5,
        peer_group_id: str | None = None,
    ):
        if minimum_samples < 3:
            raise ValueError("minimum_samples must be at least 3")
        if not math.isfinite(robust_z_threshold) or robust_z_threshold <= 0:
            raise ValueError("robust_z_threshold must be finite and positive")
        if baseline_kind == "peer_group" and not peer_group_id:
            raise ValueError("peer-group detector requires peer_group_id")
        if baseline_kind == "entity_history" and peer_group_id is not None:
            raise ValueError("entity-history detector cannot specify peer_group_id")
        self.baseline_kind = baseline_kind
        self.minimum_samples = minimum_samples
        self.robust_z_threshold = robust_z_threshold
        self.peer_group_id = peer_group_id

    def detect(self, context: DetectorContext) -> DetectorOutcome:
        _validate_context(context)
        snapshots = [
            item for item in context.baselines
            if item.baseline_kind == self.baseline_kind
            and item.feature_id in context.vector.features
            and (
                self.baseline_kind != "peer_group"
                or item.peer_group_id == self.peer_group_id
            )
        ]
        scoped = [item for item in snapshots if _baseline_matches_scope(item, context)]
        if len(scoped) != len(snapshots):
            raise ValueError("baseline scope does not match authenticated product context")
        candidates = [
            item for item in scoped
            if context.vector.features.get(item.feature_id) is not None
        ]
        if not candidates:
            return _skipped(self, "No matching scoped baseline is available.")
        baseline = candidates[0]
        if len(candidates) > 1:
            raise ValueError("ambiguous baseline snapshots for detector feature scope")
        if len(baseline.values) < self.minimum_samples:
            return _skipped(self, "Baseline sample count is below the configured minimum.")
        observed = context.vector.features[baseline.feature_id]
        if isinstance(observed, bool) or not isinstance(observed, (int, float)):
            raise TypeError("robust deviation feature must be numeric")
        median = _median(baseline.values)
        deviations = [abs(value - median) for value in baseline.values]
        mad = _median(deviations)
        delta = float(observed) - median
        if mad == 0:
            triggered = delta != 0
            robust_z = None
            score = 1.0 if triggered else 0.0
            evidence = (
                f"observed={float(observed)}",
                f"baseline_median={median}",
                "baseline_mad=0",
                "zero_mad_nonmedian_is_outlier=true" if triggered else "observed_equals_median=true",
            )
        else:
            robust_z = 0.67448975 * delta / mad
            triggered = abs(robust_z) >= self.robust_z_threshold
            score = min(abs(robust_z) / self.robust_z_threshold, 1.0)
            evidence = (
                f"observed={float(observed)}",
                f"baseline_median={median}",
                f"baseline_mad={mad}",
                f"robust_z={robust_z}",
                f"configured_threshold={self.robust_z_threshold}",
            )
        return DetectorOutcome(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_kind=self.detector_kind,
            status="evaluated",
            triggered=triggered,
            risk_score=score,
            feature_id=baseline.feature_id,
            evidence=evidence,
            explanation=(
                "Deviation was measured against a customer-scoped robust baseline; "
                "it does not establish malicious activity."
            ),
        )


class PeerGroupDetector(RobustDeviationDetector):
    """Explicit peer-group variant; group membership and baseline creation are customer-owned."""

    detector_id = "core.peer-group-deviation"
    detector_version = "1.0.0"
    detector_kind: DetectorKind = "peer_group"

    def __init__(
        self,
        *,
        peer_group_id: str,
        minimum_samples: int = 5,
        robust_z_threshold: float = 3.5,
    ):
        super().__init__(
            baseline_kind="peer_group",
            minimum_samples=minimum_samples,
            robust_z_threshold=robust_z_threshold,
            peer_group_id=peer_group_id,
        )


class DetectorRegistry:
    """Deterministic registry; duplicate detector IDs are rejected."""

    def __init__(self, detectors: Sequence[BehaviouralDetector]):
        self._detectors = tuple(detectors)
        ids = [item.detector_id for item in self._detectors]
        if len(ids) != len(set(ids)):
            raise ValueError("detector IDs must be unique")
        if not self._detectors:
            raise ValueError("at least one detector is required")

    @property
    def detectors(self) -> tuple[BehaviouralDetector, ...]:
        return self._detectors


def run_detectors(
    registry: DetectorRegistry,
    context: DetectorContext,
) -> tuple[DetectorOutcome, ...]:
    """Run detectors independently; failures are explicit, never treated as no-alert."""
    _validate_context(context)
    outcomes: list[DetectorOutcome] = []
    for detector in registry.detectors:
        try:
            outcome = detector.detect(context)
            if outcome.detector_id != detector.detector_id:
                raise ValueError("detector returned an outcome with a mismatched ID")
            outcomes.append(outcome)
        except Exception:  # noqa: BLE001 - isolate untrusted detector implementations
            outcomes.append(
                DetectorOutcome(
                    detector_id=detector.detector_id,
                    detector_version=detector.detector_version,
                    detector_kind=detector.detector_kind,
                    status="failed",
                    explanation="Detector execution failed; this detector produced no risk decision.",
                    error_code="DETECTOR_EXECUTION_FAILED",
                )
            )
    return tuple(outcomes)


def _validate_context(context: DetectorContext) -> None:
    validate_feature_vector(
        context.vector,
        context.trusted_scope,
        dict(context.definitions),
    )


def _baseline_matches_scope(
    baseline: BaselineSnapshot,
    context: DetectorContext,
) -> bool:
    vector = context.vector
    return (
        baseline.tenant_id == context.trusted_scope.tenant_id
        and baseline.deployment_id == context.trusted_scope.deployment_id
        and baseline.environment == context.trusted_scope.environment
        and baseline.product_id == vector.product_id
        and baseline.business_unit_id == vector.business_unit_id
        and (
            baseline.baseline_kind != "entity_history"
            or baseline.entity_id == vector.entity_id
        )
    )


def _compare(value: float, comparator: Comparator, threshold: float) -> bool:
    return {
        "gt": value > threshold,
        "gte": value >= threshold,
        "lt": value < threshold,
        "lte": value <= threshold,
    }[comparator]


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (float(ordered[middle - 1]) + float(ordered[middle])) / 2.0


def _skipped(detector: BehaviouralDetector, explanation: str) -> DetectorOutcome:
    return DetectorOutcome(
        detector_id=detector.detector_id,
        detector_version=detector.detector_version,
        detector_kind=detector.detector_kind,
        status="skipped",
        explanation=explanation,
    )
