from datetime import datetime, timezone

import pytest

from cybershield_ml.contracts import TrustedProductScope
from cybershield_ml.detectors import (
    BaselineSnapshot,
    DetectorContext,
    DetectorRegistry,
    DetectorOutcome,
    PeerGroupDetector,
    RobustDeviationDetector,
    ThresholdRule,
    ThresholdRuleDetector,
    run_detectors,
)
from cybershield_ml.feature_contracts import FeatureDefinition, FeatureVector


@pytest.fixture
def scope():
    return TrustedProductScope(
        tenant_id="tenant-a",
        deployment_id="deploy-a",
        environment="test",
        allowed_products=frozenset({"fraudshield"}),
        business_unit_id="bu-a",
    )


@pytest.fixture
def definition():
    return FeatureDefinition(
        feature_id="login_count",
        product_id="fraudshield",
        description="Number of login events in the window",
        value_type="count",
        unit="events",
        aggregation="count",
        window_seconds=300,
        source_event_types=frozenset({"auth.login"}),
        missing_value_policy="zero",
    )


@pytest.fixture
def vector():
    return FeatureVector(
        tenant_id="tenant-a",
        deployment_id="deploy-a",
        environment="test",
        product_id="fraudshield",
        business_unit_id="bu-a",
        entity_type="user",
        entity_id="user-1",
        feature_set_version="1.0.0",
        window_start=datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 11, 9, 10, 5, tzinfo=timezone.utc),
        source_event_count=8,
        features={"login_count": 8},
    )


@pytest.fixture
def context(scope, definition, vector):
    return DetectorContext(
        vector=vector,
        trusted_scope=scope,
        definitions={"login_count": definition},
    )


def test_threshold_rule_emits_explainable_outcome(context):
    detector = ThresholdRuleDetector(
        [ThresholdRule(feature_id="login_count", comparator="gte", threshold=8)]
    )
    (result,) = run_detectors(DetectorRegistry([detector]), context)
    assert result.status == "evaluated"
    assert result.triggered is True
    assert result.feature_id == "login_count"
    assert "threshold=8.0" in result.evidence


def test_threshold_rule_no_match_is_skipped_not_clean(context):
    detector = ThresholdRuleDetector(
        [ThresholdRule(feature_id="login_count", comparator="gt", threshold=8)]
    )
    (result,) = run_detectors(DetectorRegistry([detector]), context)
    assert result.status == "skipped"
    assert result.triggered is None
    assert result.risk_score is None


def test_robust_detector_uses_median_absolute_deviation(context):
    baseline = BaselineSnapshot(
        tenant_id="tenant-a",
        deployment_id="deploy-a",
        environment="test",
        product_id="fraudshield",
        business_unit_id="bu-a",
        feature_id="login_count",
        baseline_kind="entity_history",
        values=(1, 2, 2, 3, 3, 4, 4, 5),
    )
    ctx = context.model_copy(update={"baselines": (baseline,)})
    detector = RobustDeviationDetector(
        baseline_kind="entity_history",
        minimum_samples=5,
        robust_z_threshold=2.0,
    )
    (result,) = run_detectors(DetectorRegistry([detector]), ctx)
    assert result.status == "evaluated"
    assert result.triggered is True
    assert any(item.startswith("robust_z=") for item in result.evidence)


def test_peer_detector_requires_and_uses_explicit_group(context):
    baseline = BaselineSnapshot(
        tenant_id="tenant-a",
        deployment_id="deploy-a",
        environment="test",
        product_id="fraudshield",
        business_unit_id="bu-a",
        feature_id="login_count",
        baseline_kind="peer_group",
        peer_group_id="finance-users",
        values=(1, 2, 2, 3, 3, 4, 4, 5),
    )
    ctx = context.model_copy(update={"baselines": (baseline,)})
    detector = PeerGroupDetector(peer_group_id="finance-users", minimum_samples=5)
    (result,) = run_detectors(DetectorRegistry([detector]), ctx)
    assert result.status == "evaluated"
    assert result.feature_id == "login_count"


def test_peer_group_without_snapshot_is_skipped(context):
    detector = PeerGroupDetector(peer_group_id="finance-users")
    (result,) = run_detectors(DetectorRegistry([detector]), context)
    assert result.status == "skipped"


def test_cross_tenant_baseline_fails_closed(context):
    baseline = BaselineSnapshot(
        tenant_id="tenant-b",
        deployment_id="deploy-a",
        environment="test",
        product_id="fraudshield",
        business_unit_id="bu-a",
        feature_id="login_count",
        baseline_kind="entity_history",
        values=(1, 2, 3, 4, 5),
    )
    ctx = context.model_copy(update={"baselines": (baseline,)})
    detector = RobustDeviationDetector()
    (result,) = run_detectors(DetectorRegistry([detector]), ctx)
    assert result.status == "failed"
    assert result.error_code == "DETECTOR_EXECUTION_FAILED"


def test_duplicate_detector_ids_are_rejected():
    first = ThresholdRuleDetector(
        [ThresholdRule(feature_id="x", comparator="gt", threshold=1)]
    )
    second = ThresholdRuleDetector(
        [ThresholdRule(feature_id="y", comparator="gt", threshold=1)]
    )
    with pytest.raises(ValueError, match="unique"):
        DetectorRegistry([first, second])


def test_detector_exception_is_explicit_failure(context):
    class BrokenDetector:
        detector_id = "test.broken"
        detector_version = "1.0.0"
        detector_kind = "rule"

        def detect(self, _context):
            raise RuntimeError("internal details must not leak")

    (result,) = run_detectors(DetectorRegistry([BrokenDetector()]), context)
    assert result.status == "failed"
    assert result.triggered is None
    assert result.risk_score is None
    assert result.error_code == "DETECTOR_EXECUTION_FAILED"
    assert "internal details" not in result.explanation
