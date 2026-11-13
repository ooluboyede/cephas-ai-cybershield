from datetime import datetime, timedelta, timezone

import pytest

from cybershield_ml.contracts import TrustedProductScope
from cybershield_ml.device_intelligence import (
    DeviceFraudAssociation,
    DeviceRiskContext,
    DeviceRiskPolicy,
    recommend_device_action,
    record_device_risk_review,
)

NOW = datetime(2026, 11, 13, 8, 0, tzinfo=timezone.utc)
DEVICE = "hmac-sha256:v1:" + "a" * 64


@pytest.fixture
def scope():
    return TrustedProductScope(
        tenant_id="tenant-a",
        deployment_id="deployment-a",
        environment="test",
        allowed_products=frozenset({"cybershield"}),
        business_unit_id="bu-a",
    )


def association(
    *,
    case_id="case-1",
    status="confirmed",
    evidence_ref="evidence-1",
    tenant_id="tenant-a",
    occurred_at=None,
):
    return DeviceFraudAssociation(
        tenant_id=tenant_id,
        deployment_id="deployment-a",
        environment="test",
        product_id="cybershield",
        business_unit_id="bu-a",
        device_key=DEVICE,
        case_id=case_id,
        association_status=status,
        evidence_ref=evidence_ref,
        occurred_at=occurred_at or NOW - timedelta(days=1),
    )


def context(scope, associations):
    return DeviceRiskContext(
        trusted_scope=scope,
        product_id="cybershield",
        device_key=DEVICE,
        associations=tuple(associations),
        evaluated_at=NOW,
    )


def test_repeated_confirmed_fraud_recommends_block_for_human_review(scope):
    result = recommend_device_action(
        context(
            scope,
            [
                association(case_id="case-1", evidence_ref="evidence-1"),
                association(case_id="case-2", evidence_ref="evidence-2"),
            ],
        )
    )
    assert result.action == "block_recommended"
    assert result.status == "pending_human_review"
    assert result.confirmed_case_count == 2
    assert result.enforcement_executed is False


def test_suspected_associations_only_flag_not_block(scope):
    result = recommend_device_action(
        context(scope, [association(status="suspected")])
    )
    assert result.action == "flag"
    assert result.confirmed_case_count == 0
    assert result.enforcement_executed is False


def test_single_confirmed_case_recommends_investigation(scope):
    result = recommend_device_action(
        context(scope, [association()])
    )
    assert result.action == "investigate"


def test_cross_tenant_association_fails_closed(scope):
    with pytest.raises(ValueError, match="outside the authenticated scope"):
        recommend_device_action(
            context(scope, [association(tenant_id="tenant-b")])
        )


def test_duplicate_case_association_is_rejected(scope):
    with pytest.raises(ValueError, match="duplicate case"):
        recommend_device_action(
            context(
                scope,
                [
                    association(case_id="same-case", evidence_ref="evidence-1"),
                    association(case_id="same-case", evidence_ref="evidence-2"),
                ],
            )
        )


def test_old_association_is_outside_lookback(scope):
    result = recommend_device_action(
        context(
            scope,
            [association(occurred_at=NOW - timedelta(days=120))],
        ),
        DeviceRiskPolicy(lookback_days=90),
    )
    assert result.action == "monitor"


def test_human_approval_records_decision_but_does_not_execute_block(scope):
    result = recommend_device_action(
        context(
            scope,
            [
                association(case_id="case-1", evidence_ref="evidence-1"),
                association(case_id="case-2", evidence_ref="evidence-2"),
            ],
        )
    )
    review = record_device_risk_review(
        result,
        reviewer_id="reviewer-1",
        decision="approve",
        rationale="Two independently evidenced confirmed fraud cases.",
        reviewed_at=NOW,
    )
    assert review.approved_action == "block"
    assert review.enforcement_executed is False


def test_non_block_recommendation_cannot_be_approved_for_block(scope):
    result = recommend_device_action(
        context(scope, [association(status="suspected")])
    )
    with pytest.raises(ValueError, match="only a block recommendation"):
        record_device_risk_review(
            result,
            reviewer_id="reviewer-1",
            decision="approve",
            rationale="Reviewed suspected activity.",
            reviewed_at=NOW,
        )


def test_device_key_must_be_pseudonymous_hmac():
    with pytest.raises(ValueError):
        DeviceFraudAssociation(
            tenant_id="tenant-a",
            deployment_id="deployment-a",
            environment="test",
            product_id="cybershield",
            business_unit_id="bu-a",
            device_key="raw-device-id-123",
            case_id="case-1",
            association_status="confirmed",
            evidence_ref="evidence-1",
            occurred_at=NOW,
        )
