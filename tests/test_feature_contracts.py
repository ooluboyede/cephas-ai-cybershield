from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from cybershield_ml.contracts import TrustedProductScope
from cybershield_ml.feature_contracts import (
    FeatureDefinition,
    FeatureVector,
    validate_feature_vector,
)


def definition(**overrides):
    payload = {
        "feature_id": "auth.failure_ratio",
        "product_id": "BankFlow",
        "description": "Ratio of failed authentication attempts in a window",
        "value_type": "ratio",
        "unit": "ratio",
        "aggregation": "ratio",
        "window_seconds": 300,
        "source_event_types": {"authentication.failure", "authentication.success"},
        "missing_value_policy": "quarantine",
        "minimum": 0.0,
        "maximum": 1.0,
    }
    payload.update(overrides)
    return FeatureDefinition(**payload)


def vector(**overrides):
    payload = {
        "tenant_id": "tenant-a",
        "deployment_id": "prod-west",
        "environment": "production",
        "product_id": "BankFlow",
        "business_unit_id": "payments",
        "entity_type": "user",
        "entity_id": "user-123",
        "feature_set_version": "bankflow-auth-v1",
        "window_start": datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc),
        "window_end": datetime(2026, 11, 9, 10, 5, tzinfo=timezone.utc),
        "source_event_count": 5,
        "features": {"auth.failure_ratio": 0.4},
    }
    payload.update(overrides)
    return FeatureVector(**payload)


def scope(**overrides):
    payload = {
        "tenant_id": "tenant-a",
        "deployment_id": "prod-west",
        "environment": "production",
        "allowed_products": {"BankFlow", "FraudShield"},
        "business_unit_id": "payments",
    }
    payload.update(overrides)
    return TrustedProductScope(**payload)


def test_accepts_valid_product_owned_feature_vector():
    value = vector()
    assert validate_feature_vector(
        value, scope(), {"auth.failure_ratio": definition()}
    ) == value


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"tenant_id": "tenant-b"}, "tenant"),
        ({"deployment_id": "staging"}, "deployment"),
        ({"environment": "development"}, "environment"),
        ({"product_id": "FraudShield"}, "product"),
        ({"business_unit_id": "treasury"}, "business unit"),
    ],
)
def test_rejects_scope_substitution(change, message):
    with pytest.raises(ValueError, match=message):
        validate_feature_vector(
            vector(**change), scope(), {"auth.failure_ratio": definition()}
        )


def test_rejects_feature_owned_by_another_product():
    with pytest.raises(ValueError, match="undefined features"):
        validate_feature_vector(
            vector(features={"fraudshield.device_novelty": 1.0}),
            scope(),
            {"auth.failure_ratio": definition()},
        )



def test_rejects_feature_definition_owned_by_another_product():
    foreign_definition = definition(
        feature_id="fraudshield.device_novelty", product_id="FraudShield"
    )
    with pytest.raises(ValueError, match="owned by another product"):
        validate_feature_vector(
            vector(features={"fraudshield.device_novelty": 1.0}),
            scope(),
            {"fraudshield.device_novelty": foreign_definition},
        )

def test_missing_quarantine_feature_requires_quarantined_vector():
    with pytest.raises(ValueError, match="quarantined status"):
        validate_feature_vector(
            vector(features={}), scope(), {"auth.failure_ratio": definition()}
        )
    quarantined = vector(features={}, quality_status="quarantined")
    assert validate_feature_vector(
        quarantined, scope(), {"auth.failure_ratio": definition()}
    ) == quarantined


def test_zero_policy_requires_explicit_zero_not_silent_missing():
    zero_definition = definition(missing_value_policy="zero")
    with pytest.raises(ValueError, match="explicitly provide zero"):
        validate_feature_vector(
            vector(features={}), scope(), {"auth.failure_ratio": zero_definition}
        )
    valid = vector(features={"auth.failure_ratio": 0.0})
    assert validate_feature_vector(
        valid, scope(), {"auth.failure_ratio": zero_definition}
    ) == valid


def test_rejects_out_of_range_and_non_finite_values():
    with pytest.raises(ValueError, match="exceeds its maximum"):
        validate_feature_vector(
            vector(features={"auth.failure_ratio": 1.1}),
            scope(),
            {"auth.failure_ratio": definition()},
        )
    with pytest.raises(ValidationError):
        vector(features={"auth.failure_ratio": float("nan")})


def test_rejects_invalid_time_window():
    with pytest.raises(ValidationError, match="window_start"):
        vector(
            window_start=datetime(2026, 11, 9, 10, 5, tzinfo=timezone.utc),
            window_end=datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc),
        )
    with pytest.raises(ValidationError, match="timezone"):
        vector(window_start=datetime(2026, 11, 9, 10, 0))
