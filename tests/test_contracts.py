from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from cybershield_ml.contracts import (
    SecurityTelemetryEvent,
    TrustedProductScope,
    event_fingerprint,
    validate_event_scope,
)


def event(**overrides):
    payload = {
        "event_id": "evt-001",
        "tenant_id": "tenant-a",
        "deployment_id": "prod-west",
        "product_id": "BankFlow",
        "environment": "production",
        "business_unit_id": "payments",
        "entity_type": "user",
        "entity_id": "user-123",
        "event_type": "authentication.failure",
        "event_time": datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc),
        "ingested_at": datetime(2026, 11, 9, 10, 0, 2, tzinfo=timezone.utc),
        "source_system": "bankflow-api",
        "source_version": "2.4.0",
        "source_event_id": "src-77",
        "clock_quality": "verified",
        "data_classification": "confidential",
        "attributes": {"failure_reason": "invalid_credential", "risk_count": 3},
    }
    payload.update(overrides)
    return SecurityTelemetryEvent(**payload)


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


def test_canonical_event_normalizes_timestamps_to_utc():
    value = event()
    assert value.event_time.tzinfo == timezone.utc
    assert value.ingested_at.tzinfo == timezone.utc
    assert value.schema_version == "1.0.0"


def test_event_rejects_naive_timestamps_and_unknown_fields():
    with pytest.raises(ValidationError):
        event(event_time=datetime(2026, 11, 9, 10, 0))
    with pytest.raises(ValidationError):
        event(unreviewed_field="must-not-be-accepted")


def test_event_rejects_non_finite_attribute_values():
    with pytest.raises(ValidationError):
        event(attributes={"score": float("nan")})


def test_event_scope_accepts_authorized_product():
    assert validate_event_scope(event(), scope()).product_id == "BankFlow"
    second_product = event(product_id="FraudShield")
    assert validate_event_scope(second_product, scope()).product_id == "FraudShield"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"tenant_id": "tenant-b"}, "tenant"),
        ({"deployment_id": "staging"}, "deployment"),
        ({"environment": "development"}, "environment"),
        ({"product_id": "PayrollShield"}, "product"),
        ({"business_unit_id": "treasury"}, "business unit"),
    ],
)
def test_event_scope_rejects_untrusted_scope_substitution(change, message):
    with pytest.raises(ValueError, match=message):
        validate_event_scope(event(**change), scope())


def test_event_fingerprint_is_deterministic_and_scope_bound():
    first = event()
    assert event_fingerprint(first) == event_fingerprint(event())
    assert event_fingerprint(first) != event_fingerprint(
        event(product_id="FraudShield")
    )
