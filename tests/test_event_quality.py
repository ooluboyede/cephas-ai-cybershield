from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from cybershield_ml.contracts import SecurityTelemetryEvent
from cybershield_ml.event_quality import EventQualityPolicy, assess_event_quality


def event(**overrides):
    payload = {
        "event_id": "evt-clock-1",
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
        "clock_quality": "verified",
        "measured_clock_offset_seconds": 10.0,
    }
    payload.update(overrides)
    return SecurityTelemetryEvent(**payload)


def test_authentication_uses_sixty_second_clock_skew_limit():
    result = assess_event_quality(
        event(measured_clock_offset_seconds=61),
        event_class="authentication",
        policy=EventQualityPolicy(),
    )
    assert result.disposition == "uncertain"
    assert result.max_allowed_clock_skew_seconds == 60
    assert "measured_clock_skew_exceeds_policy" in result.reasons


def test_control_plane_uses_three_hundred_second_clock_skew_limit():
    result = assess_event_quality(
        event(measured_clock_offset_seconds=301),
        event_class="control_plane",
        policy=EventQualityPolicy(),
    )
    assert result.disposition == "uncertain"
    assert result.max_allowed_clock_skew_seconds == 300


def test_verified_telemetry_within_skew_is_accepted():
    result = assess_event_quality(
        event(), event_class="telemetry", policy=EventQualityPolicy()
    )
    assert result.disposition == "accepted"


def test_unknown_clock_quality_is_uncertain_not_silently_accepted():
    result = assess_event_quality(
        event(clock_quality="unknown", measured_clock_offset_seconds=None),
        event_class="telemetry",
        policy=EventQualityPolicy(),
    )
    assert result.disposition == "uncertain"
    assert "clock_offset_not_verified" in result.reasons


def test_delayed_offline_event_is_buffered_not_dropped():
    result = assess_event_quality(
        event(ingested_at=datetime(2026, 11, 9, 10, 20, tzinfo=timezone.utc)),
        event_class="telemetry",
        policy=EventQualityPolicy(),
        offline_delivery=True,
    )
    assert result.disposition == "buffered_offline_delivery"
    assert "customer_buffered_offline_delivery" in result.reasons


def test_excessive_skew_takes_precedence_over_offline_buffering():
    result = assess_event_quality(
        event(
            measured_clock_offset_seconds=400,
            ingested_at=datetime(2026, 11, 9, 10, 20, tzinfo=timezone.utc),
        ),
        event_class="telemetry",
        policy=EventQualityPolicy(),
        offline_delivery=True,
    )
    assert result.disposition == "uncertain"


def test_future_event_timestamp_is_uncertain():
    result = assess_event_quality(
        event(
            event_time=datetime(2026, 11, 9, 10, 1, tzinfo=timezone.utc),
            ingested_at=datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc),
        ),
        event_class="telemetry",
        policy=EventQualityPolicy(),
    )
    assert result.disposition == "uncertain"
    assert "event_time_is_after_ingestion_time" in result.reasons


def test_policy_rejects_non_finite_thresholds():
    with pytest.raises(ValidationError):
        EventQualityPolicy(telemetry_max_clock_skew_seconds=float("nan"))
