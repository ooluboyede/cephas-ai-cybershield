from datetime import datetime, timedelta, timezone

import pytest
from cybershield_ml.contracts import SecurityTelemetryEvent, TrustedProductScope
from cybershield_ml.event_quality import EventQualityPolicy
from cybershield_ml.event_time_features import aggregate_event_time_features
from cybershield_ml.feature_contracts import FeatureDefinition


BASE = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)


def scope():
    return TrustedProductScope(
        tenant_id="tenant-a",
        deployment_id="bank-prod",
        environment="production",
        allowed_products={"BankFlow"},
        business_unit_id="payments",
    )


def event(
    event_id,
    *,
    event_time=None,
    ingested_at=None,
    source_system="identity",
    attributes=None,
    event_type="auth.failure",
    clock_quality="verified",
    offset=0.0,
    tenant_id="tenant-a",
):
    timestamp = event_time or BASE
    return SecurityTelemetryEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        deployment_id="bank-prod",
        product_id="BankFlow",
        environment="production",
        business_unit_id="payments",
        entity_type="user",
        entity_id="user-17",
        event_type=event_type,
        event_time=timestamp,
        ingested_at=ingested_at or timestamp + timedelta(seconds=2),
        source_system=source_system,
        source_version="2.1",
        clock_quality=clock_quality,
        measured_clock_offset_seconds=offset,
        attributes=attributes or {},
    )


def definitions():
    return {
        "bankflow.auth.failures": FeatureDefinition(
            feature_id="bankflow.auth.failures",
            product_id="BankFlow",
            feature_set_version="bankflow-auth-v1",
            description="Authentication failure count in a five minute window",
            value_type="count",
            unit="events",
            aggregation="count",
            window_seconds=300,
            source_event_types={"auth.failure"},
            missing_value_policy="zero",
        ),
        "bankflow.auth.failure_ratio": FeatureDefinition(
            feature_id="bankflow.auth.failure_ratio",
            product_id="BankFlow",
            feature_set_version="bankflow-auth-v1",
            description="Ratio of failed authentication attempts in a window",
            value_type="ratio",
            unit="ratio",
            aggregation="ratio",
            window_seconds=300,
            source_event_types={"auth.failure", "auth.success"},
            missing_value_policy="quarantine",
            minimum=0.0,
            maximum=1.0,
        ),
    }


def aggregate(events, **kwargs):
    return aggregate_event_time_features(
        events,
        trusted_scope=scope(),
        definitions=definitions(),
        source_attributes={"bankflow.auth.failure_ratio": "failed"},
        quality_policy=EventQualityPolicy(),
        **kwargs,
    )


def test_uses_event_time_and_half_open_utc_windows():
    events = [
        event("late", event_time=BASE + timedelta(minutes=4, seconds=59),
              attributes={"failed": True}),
        event("early", event_time=BASE + timedelta(seconds=1),
              attributes={"failed": False}),
        event("boundary", event_time=BASE + timedelta(minutes=5),
              attributes={"failed": True}),
    ]
    result = aggregate(events)
    assert len(result.vectors) == 2
    first, second = result.vectors
    assert first.window_start == BASE
    assert first.window_end == BASE + timedelta(minutes=5)
    assert first.source_event_count == 2
    assert first.features["bankflow.auth.failures"] == 2
    assert first.features["bankflow.auth.failure_ratio"] == 0.5
    assert second.window_start == BASE + timedelta(minutes=5)
    assert second.source_event_count == 1


def test_out_of_order_arrival_produces_identical_output():
    events = [
        event("a", event_time=BASE + timedelta(minutes=3), attributes={"failed": True}),
        event("b", event_time=BASE + timedelta(seconds=10), attributes={"failed": False}),
    ]
    forward = aggregate(events)
    reverse = aggregate(list(reversed(events)))
    assert forward.vectors == reverse.vectors


def test_exact_replay_is_ignored_and_counted():
    original = event("same", attributes={"failed": True})
    result = aggregate([original, original])
    assert result.duplicate_event_count == 1
    assert result.vectors[0].source_event_count == 1


def test_conflicting_replay_fails_closed():
    original = event("same", attributes={"failed": True})
    altered = event("same", attributes={"failed": False})
    with pytest.raises(ValueError, match="conflicting replay"):
        aggregate([original, altered])


def test_event_ids_are_namespaced_by_source_system():
    first = event("same", source_system="identity", attributes={"failed": True})
    second = event("same", source_system="vpn", attributes={"failed": False})
    result = aggregate([first, second])
    assert result.duplicate_event_count == 0
    assert result.vectors[0].source_event_count == 2


def test_tenant_substitution_is_rejected():
    with pytest.raises(ValueError, match="tenant"):
        aggregate([event("foreign", tenant_id="tenant-b", attributes={"failed": True})])


def test_unknown_clock_event_is_excluded_and_quarantines_mixed_window():
    trusted = event("trusted", attributes={"failed": True})
    uncertain = event(
        "uncertain",
        attributes={"failed": False},
        clock_quality="unknown",
        offset=None,
    )
    result = aggregate([trusted, uncertain])
    assert result.uncertain_event_ids == ("uncertain",)
    assert len(result.vectors) == 1
    assert result.vectors[0].quality_status == "quarantined"


def test_delayed_offline_event_is_buffered_but_retained():
    delayed = event(
        "offline",
        attributes={"failed": True},
        ingested_at=BASE + timedelta(minutes=12),
    )
    result = aggregate([delayed], offline_event_ids=frozenset({"offline"}))
    assert result.buffered_event_ids == ("offline",)
    assert result.vectors[0].source_event_count == 1
    assert result.vectors[0].quality_status == "accepted"


def test_clock_skew_beyond_authentication_policy_is_quarantined():
    trusted = event("trusted", attributes={"failed": True})
    skewed = event(
        "skewed",
        attributes={"failed": False},
        offset=61.0,
    )
    result = aggregate([trusted, skewed])
    assert result.uncertain_event_ids == ("skewed",)
    assert result.vectors[0].quality_status == "quarantined"


def test_numeric_aggregation_requires_explicit_source_attribute():
    invalid = FeatureDefinition(
        feature_id="bankflow.auth.byte_sum",
        product_id="BankFlow",
        description="Sum of outbound bytes over five minutes",
        value_type="bytes",
        unit="bytes",
        aggregation="sum",
        window_seconds=300,
        source_event_types={"auth.failure"},
        missing_value_policy="omit",
    )
    with pytest.raises(ValueError, match="requires a source attribute"):
        aggregate_event_time_features(
            [event("a", attributes={"failed": True})],
            trusted_scope=scope(),
            definitions={"bankflow.auth.byte_sum": invalid},
            quality_policy=EventQualityPolicy(),
        )
