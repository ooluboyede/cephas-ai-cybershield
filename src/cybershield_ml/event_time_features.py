"""Deterministic, bounded event-time aggregation for the shared CEPHAS feature platform.

This module is a pure batch processor. Durable replay protection, watermarks,
stream checkpoints and distributed exactly-once delivery require a customer-
operated stateful backend and are deliberately not claimed here.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping

from .contracts import (
    SecurityTelemetryEvent,
    TrustedProductScope,
    event_fingerprint,
    validate_event_scope,
)
from .event_quality import EventQualityPolicy, assess_event_quality
from .feature_contracts import (
    FeatureDefinition,
    FeatureVector,
    validate_feature_vector,
)


@dataclass(frozen=True)
class EventTimeFeatureBatch:
    """Deterministic batch output plus explicit exclusions and delivery metadata."""

    vectors: tuple[FeatureVector, ...]
    duplicate_event_count: int
    buffered_event_ids: tuple[str, ...]
    uncertain_event_ids: tuple[str, ...]


def aggregate_event_time_features(
    events: list[SecurityTelemetryEvent],
    *,
    trusted_scope: TrustedProductScope,
    definitions: Mapping[str, FeatureDefinition],
    source_attributes: Mapping[str, str] | None = None,
    event_classes: Mapping[str, str] | None = None,
    offline_event_ids: frozenset[str] = frozenset(),
    quality_policy: EventQualityPolicy | None = None,
) -> EventTimeFeatureBatch:
    """Deduplicate, quality-gate and aggregate canonical events into UTC windows.

    Event IDs are deduplicated within (tenant, deployment, product, source system).
    Exact replays are ignored; conflicting replays fail closed. Event-time, not
    ingestion-time, determines the half-open feature window [start, end).
    """
    source_attributes = source_attributes or {}
    event_classes = event_classes or {}
    quality_policy = quality_policy or EventQualityPolicy()
    unique: dict[tuple[str, str, str, str, str], SecurityTelemetryEvent] = {}
    fingerprints: dict[tuple[str, str, str, str, str], str] = {}
    duplicate_count = 0

    for event in events:
        validate_event_scope(event, trusted_scope)
        key = (
            event.tenant_id,
            event.deployment_id,
            event.product_id,
            event.source_system,
            event.event_id,
        )
        fingerprint = event_fingerprint(event)
        if key in unique:
            if fingerprints[key] != fingerprint:
                raise ValueError(
                    "conflicting replay for event_id "
                    f"{event.event_id!r} in source {event.source_system!r}"
                )
            duplicate_count += 1
            continue
        unique[key] = event
        fingerprints[key] = fingerprint

    products = {event.product_id for event in unique.values()}
    product_definitions: dict[str, list[FeatureDefinition]] = defaultdict(list)
    for definition in definitions.values():
        product_definitions[definition.product_id].append(definition)
    for product in products:
        if product not in trusted_scope.allowed_products:
            raise ValueError("event product is not authorised for this deployment")
        if not product_definitions.get(product):
            raise ValueError(f"no feature definitions registered for product {product!r}")
        windows = {item.window_seconds for item in product_definitions[product]}
        versions = {item.feature_set_version for item in product_definitions[product]}
        if len(windows) != 1:
            raise ValueError("one aggregation batch requires one window size per product")
        if len(versions) != 1:
            raise ValueError("one aggregation batch requires one feature-set version per product")

    accepted: dict[tuple, list[SecurityTelemetryEvent]] = defaultdict(list)
    uncertain_groups: set[tuple] = set()
    buffered_ids: list[str] = []
    uncertain_ids: list[str] = []

    for event in unique.values():
        definitions_for_product = product_definitions[event.product_id]
        window_seconds = definitions_for_product[0].window_seconds
        window_start = _window_start(event.event_time, window_seconds)
        group_key = _group_key(event, window_start)
        event_class = event_classes.get(
            event.event_type,
            "authentication" if event.event_type.startswith(("auth", "authentication"))
            else "telemetry",
        )
        if event_class not in {"authentication", "control_plane", "telemetry"}:
            raise ValueError(f"unsupported event class for {event.event_type!r}")
        quality = assess_event_quality(
            event,
            event_class=event_class,
            policy=quality_policy,
            offline_delivery=event.event_id in offline_event_ids,
        )
        if quality.disposition == "uncertain":
            uncertain_ids.append(event.event_id)
            uncertain_groups.add(group_key)
            continue
        if quality.disposition == "buffered_offline_delivery":
            buffered_ids.append(event.event_id)
        accepted[group_key].append(event)

    vectors: list[FeatureVector] = []
    for group_key in sorted(accepted, key=_sort_group_key):
        group_events = sorted(
            accepted[group_key],
            key=lambda item: (item.event_time, item.source_system, item.event_id),
        )
        first = group_events[0]
        window_seconds = product_definitions[first.product_id][0].window_seconds
        window_start = _window_start(first.event_time, window_seconds)
        window_end = window_start + timedelta(seconds=window_seconds)
        values: dict[str, int | float | bool | None] = {}
        missing_quarantine = False

        for definition in sorted(
            product_definitions[first.product_id], key=lambda item: item.feature_id
        ):
            matching = [
                event for event in group_events
                if event.event_type in definition.source_event_types
            ]
            attribute = source_attributes.get(definition.feature_id)
            value = _aggregate_one(definition, matching, attribute)
            if value is None:
                if definition.missing_value_policy == "zero":
                    value = 0
                elif definition.missing_value_policy == "quarantine":
                    missing_quarantine = True
                elif definition.missing_value_policy == "not_applicable":
                    value = None
            if value is not None:
                values[definition.feature_id] = value

        quarantined = missing_quarantine or group_key in uncertain_groups
        vector = FeatureVector(
            tenant_id=first.tenant_id,
            deployment_id=first.deployment_id,
            environment=first.environment,
            product_id=first.product_id,
            business_unit_id=first.business_unit_id,
            entity_type=first.entity_type,
            entity_id=first.entity_id,
            feature_set_version=product_definitions[first.product_id][0].feature_set_version,
            window_start=window_start,
            window_end=window_end,
            source_event_count=len(group_events),
            features=values,
            quality_status="quarantined" if quarantined else "accepted",
        )
        validate_feature_vector(
            vector,
            trusted_scope,
            {item.feature_id: item for item in product_definitions[first.product_id]},
        )
        vectors.append(vector)

    return EventTimeFeatureBatch(
        vectors=tuple(vectors),
        duplicate_event_count=duplicate_count,
        buffered_event_ids=tuple(sorted(buffered_ids)),
        uncertain_event_ids=tuple(sorted(uncertain_ids)),
    )


def _aggregate_one(
    definition: FeatureDefinition,
    events: list[SecurityTelemetryEvent],
    source_attribute: str | None,
) -> int | float | bool | None:
    if definition.aggregation == "count":
        return len(events)
    if not events:
        return None
    if not source_attribute:
        raise ValueError(
            f"feature {definition.feature_id!r} requires a source attribute"
        )
    values = [
        event.attributes[source_attribute]
        for event in events
        if source_attribute in event.attributes and event.attributes[source_attribute] is not None
    ]
    if not values:
        return None
    if definition.aggregation == "distinct_count":
        return len({str(value) for value in values})
    if definition.aggregation == "ratio":
        if any(type(value) is not bool for value in values):
            raise TypeError("ratio source attributes must be boolean")
        return sum(values) / len(values)
    if definition.aggregation == "last":
        value = values[-1]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("last aggregation requires numeric source attributes")
        return value
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in values):
        raise TypeError(f"{definition.aggregation} requires numeric source attributes")
    if definition.aggregation == "sum":
        return sum(values)
    if definition.aggregation == "mean":
        return sum(values) / len(values)
    if definition.aggregation == "maximum":
        return max(values)
    if definition.aggregation == "minimum":
        return min(values)
    raise ValueError(f"unsupported aggregation {definition.aggregation!r}")


def _window_start(value: datetime, window_seconds: int) -> datetime:
    timestamp = value.astimezone(timezone.utc).timestamp()
    start = int(timestamp // window_seconds) * window_seconds
    return datetime.fromtimestamp(start, tz=timezone.utc)


def _group_key(event: SecurityTelemetryEvent, window_start: datetime) -> tuple:
    return (
        event.tenant_id,
        event.deployment_id,
        event.environment,
        event.product_id,
        event.business_unit_id or "",
        event.entity_type,
        event.entity_id,
        window_start,
    )


def _sort_group_key(value: tuple) -> tuple:
    return (*value[:-1], value[-1].isoformat())
