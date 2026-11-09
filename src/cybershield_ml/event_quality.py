"""Clock-quality and offline-delivery decisions for shared CEPHAS telemetry."""

from __future__ import annotations

import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .contracts import SecurityTelemetryEvent

EventClass = Literal["authentication", "control_plane", "telemetry"]
EventDisposition = Literal[
    "accepted",
    "buffered_offline_delivery",
    "uncertain",
]


class EventQualityPolicy(BaseModel):
    """Customer-configurable thresholds; no wall-clock or implicit timezone assumptions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authentication_max_clock_skew_seconds: float = Field(default=60, ge=0)
    control_plane_max_clock_skew_seconds: float = Field(default=300, ge=0)
    telemetry_max_clock_skew_seconds: float = Field(default=300, ge=0)
    max_online_delivery_delay_seconds: float = Field(default=300, ge=0)

    @model_validator(mode="after")
    def finite_thresholds(self):
        for name in (
            "authentication_max_clock_skew_seconds",
            "control_plane_max_clock_skew_seconds",
            "telemetry_max_clock_skew_seconds",
            "max_online_delivery_delay_seconds",
        ):
            if not math.isfinite(getattr(self, name)):
                raise ValueError(f"{name} must be finite")
        return self


class EventQualityResult(BaseModel):
    """Explicit decision metadata; uncertain events must not silently train models."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    disposition: EventDisposition
    measured_clock_offset_seconds: float | None
    ingestion_delay_seconds: float
    max_allowed_clock_skew_seconds: float
    reasons: tuple[str, ...]


def assess_event_quality(
    event: SecurityTelemetryEvent,
    *,
    event_class: EventClass,
    policy: EventQualityPolicy,
    offline_delivery: bool = False,
) -> EventQualityResult:
    """Classify event timing without discarding late customer-buffered telemetry."""
    delay = (event.ingested_at - event.event_time).total_seconds()
    if delay < 0:
        return EventQualityResult(
            disposition="uncertain",
            measured_clock_offset_seconds=None,
            ingestion_delay_seconds=delay,
            max_allowed_clock_skew_seconds=_skew_limit(event_class, policy),
            reasons=("event_time_is_after_ingestion_time",),
        )

    offset = event.measured_clock_offset_seconds
    limit = _skew_limit(event_class, policy)
    reasons: list[str] = []

    if event.clock_quality == "unknown" or offset is None:
        reasons.append("clock_offset_not_verified")
    elif abs(offset) > limit:
        reasons.append("measured_clock_skew_exceeds_policy")

    delayed = delay > policy.max_online_delivery_delay_seconds
    if delayed:
        reasons.append("delivery_delay_exceeds_online_window")
    if offline_delivery and delayed:
        reasons.append("customer_buffered_offline_delivery")
    elif offline_delivery:
        reasons.append("offline_delivery_declared")

    if any(
        reason in reasons
        for reason in ("clock_offset_not_verified", "measured_clock_skew_exceeds_policy")
    ):
        disposition: EventDisposition = "uncertain"
    elif delayed or offline_delivery:
        disposition = "buffered_offline_delivery"
    else:
        disposition = "accepted"

    return EventQualityResult(
        disposition=disposition,
        measured_clock_offset_seconds=offset,
        ingestion_delay_seconds=delay,
        max_allowed_clock_skew_seconds=limit,
        reasons=tuple(reasons),
    )


def _skew_limit(event_class: EventClass, policy: EventQualityPolicy) -> float:
    if event_class == "authentication":
        return policy.authentication_max_clock_skew_seconds
    if event_class == "control_plane":
        return policy.control_plane_max_clock_skew_seconds
    return policy.telemetry_max_clock_skew_seconds
