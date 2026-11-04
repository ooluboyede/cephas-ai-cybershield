import pandas as pd

from .events import SecurityEvent

FEATURE_COLUMNS = [
    "auth_failures_5m",
    "auth_successes_5m",
    "unique_source_ips_5m",
    "distinct_destinations_5m",
    "outbound_bytes_5m",
    "process_launches_5m",
    "privilege_events_5m",
    "off_hours_events_5m",
    "event_rate_5m",
]


def deduplicate_events(events: list[SecurityEvent]) -> list[SecurityEvent]:
    """Remove exact replays; reject an event ID reused with a different payload."""
    unique: dict[tuple[str, str], SecurityEvent] = {}
    for event in events:
        key = (event.tenant_id, event.event_id)
        previous = unique.get(key)
        if previous is not None and previous != event:
            raise ValueError(
                f"conflicting payloads for event_id {event.event_id!r} "
                f"within tenant {event.tenant_id!r}"
            )
        unique[key] = event
    return list(unique.values())


def engineer_features(events: list[SecurityEvent]) -> pd.DataFrame:
    """Aggregate deduplicated events per tenant/entity/5-minute UTC window."""
    events = deduplicate_events(events)
    columns = ["tenant_id", "entity_id", "window_start", *FEATURE_COLUMNS]
    if not events:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame([event.model_dump() for event in events])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["window_start"] = df["timestamp"].dt.floor("5min")
    hour = df["timestamp"].dt.hour
    df["off_hours"] = ((hour < 7) | (hour >= 20)).astype(int)
    keys = ["tenant_id", "entity_id", "window_start"]
    grouped = df.groupby(keys, sort=True, dropna=False)
    output = grouped.agg(
        auth_failures_5m=("event_type", lambda values: int((values == "auth_failure").sum())),
        auth_successes_5m=("event_type", lambda values: int((values == "auth_success").sum())),
        unique_source_ips_5m=("source_ip", "nunique"),
        distinct_destinations_5m=("destination", "nunique"),
        outbound_bytes_5m=("outbound_bytes", "sum"),
        process_launches_5m=("event_type", lambda values: int((values == "process_launch").sum())),
        privilege_events_5m=("privileged", "sum"),
        off_hours_events_5m=("off_hours", "sum"),
        event_rate_5m=("event_id", "count"),
    ).reset_index()
    for column in FEATURE_COLUMNS:
        output[column] = pd.to_numeric(output[column], errors="raise").astype(float)
    return output[columns]
