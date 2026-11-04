import pandas as pd
from .events import SecurityEvent

FEATURE_COLUMNS = ["auth_failures_5m", "auth_successes_5m", "unique_source_ips_5m",
"distinct_destinations_5m", "outbound_bytes_5m", "process_launches_5m",
"privilege_events_5m", "off_hours_events_5m", "event_rate_5m"]

def engineer_features(events: list[SecurityEvent]) -> pd.DataFrame:
    """Aggregate per tenant/entity/5-minute UTC window; not an authorisation boundary."""
    if not events:
        return pd.DataFrame(columns=["tenant_id", "entity_id", "window_start", *FEATURE_COLUMNS])
    df = pd.DataFrame([e.model_dump() for e in events])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["window_start"] = df["timestamp"].dt.floor("5min")
    hour = df["timestamp"].dt.hour
    df["off_hours"] = ((hour < 7) | (hour >= 20)).astype(int)
    keys = ["tenant_id", "entity_id", "window_start"]
    g = df.groupby(keys, sort=True, dropna=False)
    out = g.agg(
        auth_failures_5m=("event_type", lambda s: int((s == "auth_failure").sum())),
        auth_successes_5m=("event_type", lambda s: int((s == "auth_success").sum())),
        unique_source_ips_5m=("source_ip", "nunique"),
        distinct_destinations_5m=("destination", "nunique"),
        outbound_bytes_5m=("outbound_bytes", "sum"),
        process_launches_5m=("event_type", lambda s: int((s == "process_launch").sum())),
        privilege_events_5m=("privileged", "sum"),
        off_hours_events_5m=("off_hours", "sum"),
        event_rate_5m=("event_id", "count"),
    ).reset_index()
    for col in FEATURE_COLUMNS:
        out[col] = pd.to_numeric(out[col], errors="coerce").fillna(0).astype(float)
    return out[["tenant_id", "entity_id", "window_start", *FEATURE_COLUMNS]]
