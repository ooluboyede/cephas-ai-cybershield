import random
from datetime import datetime, timedelta, timezone

from .events import SecurityEvent


def synthetic_events(seed=7, entities=30, windows=24):
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, 8, tzinfo=timezone.utc)
    result, n = [], 0
    for user in range(entities):
        for w in range(windows):
            anomaly = user == 0 and w in {8, 17}
            count = 18 if anomaly else rng.randint(2, 5)
            for _ in range(count):
                n += 1
                kind = rng.choices(["auth_success", "auth_failure", "network_connection",
                    "process_launch", "privilege_change"], [65, 8, 15, 10, 2])[0]
                result.append(SecurityEvent(event_id=f"synthetic-{n}",
                    tenant_id="synthetic-tenant", entity_id=f"synthetic-user-{user:03}",
                    timestamp=start + timedelta(minutes=5*w, seconds=rng.randint(0, 299)),
                    event_type=kind, source_ip=f"192.0.2.{rng.randint(1,30)}",
                    destination=f"service-{rng.randint(1,8)}.example.invalid",
                    outbound_bytes=rng.randint(80_000_000, 180_000_000) if anomaly and kind == "network_connection" else rng.randint(0,150_000),
                    process_name="synthetic-process",
                    privileged=bool(anomaly and kind == "privilege_change")))
    return result
