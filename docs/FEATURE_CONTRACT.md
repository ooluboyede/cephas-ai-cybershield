# Feature Contract 1.0.0

Grain: one row per tenant + entity + five-minute UTC window.

| Feature | Definition |
|---|---|
| auth_failures_5m | Failed authentication event count |
| auth_successes_5m | Successful authentication event count |
| unique_source_ips_5m | Distinct non-null source IPs |
| distinct_destinations_5m | Distinct non-null destinations |
| outbound_bytes_5m | Sum of outbound bytes |
| process_launches_5m | Process launch event count |
| privilege_events_5m | Count of events marked privileged |
| off_hours_events_5m | Events before 07:00 or at/after 20:00 UTC |
| event_rate_5m | Total event count |

Tenant context must be authenticated and set server-side upstream. Never trust tenant IDs from an untrusted producer. Changes to feature definitions require a schema-version change. Customer-specific business hours and timezone policy must be agreed before operational use.
