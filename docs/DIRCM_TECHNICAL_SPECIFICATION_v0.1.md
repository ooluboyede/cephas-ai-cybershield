# DIRCM — Device Intelligence and Risk Control Module
## Technical Specification v0.1

**Status:** Proposed engineering specification  
**Product:** CEPHAS AI CyberShield  
**Target:** Customer-hosted enterprise deployments  
**Release policy:** Specification only; implementation is gated by the existing ML integrity, model-signing and CI work.

---

## 1. Purpose and scope

DIRCM adds device-centric security intelligence to CyberShield. It inventories devices, maintains tenant-scoped device identities, correlates permitted endpoint/network/identity telemetry, detects suspicious behaviour, calculates explainable risk, and creates human-reviewable response recommendations.

DIRCM is not an endpoint agent, EDR product, MDM product, identity provider, firewall, or automatic blocking system in v0.1. Those capabilities require separately tested connectors and customer-authorised deployment.

### 1.1 Required outcomes

1. Assign a stable, pseudonymous, tenant-scoped device identifier where evidence supports continuity.
2. Distinguish verified device identity from probabilistic fingerprint matches.
3. Ingest and normalise device observations from approved sources.
4. Derive time-windowed, versioned device features.
5. Identify anomalous or threat-associated device behaviour with evidence and confidence.
6. Calculate an explainable risk score and severity.
7. Recommend proportionate controls, including blocking a device associated with repeated, corroborated malicious activity.
8. Require an authorised human decision before disruptive enforcement.
9. Preserve tenant isolation, provenance, auditability, privacy and customer control.

### 1.2 Explicit non-goals for initial release

- Silent or automatic permanent device blocking.
- Treating an IP address, user-agent string, cookie, MAC address or browser fingerprint alone as proof of device identity or compromise.
- Covert fingerprinting, cross-customer tracking or global device blacklists.
- Collecting passwords, private keys, raw biometric data or unrelated personal content.
- Deserialising untrusted ML artifacts.
- Uploading customer telemetry or customer model artifacts to CEPHAS-hosted services by default.
- Claiming production readiness before integration, security, privacy and operational validation.

## 2. Architectural placement

DIRCM is a domain module inside CyberShield and consumes the existing validated security-event contract and feature-engineering pipeline. It must not create a parallel event schema or bypass the existing model artifact integrity and model-signing controls.

Logical flow:

```text
Approved endpoint / network / identity sources
                  |
          Authenticated ingestion
                  |
        Event validation + provenance
                  |
         Tenant-scoped device resolver
                  |
       Device inventory + observations
                  |
      Versioned feature engineering
                  |
    Rules + approved ML anomaly detectors
                  |
        Explainable device risk engine
                  |
        Recommendation / case workflow
                  |
          Human approval boundary
                  |
       Customer policy enforcement adapter
                  |
      Immutable audit + outcome feedback
```

### 2.1 Component boundaries

| Component | Responsibility |
|---|---|
| Telemetry adapter | Authenticate source, normalise and submit observations |
| Event validation | Validate schema, timestamps, source identity and tenant context |
| Device resolver | Resolve verified identifiers or issue probabilistic match candidates |
| Device registry | Store tenant-scoped device records and lifecycle state |
| Observation store | Store minimised, provenance-bearing observations |
| Feature pipeline | Build versioned time-windowed device features |
| Detection service | Run deterministic detections and approved ML models |
| Risk engine | Aggregate evidence into explainable risk and confidence |
| Recommendation service | Produce proposed actions and required approvals |
| Approval workflow | Enforce separation of duties and approval state transitions |
| Enforcement adapter | Execute only approved, scoped, reversible actions supported by a connector |
| Audit service | Record evidence, decisions, approvals, execution and rollback |

## 3. Device identity and resolution

### 3.1 Identity assurance classes

- **A — Cryptographically verified:** device certificate, managed endpoint identity, TPM-backed key/attestation, or equivalent trusted enrollment. Verification is source- and integration-specific.
- **B — Authenticated managed identity:** authenticated EDR/MDM/agent identifier with validated source credentials, but no hardware attestation.
- **C — Probabilistic identity:** a tenant-local combination of permitted attributes and behavioural continuity. Must be labelled as a candidate match, not a verified identity.
- **D — Unknown:** insufficient evidence to resolve identity.

A device identifier must be generated by CyberShield as a random opaque ID. It must not be derived directly from a MAC address, serial number, hostname, IP address or browser fingerprint.

### 3.2 Resolution rules

1. Resolve A/B identities only within the authenticated tenant and registered source namespace.
2. Never merge records across tenants.
3. C-class matches create a link candidate with match confidence, supporting signals, conflicting signals and expiry; they do not silently merge device records.
4. A conflicting cryptographic identity creates a security event and requires investigation.
5. IP addresses and network addresses are time-bound observations, not device primary keys.
6. Re-enrolment, reimaging, ownership transfer and device retirement must have explicit lifecycle events.
7. Device identifiers must be non-reusable after retirement.

### 3.3 Privacy and minimisation

Collect only attributes required by the customer-approved use case. Hash or tokenise identifiers where feasible, use tenant-specific keyed pseudonymisation for sensitive stable attributes, restrict access to raw attributes, define retention per customer policy, and document legal basis and notice requirements. Do not use browser fingerprinting as a substitute for managed endpoint identity.

## 4. Logical data model

All records are tenant-scoped. Every read, write, background job, cache key, export and connector operation must carry a server-verified tenant context. Application filters alone are insufficient. Where PostgreSQL is used, enforce row-level security and transaction-scoped tenant context; fail closed when tenant context is absent.

### 4.1 Core entities

| Entity | Key fields |
|---|---|
| device | tenant_id, device_id, display_name, platform, identity_assurance, lifecycle_state, first_seen_at, last_seen_at |
| device_identifier | tenant_id, device_id, identifier_type, value_digest, source_id, assurance, valid_from, valid_to |
| device_observation | tenant_id, observation_id, device_id nullable, source_id, observed_at, received_at, event_type, normalised_payload, provenance, quality |
| device_feature_snapshot | tenant_id, device_id, window_start, window_end, feature_set_version, features, quality_flags |
| device_detection | tenant_id, detection_id, device_id, detector_id, detector_version, severity, confidence, evidence_refs, detected_at |
| device_risk_assessment | tenant_id, assessment_id, device_id, score, severity, confidence, contributing_factors, policy_version, assessed_at |
| device_recommendation | tenant_id, recommendation_id, device_id, action_type, rationale, evidence_refs, status, expires_at, created_at |
| approval_decision | tenant_id, decision_id, recommendation_id, approver_id, decision, reason, decided_at |
| enforcement_execution | tenant_id, execution_id, recommendation_id, connector_id, action, result, external_reference, executed_at, rollback_reference |
| device_audit_event | tenant_id, audit_id, actor_type, actor_id, action, target_ref, before_digest, after_digest, correlation_id, occurred_at |

Use opaque UUID/ULID identifiers. Use JSON only for versioned, validated feature/evidence payloads; keep security-critical ownership, status, actor and relationship fields typed and constrained. Encrypt sensitive fields at rest and in transit.

### 4.2 Required database constraints

- Composite uniqueness for (tenant_id, device_id) and source-scoped external identifiers.
- Foreign keys include tenant_id where supported, preventing cross-tenant relationships.
- Unique idempotency key scoped to tenant and source.
- Immutable audit records; corrections are appended, not overwritten.
- Valid state-transition constraints for recommendation and execution records.
- Retention and deletion workflows that preserve legally required audit evidence without retaining unnecessary raw telemetry.
- Tenant-isolation tests for every query and background worker.

## 5. Event contract and ingestion

DIRCM should extend or map into the existing CyberShield security-event contract. Do not introduce a second incompatible event envelope.

Minimum logical fields:

| Field | Requirement |
|---|---|
| event_id | Stable source event ID or generated idempotency ID |
| tenant_id | Derived from authenticated server-side source registration; never trusted from payload alone |
| source_id | Registered connector/agent identity |
| event_type | Allow-listed event type |
| occurred_at | Source timestamp, timezone-aware |
| received_at | Server timestamp |
| device_reference | Optional source identifier resolved inside tenant |
| user_reference | Optional pseudonymous tenant-local identity |
| network_context | Minimised, time-bound observations |
| attributes | Validated event-type-specific payload |
| provenance | Source, connector version, signature/authentication result |
| quality | Clock skew, offline/late, completeness and validation flags |
| correlation_id | Trace and incident correlation identifier |

Ingestion requirements: authenticated transport (mTLS where appropriate), signed requests or equivalent source authentication, schema validation, replay protection, bounded payload sizes, rate limits, idempotency, timestamp quality classification, dead-letter handling, and secret rotation. Invalid tenant context must fail closed.

## 6. Feature engineering and ML

Feature engineering must be deterministic, versioned, testable and tenant-safe. Every feature snapshot records feature-set version, time window, source coverage and quality flags.

### 6.1 Initial feature families

| Family | Example features |
|---|---|
| Authentication | failed logins, distinct accounts, MFA failures, impossible session sequence indicators |
| Access pattern | new resource count, unusual access hours, privileged access changes |
| Network | destination novelty, connection burst rate, rare protocol/port observations, threat-intel matches |
| Endpoint posture | patch age, protection status, malware/EDR alert count, unsupported OS indicator |
| Process/security events | suspicious process alert counts, persistence indicators from trusted EDR, unsigned binary alerts |
| Behaviour | deviation from device's tenant-local baseline, activity velocity, sequence anomalies |
| Identity association | number of distinct user identities, unusual device/account pairings |
| Data quality | event delay, clock skew, missingness, source confidence, observation coverage |

Features must not infer malware or compromise from weak signals alone. Exclude protected or sensitive personal attributes from model features. Keep raw identifiers out of model inputs unless specifically justified, minimised and approved.

### 6.2 Detection strategy

Start with deterministic high-signal rules and interpretable statistical baselines. ML anomaly scores are supporting evidence, not verdicts. Isolation Forest or other models may be used only after data quality, tenant isolation, artifact integrity and signing gates pass.

Every detection stores detector/model version, feature-set version, threshold/policy version, evidence references, confidence and data-quality caveats. Training and evaluation splits must prevent tenant leakage and temporal leakage. Use representative, authorised and independently labelled data before making precision/recall claims. Monitor drift and false positives.

### 6.3 Repeated malicious device association

A repeated association may raise risk only when evidence is sufficiently corroborated. The system must:
- Deduplicate repeated copies of the same underlying event.
- Distinguish independent sources from duplicated feeds.
- Weight evidence by source reliability, freshness and confidence.
- Track recurrence across defined windows.
- Discount expired or remediated indicators.
- Identify shared devices, NAT, proxies, VPNs and dynamic IP risks.
- Explain exactly which incidents contributed to the recommendation.

A shared IP or weak fingerprint must never by itself justify blocking a device.

## 7. Risk scoring and decision policy

### 7.1 Score semantics

The 0–100 score is a policy-calibrated prioritisation index, not a probability of compromise. Do not describe it as a probability unless separately calibrated and validated.

Initial severity bands are configurable defaults:

| Score | Severity | Default handling |
|---:|---|---|
| 0–19 | Informational | Normal monitoring |
| 20–39 | Low | Enhanced monitoring |
| 40–59 | Medium | Analyst review |
| 60–79 | High | Recommend scoped restriction; approval required |
| 80–100 | Critical | Urgent incident and containment recommendation; approval required |

Risk aggregation must consider evidence strength, independent corroboration, recency, persistence, source reliability, asset criticality and data quality. Apply decay to stale evidence. A high score with low data quality must be visibly marked as low-confidence and must not trigger a high-impact recommendation automatically.

### 7.2 Recommendation policy

The system may automatically create alerts and recommendations. It must not automatically execute disruptive controls in the initial release.

Supported recommendation types:
- BLOCK_DEVICE
- ISOLATE_ENDPOINT
- REVOKE_DEVICE_SESSIONS
- REQUIRE_STEP_UP_AUTH
- RESTRICT_NETWORK_ACCESS
- INCREASE_MONITORING
- REQUEST_ENDPOINT_SCAN
- RELEASE_OR_REINSTATE_DEVICE

Every recommendation includes target tenant/device, action scope, reason codes, evidence references, risk score, confidence, policy version, expiry, expected impact, rollback path and required approval role.

### 7.3 Approval and enforcement controls

- Separate recommendation creator from approver for high-impact actions.
- Enforce RBAC and optional dual approval per customer policy.
- Require step-up authentication for privileged approvals where supported.
- Use short-lived, single-use approval tokens bound to tenant, device, action, scope and recommendation digest.
- Revalidate device state and evidence immediately before execution.
- Use idempotency keys and signed connector requests.
- Record connector response and external reference.
- Provide rollback/reinstatement where the integration supports it.
- Expired, superseded or revoked recommendations cannot execute.
- If approval service, tenant context or audit service is unavailable, enforcement fails closed.

Emergency break-glass handling must be customer-configured, time-limited, strongly authenticated and fully audited. It is not a silent bypass.

## 8. API contract (logical v1)

All endpoints require authenticated caller identity, server-verified tenant context, RBAC, request correlation and audit logging. The exact transport/framework mapping follows the repository's existing API conventions.

| Method and route | Purpose |
|---|---|
| POST /api/v1/device-observations | Submit authenticated device observations |
| GET /api/v1/devices | List tenant-visible devices with filters |
| GET /api/v1/devices/{device_id} | Retrieve device profile and identity assurance |
| GET /api/v1/devices/{device_id}/risk | Retrieve latest assessment and contributing factors |
| GET /api/v1/devices/{device_id}/detections | Retrieve detections and evidence references |
| POST /api/v1/devices/{device_id}/assessments | Request/recompute an assessment |
| GET /api/v1/device-recommendations | List pending and historical recommendations |
| POST /api/v1/device-recommendations/{id}/approve | Approve with scoped approval context |
| POST /api/v1/device-recommendations/{id}/reject | Reject with reason |
| POST /api/v1/device-recommendations/{id}/revoke | Revoke before execution |
| POST /api/v1/device-recommendations/{id}/execute | Execute an approved action through an enabled connector |
| POST /api/v1/device-recommendations/{id}/rollback | Request supported rollback/reinstatement |

API responses must not expose raw device identifiers or sensitive telemetry to unauthorised roles. Pagination, filtering, rate limits, request size limits and idempotency are mandatory for write operations.

### 8.1 Example recommendation payload

```json
{
  "recommendation_id": "opaque-id",
  "tenant_id": "server-derived-tenant",
  "device_id": "opaque-device-id",
  "action_type": "BLOCK_DEVICE",
  "severity": "HIGH",
  "risk_score": 86,
  "confidence": 0.91,
  "score_semantics": "policy_priority_index_not_probability",
  "reason_codes": [
    "REPEATED_CORROBORATED_MALICIOUS_ACTIVITY",
    "PERSISTENT_ENDPOINT_ALERTS"
  ],
  "evidence_refs": ["incident-ref-1", "incident-ref-2"],
  "policy_version": "dircm-risk-policy-1",
  "expires_at": "2026-11-12T14:00:00Z",
  "approval_required": true,
  "execution_status": "NOT_EXECUTED"
}
```

Example only; values are illustrative and must not be treated as measured product performance.

## 9. Dashboard requirements

Provide a Device Intelligence workspace with:
- Device inventory and identity assurance class.
- Device risk distribution and trend.
- High-risk devices and repeated corroborated threat associations.
- Device profile, observation timeline and linked incidents.
- Risk score, confidence, quality flags and contributing factors.
- Pending approvals and action history.
- Blocked, isolated, expired and reinstated state.
- Connector health and last successful synchronisation.
- Filters for tenant-authorised business unit, platform, severity, source and time.

Never show a global cross-tenant device list. Use explicit labels for verified, probabilistic and unknown identity.

## 10. Security, privacy and operational requirements

1. Database-enforced tenant isolation; fail closed on missing or invalid tenant context.
2. Server-verified tenant and business-unit scope; never accept tenant ownership from an untrusted client payload.
3. Least privilege, RBAC, separation of duties and step-up approval.
4. Encryption in transit and at rest; secrets held outside source control.
5. Signed/authenticated connector traffic, replay protection and credential rotation.
6. Append-only, tamper-evident audit trail with protected retention.
7. Model and feature artifacts validated and signature-verified before deserialisation or execution.
8. Customer-controlled deployment, telemetry retention, integrations and enforcement policies.
9. Bounded ingestion, backpressure, retry limits and dead-letter controls.
10. Observability for event lag, source coverage, scoring latency, connector failures, false positives and approval latency.
11. Data minimisation, configurable retention, export/deletion controls and documented customer responsibilities.
12. Secure defaults: recommendations only; no disruptive action until customer enables a connector and approves policy.

## 11. Acceptance test plan

### Identity and data
- Verified identity resolves only inside its tenant.
- Probabilistic match creates a candidate, not an automatic merge.
- IP changes do not create a new verified identity or prove identity continuity.
- Retired identifiers cannot be reassigned.
- Duplicate and replayed events are idempotently handled.
- Invalid timestamps, clock skew, offline delivery and malformed payloads are classified.

### Tenant isolation
- Cross-tenant reads, writes, joins, exports, caches, background jobs and connector actions are denied.
- Missing tenant context fails closed.
- Business-unit restrictions are enforced where configured.
- RLS/DB policy tests prove isolation independently of application filters.

### Detection and scoring
- Feature generation is deterministic for a fixed event set and version.
- Duplicate events do not inflate repeated-incident counts.
- Stale evidence decays according to policy.
- Low-confidence or poor-quality observations are surfaced as such.
- Every score is explainable from stored factors and policy version.
- Model evaluation prevents tenant and temporal leakage.
- False-positive, precision, recall and calibration reports use labelled validation data only.

### Recommendation and enforcement
- Detection can create a recommendation but cannot execute it.
- Unapproved, expired, revoked or wrong-scope recommendations cannot execute.
- Creator cannot approve their own high-impact action when separation is required.
- Approval token cannot be reused or altered.
- Connector failure is recorded and does not report success.
- Rollback/reinstatement is available only where connector capability is verified.
- Every state transition is audited.

### Resilience and security
- Rate limiting, payload bounds, retries and dead-letter handling work.
- Connector secrets are not logged.
- Tampered or unsigned model artifacts are rejected before deserialisation.
- Audit tampering is detectable.
- Backup/restore, retention and deletion workflows are tested.
- Threat modelling, SAST/dependency checks, DAST where applicable and independent penetration testing are completed before production claims.

## 12. Delivery plan and dependency gates

DIRCM work must not displace the existing CyberShield release gates.

| Order | Gate | Exit criteria |
|---|---|---|
| 0 | Existing foundation stabilisation | CI green and event-contract baseline stable |
| 1 | Existing ML data integrity | 0.3.1 data validation and tenant-safe training accepted |
| 2 | Existing model artifact integrity | 0.3.2 integrity checks and regression tests accepted |
| 3 | Existing model signing | 0.3.3 signature verification before deserialisation accepted |
| 4 | DIRCM 0.1 | Device identity, inventory, observation contract and isolation tests |
| 5 | DIRCM 0.2 | Versioned feature pipeline and labelled behavioural tests |
| 6 | DIRCM 0.3 | Explainable risk policy, confidence and evidence correlation |
| 7 | DIRCM 0.4 | Approval workflow, action simulation and connector contract |
| 8 | DIRCM 0.5 | One customer-approved integration validated end-to-end |
| 9 | DIRCM 0.6 | Independent security review, operational runbooks and customer acceptance |

### DIRCM 0.1 completion criteria

- [ ] Threat model and data-flow diagram reviewed.
- [ ] Device identity assurance classes implemented.
- [ ] Tenant-scoped device registry schema reviewed.
- [ ] Observation contract mapped to existing security-event contract.
- [ ] Source authentication and idempotency design accepted.
- [ ] Database-enforced tenant isolation tests pass.
- [ ] Privacy, retention and telemetry minimisation reviewed.
- [ ] No enforcement capability enabled.
- [ ] CI and security checks pass.

## 13. Release and claims policy

DIRCM must be labelled experimental until its required gates pass. A completed specification is not an implemented module. A passing unit test suite is not production certification. Production readiness requires representative customer data, integration validation, independent security review, documented operational controls and customer acceptance.

**Decision recorded:** DIRCM is a core CyberShield capability. Its first implementation milestone is DIRCM 0.1, but implementation starts only after the existing prerequisite security and CI gates are confirmed complete.
