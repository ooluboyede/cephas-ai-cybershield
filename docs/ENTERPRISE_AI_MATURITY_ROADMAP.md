# CyberShield Enterprise AI Maturity Programme

Status: **programme baseline / planned work**  
Product: CEPHAS AI CyberShield  
Deployment principle: customer-hosted, customer-controlled; customer telemetry, keys, models and security decisions remain in the customer's environment.

This roadmap distinguishes the current research foundation from capabilities that must be engineered, tested and independently validated before production claims are made. A model score is a triage signal, not proof of compromise.

## Current verified foundation

The repository currently provides:
- A validated, timezone-aware security event model.
- A five-minute UTC feature aggregation pipeline with tenant-scoped event de-duplication.
- Nine count/volume behavioural features.
- A scikit-learn Isolation Forest baseline, tenant-scoped training/scoring and basic artifact metadata.
- Synthetic-data demonstrations, basic evaluation utilities and automated tests.
- Model integrity/signing and release-floor work on separate, still-unmerged security branches. Those branches are not production certification.

The current model is a baseline trained and demonstrated with synthetic data. It is not yet a mature enterprise detection system. The current feature set does not cover the full identity, endpoint, cloud, network, application, email, data-loss or industrial-control threat surface.

## Non-negotiable platform requirements

1. **Customer control:** deployable on customer infrastructure; telemetry, feature stores, models, signing keys, audit records and policy decisions stay customer-controlled.
2. **Isolation:** trusted server-side tenant/deployment context; database-enforced tenant and business-unit boundaries where persisted data is shared; fail closed; cross-scope tests on every data path.
3. **Data contracts:** versioned schemas, source identity, event-time and ingest-time, clock-quality, provenance, deduplication, late-arrival handling, data-quality metrics and explicit missing-value semantics.
4. **Reproducibility:** immutable training/evaluation datasets or fingerprints, pinned dependencies, deterministic configurations, model lineage and signed release artifacts.
5. **Evidence-led detection:** labelled and representative customer-approved datasets, temporal and entity-separated validation, per-tenant calibration, false-positive measurement and documented detection coverage.
6. **Human accountability:** explainable alert evidence, analyst feedback, approval gates and auditable policy-controlled response. No autonomous disruptive containment by default.
7. **Operational resilience:** backpressure, bounded queues, replay, idempotency, offline buffering, recovery, health checks, capacity tests and graceful degradation.
8. **Security:** least privilege, MFA for operators, secrets management, signed updates, key lifecycle, tamper-evident audit and independent penetration/security assessment.

## Delivery sequence and acceptance gates

### Gate A — Evaluation and model-quality foundation (next engineering gate; 0.4.0)

Build a rigorous evaluation harness before adding more algorithms.

Deliver:
- Explicit label contract (0 = benign, 1 = malicious/suspicious) and strict input validation.
- Score semantics that clearly state whether higher or lower values mean greater anomaly risk.
- Precision, recall, F1, PR-AUC, ROC-AUC where mathematically valid, confusion matrix, false-positive rate, false-negative rate and alert-volume metrics.
- Threshold sweeps and per-tenant / per-entity / per-event-family breakdowns where sample sizes permit.
- Time-ordered train/validation/test splits; prevent entity and temporal leakage.
- Baseline comparison against simple rules and current Isolation Forest.
- Reproducible benchmark fixtures, class-imbalance tests, degenerate-label tests and machine-readable evaluation reports.
- A model promotion policy with minimum sample sizes and customer-approved operating thresholds; do not invent universal pass scores.

Exit criteria:
- Metrics are computed from held-out labelled data and reproducible from recorded configuration and dataset fingerprint.
- Tests cover empty, malformed, imbalanced, single-class and leakage-prone datasets.
- Evaluation output never describes anomaly detection as confirmed malicious activity.
- No production model promotion is possible without an approved evaluation report.

### Gate B — Feature engineering and data quality (0.4.1)

Expand the event contract and features with source-specific provenance and explicit semantics. Candidate feature families include authentication velocity and failure/success ratios; account/device novelty; peer-group deviations; process ancestry and rare execution; destination/domain novelty; DNS and network behaviour; privilege escalation; lateral movement; cloud control-plane changes; data access and exfiltration; and business-hour baselines.

Deliver:
- Event-time plus ingest-time, source type/version, event provenance and clock-quality.
- Late/out-of-order event policy, bounded correction windows and replay-safe aggregates.
- Robust missingness, null, cardinality and unit validation.
- Versioned feature definitions and backward-compatibility tests.
- Tenant-specific baselines without cross-tenant data leakage.
- Data-quality dashboards and quarantining of malformed or low-confidence inputs.

Exit criteria:
- Every feature has a documented definition, unit, source, missing-value rule, leakage analysis and version.
- Replay, duplicate, delayed, out-of-order and clock-skew tests pass.
- Cross-tenant feature contamination tests pass.

### Gate C — Multi-detector behavioural analytics (0.4.2)

Introduce complementary detectors behind a common, versioned interface:
- Rules and deterministic correlation for high-confidence known patterns.
- Robust statistical and peer-group baselines.
- Time-series / sequence behaviour for account, host and workload activity.
- Supervised classification only where sufficiently representative, permissioned labels exist.
- Graph/entity relationship analytics for identity, device, process and network relationships.

Each detector must declare supported telemetry, intended threat classes, confidence/limitations, resource profile and explainability payload. Ensemble logic must be calibrated and must not conceal a weak component behind a single aggregate score.

Exit criteria:
- Comparative evaluation against Gate A baseline on held-out datasets.
- Per-detector performance, calibration and resource measurements.
- Model fallback and degraded-mode behaviour tested.

### Gate D — Streaming and online feature platform (0.4.3)

Build production ingestion adapters and a streaming feature service with schema validation, tenant routing, idempotency, partitioning, backpressure, replay, dead-letter handling and bounded state. Initial integrations should be customer-selected and contract-tested (for example SIEM, EDR, identity provider, cloud audit, firewall and network telemetry); no connector is considered implemented until end-to-end tests run against its documented API.

Exit criteria:
- Load, soak, outage, replay and recovery tests with published throughput/latency/resource envelopes.
- No cross-tenant routing or replay contamination.
- Connector health and data freshness are observable.

### Gate E — Drift, health and continuous validation (0.4.4)

Implement feature-distribution drift, prediction/score drift, data-quality drift, detector health, calibration decay and feedback monitoring. Distinguish input drift from confirmed performance degradation. Alert on drift; do not silently retrain or auto-promote.

Exit criteria:
- Synthetic and replayed drift scenarios trigger expected alerts.
- Alert suppression, recovery and tenant scoping are tested.
- Retraining requires policy approval, dataset lineage, evaluation and signed promotion.

### Gate F — Explainability and analyst workflow (0.4.5)

Every alert should include contributing features, baseline/peer comparison, relevant event evidence, detector/model version, confidence/limitations, data freshness and recommended investigation steps. Provide analyst feedback with provenance and controlled label lifecycle. Protect sensitive values with role-based reveal, step-up authentication and immutable audit.

Exit criteria:
- Analysts can reproduce why an alert was raised from retained evidence.
- Feedback is attributable, permissioned, versioned and reversible through audited correction.
- Sensitive-data access is logged and policy-controlled.

### Gate G — MLOps, model governance and lifecycle (0.4.6)

Provide customer-controlled model registry, experiment/lineage records, reproducible training, model cards, approval workflow, canary/shadow deployment, rollback governed by the release-floor protocol, signed publisher keys, rotation/revocation and revocation propagation. Model loading must verify trust and anti-rollback before deserialization.

Exit criteria:
- End-to-end customer-operated model build, evaluation, signing, deployment, rotation, revocation and recovery drill.
- Independent verification of publisher and witness trust controls.
- No unsigned, untrusted, revoked or stale model can be promoted or loaded.

### Gate H — Response orchestration and production assurance (0.4.7+)

Add policy-based response integrations with simulation/dry-run, approval levels, scoped credentials, idempotency, expiry, rollback/compensation and full audit. Start with reversible low-risk actions. High-impact actions require explicit customer policy and human approval.

Complete threat modelling, secure SDLC, SAST/DAST/dependency scanning, SBOM, secrets scanning, penetration testing, privacy review, disaster recovery, HA, capacity planning, support runbooks and customer acceptance testing.

Exit criteria:
- Customer-specific security and operational acceptance signed off.
- Independent security assessment findings closed or explicitly risk-accepted.
- Tested backup/restore, failover, incident response and upgrade/rollback procedures.
- No claim of certification unless the relevant external certification has actually been achieved.

## Model promotion policy

A model may progress from experiment to shadow, canary and production only after:
1. Dataset provenance, authorisation and quality are documented.
2. Temporal/entity leakage checks pass.
3. Held-out evaluation meets customer-approved thresholds and alert-volume budget.
4. False positives and false negatives are reviewed by security analysts.
5. Model card, limitations, supported telemetry and rollback plan are approved.
6. Artifact is signed by an authorised publisher and accepted by the customer deployment's release-control system.
7. Shadow/canary telemetry demonstrates operational stability.

Retraining must not overwrite a known-good model automatically. Drift is a reason to investigate and evaluate, not permission to promote.

## Explicitly not claimed today

The current repository does not yet provide a complete enterprise feature store, streaming ingestion, live SIEM/EDR/cloud connectors, broad multi-detector coverage, production drift alerting, calibrated supervised detection, analyst case management, production response orchestration, high availability, customer restore certification, penetration-test clearance or external certification.

This roadmap is an engineering target. Each gate must be implemented in a reviewed pull request, pass CI, and satisfy its acceptance criteria before being marked complete.
