# CyberShield 0.4.2 — Multi-Detector Behavioural Intelligence

## Goal

Introduce a reusable detector contract and a first set of deterministic behavioural
detectors for the CEPHAS Enterprise Security Intelligence Platform (ESIP). CyberShield
is the reference implementation; other CEPHAS products can map their own governed
features through product-owned adapters and definitions.

## Implemented in this gate

- A common detector protocol and immutable, versioned detector outcomes.
- A registry that rejects duplicate detector identifiers.
- Configurable threshold rules over validated product-owned features.
- Median / median-absolute-deviation (MAD) robust deviation against customer-scoped
  entity-history baselines.
- Explicit peer-group deviation using customer-supplied peer-group identifiers and
  baseline snapshots.
- Scope validation for tenant, deployment, environment, product, business unit and exact entity identity for entity-history baselines.
- Detector execution isolation: a failing detector returns an explicit failed outcome,
  never a clean/no-alert outcome and never leaks exception details into the result.
- Evidence fields explaining the feature, comparator, threshold or baseline statistics.

## Safety and interpretation

A detector outcome is a triage signal, not proof of compromise. Scores from different
detector families are not calibrated or directly comparable. This gate does not combine
scores into a universal risk score, set universal thresholds, or automatically block
users, devices, transactions or workloads.

Baselines are inputs supplied by the customer-controlled deployment. This code does not
create peer groups, pool cross-tenant data, or share features between CEPHAS products.
The authenticated scope is server-provided; callers must not derive it from untrusted
event claims.

## Not implemented / not claimed

- Distributed streaming execution, durable feature store, online state or watermarks.
- Time-series forecasting, sequence models, graph analytics or supervised models.
- Automatic baseline learning, peer-group membership governance or label pipelines.
- Cross-detector calibration, ensemble weighting or production alert budgets.
- Case management, automated response, SIEM/EDR connectors or customer data-plane
  integrations.
- Production certification, security review, penetration testing or HA/DR acceptance.

## Acceptance checks

1. Detector IDs are unique and outcomes have explicit evaluated/skipped/failed states.
2. Tenant/deployment/environment/product/business-unit scope is enforced before scoring.
3. Baselines outside authenticated scope fail closed.
4. Threshold, robust-statistical and peer-group detectors return reproducible evidence.
5. Missing baselines are skipped, not represented as benign.
6. Detector failures remain visible and cannot be mistaken for a no-alert result.
7. Ruff and pytest pass on the exact PR head SHA.
8. Independent review and staged merge order are completed before release acceptance.
