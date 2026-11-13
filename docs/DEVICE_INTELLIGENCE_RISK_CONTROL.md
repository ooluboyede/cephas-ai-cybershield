# CyberShield 0.4.3 — Device Intelligence and Risk Control Module (DIRMC)

## Purpose

DIRMC identifies repeated fraud associations involving a pseudonymous device key and
produces an explainable, customer-scoped recommendation for an authorised analyst.
It is a risk-triage capability, not an automated enforcement system.

## Implemented in this gate

- A strict device-fraud association contract carrying tenant, deployment, environment,
  product, business-unit, device-key, case, evidence-reference and event-time scope.
- Device keys must be represented as versioned HMAC-SHA-256 pseudonyms. Raw device
  identifiers are rejected by the contract.
- A configurable lookback window and minimum distinct confirmed-case/evidence threshold.
- Deterministic recommendations: monitor, flag, investigate or block recommended.
- Suspected associations alone can flag a device but cannot satisfy the block-recommendation
  threshold.
- Cross-tenant, cross-deployment, cross-environment, cross-product, cross-business-unit
  and cross-device associations fail closed.
- Duplicate case associations and future-dated evidence are rejected.
- Immutable human review records. An approval records the human decision but does not
  execute a block.

## Recommendation semantics

| Evidence | Recommendation |
|---|---|
| No recent suspected or confirmed associations | Monitor |
| Suspected associations only | Flag |
| One or more confirmed cases below policy threshold | Investigate |
| Configured count of confirmed cases and distinct evidence references met | Block recommended — human review required |

The default policy values (90-day lookback, two confirmed cases and two distinct evidence
references) are conservative reference defaults only. Each customer must configure and
approve thresholds against its own fraud operations, case definitions and evidence quality.

## Device-key requirements

The product adapter must create the device key using HMAC-SHA-256 with a secret held by
the customer-controlled deployment. Do not use a plain hash of a serial number, advertising
ID, cookie, IMEI, phone number or other enumerable identifier. The key version is carried
in the pseudonym prefix to support controlled rotation. Secret storage, key rotation,
source-specific device collection, identity confidence and device-linkage accuracy remain
adapter/deployment responsibilities and are not implemented by this module.

## Human control and enforcement boundary

- DIRMC never blocks, disables, challenges or changes access to a device.
- `block_recommended` is a recommendation state, not an enforcement instruction.
- A reviewer identity, decision, rationale and timestamp are required for the review record.
- A review approval still does not execute enforcement; a separately governed enforcement
  service and approval policy would be required in a later gate.
- Analysts must be able to contest a device association and correct or clear erroneous
  case links. This gate does not provide a case-management UI or durable correction workflow.

## Not implemented / not claimed

- Source-specific adapters for endpoint, browser, mobile, network, payment or identity systems.
- Device fingerprint collection, raw identifier normalization, HMAC secret management or key rotation.
- Durable device profile/association storage, database migrations, retention/deletion jobs or APIs.
- Identity graph resolution, household/shared-device modelling or device-linkage confidence.
- Production SIEM/EDR/fraud-case integrations, automated step-up challenges or enforcement.
- Cross-customer device intelligence, pooled reputation or cross-tenant training.
- Production certification, penetration testing, privacy assessment, HA/DR or independent review.

## Acceptance checks

1. Device keys are versioned HMAC pseudonyms; raw identifiers are rejected.
2. Association records are strictly scoped to the server-authenticated deployment.
3. Suspected associations never trigger a block recommendation by themselves.
4. Repeated confirmed cases must meet both configured case-count and distinct-evidence thresholds.
5. Duplicate cases, future-dated evidence and out-of-scope associations fail closed.
6. Every recommendation remains pending human review.
7. Review records cannot execute enforcement.
8. Ruff and pytest pass on the exact PR head SHA.
9. Independent security review and staged dependency merge are completed before release acceptance.
