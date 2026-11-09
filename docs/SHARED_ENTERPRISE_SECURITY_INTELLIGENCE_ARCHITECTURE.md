# CEPHAS Shared Enterprise Security Intelligence Architecture

Status: target architecture; not yet implemented as a cross-product service.

## Decision

CEPHAS will develop **one shared Enterprise Security Intelligence Platform (ESIP)** as a reusable security capability for the CEPHAS product portfolio. CyberShield is the platform's security-intelligence engine and reference implementation. Each CEPHAS product integrates through a versioned product telemetry adapter and receives security services through a controlled API/event contract.

This is a shared software platform, not a shared customer-data pool. Product reuse must never weaken customer, tenant, deployment, business-unit, environment or product boundaries.

## Portfolio coverage

The integration framework must support, at minimum, the following product families as they are built and certified:

| CEPHAS product family | Examples | Security telemetry emphasis |
|---|---|---|
| Banking and financial services | BankFlow, FraudShield, CPFS, NGX solutions, payment integrations | account access, privileged operations, transaction workflow abuse, service/API abuse, suspicious operator behaviour |
| Enterprise and workforce | CyberShield, Payroll FraudShield / CPFS, HR/ATS | identity, role changes, payroll approvals, employee access, data exports, privileged actions |
| Retail and commerce | RetailShield, HotelFlow, BreweryOS | POS/API access, account takeover, inventory/payment workflow abuse, customer-data access |
| Government and public services | GovShield, CustomsShield, tax mapper, INEC solutions | privileged case access, data changes, approvals, bulk queries, administrative actions |
| Ticketing, clubs and experiences | TicketShieldOS, ClubOS, FEN, Virtual Wonder World | ticket issuance/resale abuse, identity and membership access, QR validation, account/device anomalies |
| Critical infrastructure and industry | Weather Intelligence, PowerOps, CementOS, Mangal Cement, PortOps, AirportOS, OilOS | operational technology boundaries, control-plane changes, remote access, service integrity, safety-sensitive actions |

This is a portfolio integration target, not a claim that each named product currently emits telemetry or is connected.

## Shared platform services

1. **Telemetry contract and adapters:** map each product's audit/security events into a canonical, versioned envelope while preserving source product, module, deployment, tenant, business unit, environment, source identity, event time, ingestion time, provenance and clock quality.
2. **Identity and policy context:** consume trusted identity and authorization context from each product. The platform must not trust tenant, product, role or business-unit values supplied only by an untrusted client.
3. **Detection services:** shared rules, behavioural analytics, anomaly detection, threat correlation and model-serving interfaces. Product-specific detectors remain modular.
4. **Risk and alert services:** common severity/risk schema, evidence, explanation, confidence/limitations, model/rule version and recommended investigation.
5. **Case and response integration:** standard alert/case API and policy-controlled response adapters. Product workflows retain ownership of business actions and approvals.
6. **Model governance:** customer-controlled model registry, evaluation, signatures, release sequencing, approval, revocation and rollback controls.
7. **Audit and observability:** immutable/tamper-evident security audit, data freshness, detector health, model drift and connector health.
8. **Deployment profiles:** customer-hosted single-product, customer-hosted multi-product and CEPHAS internal operations. A customer may deploy only the products it licenses.

## Mandatory isolation model

Every event, feature row, model, alert, case, feedback record and response action must carry an explicit scope:

- customer / tenant;
- deployment / environment;
- product and product module;
- business unit where applicable;
- source system and entity.

Authorization must derive from a server-verified identity and deployment context. Database row-level controls must enforce isolation wherever data is persisted in a shared database. Every query, cache key, queue partition, object-store path, model registry operation and API authorization decision must be scope-aware.

**No cross-customer or cross-tenant training by default.** No product-to-product feature sharing by default. Cross-product correlation is permitted only inside the same explicitly authorized customer deployment, with customer policy enabling it, scope-preserving provenance, and tests proving no information flows across customers or unauthorized products. Any pooled or federated learning requires a separate documented privacy, consent, governance and security design.

## Data and event flow

1. Product emits a signed/authenticated audit or security event through its adapter.
2. Ingestion validates schema, source identity, event-time, ingest-time, replay/idempotency key and trusted scope.
3. Invalid or uncertain events are quarantined or marked with explicit quality status; they are not silently treated as trustworthy.
4. Scope-aware streaming aggregation builds product- and entity-specific features.
5. Detection services produce explainable alerts and evidence.
6. Policy engine routes alerts to the owning product/customer SIEM or case workflow.
7. Response adapters execute only actions explicitly allowed by customer policy and approval workflow.
8. Audit records retain the event-to-feature-to-detection-to-response lineage.

## Product integration contract

Each product adapter must provide:
- a documented event catalogue and schema version;
- authoritative source identity and authenticated transport;
- event IDs with replay semantics;
- event and ingestion timestamps plus clock-quality;
- trusted customer/deployment/product/module scope;
- data classification and redaction rules;
- source health and freshness signals;
- contract tests, replay tests, negative authorization tests and sample payloads.

A product is not labelled integrated until its adapter has end-to-end tests against that product's real documented event/API source and the customer deployment has accepted the integration.

## Delivery order

1. Complete CyberShield 0.4.0 evaluation quality gate.
2. Build 0.4.1 canonical multi-product telemetry envelope and feature/data-quality foundations, including strict scope dimensions.
3. Define adapter SDK and contract test kit; onboard one low-risk CEPHAS product as a pilot.
4. Add customer-approved product adapters in priority order.
5. Add cross-product correlation only after same-customer policy, isolation tests and audit lineage are proven.
6. Add common alert/case/response APIs and customer deployment profiles.
7. Conduct independent security review and customer acceptance for each deployment profile.

## Non-goals and safeguards

- ESIP does not replace the domain logic of FraudShield, Payroll FraudShield, TicketShieldOS, CustomsShield or other product engines.
- ESIP is not a universal data lake that silently centralizes all product data.
- A shared model is not automatically trained across products or customers.
- The platform does not autonomously block accounts, change payroll, stop industrial processes, deny public services or perform other high-impact actions without explicit customer policy and appropriate human approval.
- The platform is not considered production-ready until its isolation, connectors, availability, recovery, threat model, independent assessment and customer acceptance are demonstrated.
