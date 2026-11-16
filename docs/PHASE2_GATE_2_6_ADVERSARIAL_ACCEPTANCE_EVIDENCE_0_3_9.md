# CyberShield Phase 2 Gate 2.6 — Adversarial Acceptance Evidence Register

**Milestone:** 0.3.9  
**Parent:** Gate 2.5 branch `milestone/cybershield-0.3.8-acl-concurrency-recovery-gate-2-5`  
**Status:** Local adapter acceptance hardening in progress; live Azure and independent-review evidence outstanding.

## Purpose

Record the evidence required before the independent release-witness path can be accepted for a customer deployment. This register separates deterministic adapter tests from provider-backed evidence. Passing CI is necessary, but it is not evidence that Azure Confidential Ledger has delivered the claimed atomicity, immutability, receipt authenticity, or recovery properties.

## Evidence classes

| Class | Evidence source | What it can establish | What it cannot establish |
|---|---|---|---|
| A — Static/unit | Repository tests and lint | Input validation, adapter fail-closed paths, deterministic local behaviour | Azure service guarantees or cryptographic authenticity of a real receipt |
| B — Provider integration | Customer-controlled Azure Confidential Ledger | Actual UDF deployment, ledger API behaviour, receipt verification, identity/RBAC configuration | Independent assurance of the whole design |
| C — Adversarial operations | Controlled fault/race/restore exercises on the customer ledger | Observed concurrency, timeout recovery, administrative separation and recovery outcomes | Universal guarantees beyond the tested configuration |
| D — Independent review | Gigabrute's written assessment | Independent acceptance, findings and residual-risk disposition | Customer-specific operational approval |

## Gate 2.6 acceptance matrix

| ID | Scenario | Required assertion | Minimum evidence | Status |
|---|---|---|---|---|
| ADV-001 | Receipt verifier receives pinned identity | Verifier is called with the exact out-of-band certificate and application claims | Unit test + captured verifier arguments | Added to local suite |
| ADV-002 | Invalid native receipt | Verification failure prevents a successful adapter result | Unit test + failure output | Added to local suite |
| ADV-003 | Exact concurrent retries | One transaction identity and one durable checkpoint | Local fake test; repeat against live ledger | Local fake only |
| ADV-004 | Competing next-sequence writes | Exactly one winner; no fork | Local fake test; 10+ live clients | Local fake only |
| ADV-005 | Timeout after commit | Original operation ID resolves to the original transaction and receipt | Local fake test; injected live network response loss | Local fake only |
| ADV-006 | Receipt retrieval interruption | No acknowledgement until a receipt is obtained and verified | Local fake test; live fault injection | Local fake only |
| ADV-007 | Cross-scope authorization | Caller cannot read or mutate another tenant/deployment/product scope | Authenticated negative tests against deployed UDF and ACL RBAC | Not run |
| ADV-008 | Full-history operation-ID reuse | Reuse with altered content is rejected even when operation is not current head | UDF tests against real persisted history | Not run |
| ADV-009 | History/head/index tampering | Unauthorized overwrite and deletion are denied; evidence remains | ACL role tests and administrative audit export | Not run |
| ADV-010 | Database rollback/reconciliation | Witness history is authoritative; anchor behind is reconciled only after receipt verification | Controlled restore drill and evidence comparison | Not run |
| ADV-011 | Anchor ahead of witness | Release process stops and raises an incident | Negative integration test and incident record | Not run |
| ADV-012 | UDF integrity | Deployed UDF digest equals approved reviewed source digest | Source artifact, deployment record and live API response | Not run |
| ADV-013 | Service identity rotation | Old/new identity overlap and retirement follow approved trust-bundle procedure | Rotation drill and signed evidence | Not run |
| ADV-014 | Network partition / unresolved outcome | Fail closed; no false acknowledgement or new operation ID | Live fault-injection logs | Not run |
| ADV-015 | Independent administration | Ledger, anchor and application administrators/identities are demonstrably separated | IAM exports, role assignments and audit records | Not run |

## Local verification

Run the repository CI workflow, which executes the locked Python environment, Ruff, unit tests and PostgreSQL integration tests:

```bash
uv lock --check --python 3.11
uv sync --locked --all-extras --python 3.11
uv run --locked ruff check src tests scripts services
uv run --locked pytest -q
```

The local fake-ledger tests are explicitly class A evidence only. The fake does not implement Azure CCF transactions, native Merkle receipt validation, Azure RBAC, UDF identity, or live multi-replica behaviour.

## Live-provider evidence package

The customer-controlled test environment must produce, at minimum:

1. Azure subscription/resource identifiers and region (secrets excluded).
2. Approved UDF source, SHA-256 digest, deployment actor, deployment timestamp and live digest read-back.
3. Workload identity and least-privilege role assignment exports.
4. Pinned ACL service identity certificate fingerprint and approved rotation record.
5. Raw native receipt fixtures with transaction IDs and verifier output; redact tokens and credentials.
6. Test vectors with initial state, request digest, outcome, final ledger state and transaction ID.
7. Concurrency run configuration, client count, all outcomes and reconstructed scope head.
8. Fault-injection timeline for timeout-before-commit, timeout-after-commit, receipt unavailability and network partition.
9. Restore/rollback comparison between ledger history and the PR #8 anchor.
10. Administrative audit export proving separation of duties and attempted tampering outcomes.

Do not commit credentials, bearer tokens, private keys, customer data, or unredacted secrets to this repository. Use customer-approved secure evidence storage and reference immutable evidence identifiers here.

## Blocking decisions and exit criteria

- Gigabrute's written approval of the provider-native receipt trust model is required before treating receipt protocol evolution as approved.
- A live customer-controlled Azure ledger is required for classes B and C.
- Independent review is required before closing the security gate.
- PR #8 and PR #9 remain outside this implementation branch and must not be changed by this work.
- No production certification, immutable-witness assurance, or GIGA-SEC-02 closure is claimed by local CI.

**Gate decision:** OPEN — local tests are supporting evidence only; provider and independent-review gates remain outstanding.
