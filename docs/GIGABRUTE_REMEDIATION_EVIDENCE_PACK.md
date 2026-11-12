# Gigabrute Remediation and Evidence Pack

**Repository:** `ooluboyede/cephas-ai-cybershield`  
**Independent review:** `SEC-REV-CYBERSHIELD-033`  
**Original review date:** 9 November 2026  
**Prepared:** 12 November 2026  
**Purpose:** One navigable, finding-by-finding map of the remediation work and its evidence.

> **Review status:** This pack is a remediation handoff, not a claim of reviewer acceptance, production readiness, or merge approval. PR #5 is the primary implementation branch. PR #8 and PR #9 are dependent, draft follow-on changes. The reviewer should assess the exact current heads and report any remaining exploit path or evidence gap.

## 1. Reviewer starting points

| Workstream | Pull request | Current role |
|---|---|---|
| Cryptographic model signing and publisher verification | [PR #5](https://github.com/ooluboyede/cephas-ai-cybershield/pull/5) | Primary implementation and five finding remediations |
| Release-floor recovery and customer anchor design | [PR #8](https://github.com/ooluboyede/cephas-ai-cybershield/pull/8) | Draft follow-on for rollback recovery and external anchor service |
| Provider-neutral immutable witness protocol core | [PR #9](https://github.com/ooluboyede/cephas-ai-cybershield/pull/9) | Draft follow-on defining checkpoint, receipt and atomic transition contract |

**Review order:** PR #5 first, then PR #8, then PR #9. PR #8 is based on PR #5's branch; PR #9 is based on PR #8's branch. Do not review these as three independent changes against `main`, and do not merge a downstream PR ahead of its base.

## 2. Finding-by-finding remediation map

### GIGA-SEC-01 — Critical: metadata canonicalisation

**Concern from review:** Signature verification must bind the exact metadata representation used by the loader. Re-serialising parsed JSON or applying inconsistent canonicalisation can create ambiguity between signed and consumed content.

**Implementation location:**
- [`src/cybershield_ml/model.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/src/cybershield_ml/model.py) — metadata is read as bytes; those exact bytes are passed to signature verification before deserialisation.
- [`src/cybershield_ml/signing.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/src/cybershield_ml/signing.py) — signature envelope and digest verification.
- [`tests/test_pipeline.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/tests/test_pipeline.py) — signing and tamper/regression coverage.

**Remediation claim:** The loader verifies the signature over the metadata bytes it actually read, and the signed envelope binds metadata and artifact digests plus model identity/scope fields. It does not rely on parsing and re-serialising metadata to recreate the signed bytes.

**Reviewer confirmation requested:** Please confirm there is no alternate load/verification path that parses, normalises or reserialises metadata before authenticating it, and test whitespace/key-order/encoding changes and malformed JSON at the actual loader boundary.

**Status:** Implemented in PR #5; independent acceptance remains pending.

### GIGA-SEC-02 — High: replay protection and model-version rollback

**Concern from review:** A valid older signed model must not be replayed after a newer release has been accepted. A local database alone may be rolled back from backup or restored to an older snapshot.

**Implementation locations:**
- [`src/cybershield_ml/release_state.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/src/cybershield_ml/release_state.py) — release-state interface and PostgreSQL compare-and-set state adapter.
- [`tests/test_postgres_release_state.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/tests/test_postgres_release_state.py) — state-transition tests.
- [`tests/test_postgres_release_state_integration.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/tests/test_postgres_release_state_integration.py) — live PostgreSQL integration/concurrency tests.
- [`src/cybershield_ml/release_anchor.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-release-floor-recovery-design/src/cybershield_ml/release_anchor.py) — customer-operated HTTPS/mTLS release-floor anchor adapter in PR #8.
- [`services/release_anchor/app.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-release-floor-recovery-design/services/release_anchor/app.py) — reference customer-operated anchor service in PR #8.
- [`docs/IMMUTABLE_RELEASE_WITNESS.md`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-release-floor-recovery-design/docs/IMMUTABLE_RELEASE_WITNESS.md) — production witness requirements.
- [`src/cybershield_ml/release_witness.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-witness-protocol-core/src/cybershield_ml/release_witness.py) — provider-neutral checkpoint/receipt protocol in PR #9.
- [`tests/test_release_witness.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-witness-protocol-core/tests/test_release_witness.py) — checkpoint transition and receipt contract tests.

**Remediation claim:** PR #5 adds a durable PostgreSQL release-state compare-and-set check before model deserialisation. PR #8 adds an anchor-first recovery design and a customer-operated HTTPS/mTLS service reference. PR #9 adds a provider-neutral immutable witness contract with signed receipts, checkpoint chaining, strict scope binding and transition validation.

**Important residual limitation:** PR #8's separate anchor database is not, by itself, an immutable witness. If an administrator can restore that anchor database from an older backup, its release floor can also roll back. PR #9 defines the protocol and test contract; it does **not** yet supply a production immutable witness backend or prove an independently administered WORM/append-only service. A customer-selected witness with independently verified durability, linearizable compare-and-append, idempotency, administrative separation, backup/restore and recovery guarantees remains required.

**Reviewer confirmation requested:** Please distinguish (a) local DB replay protection, (b) recovery from application DB rollback, and (c) recovery from rollback of the anchor itself. Please confirm whether the current design closes the original threat or whether an independently administered immutable witness is a release blocker. Please review concurrent append, duplicate operation IDs, ambiguous timeout/retry, genesis/bootstrap and break-glass rollback governance.

**Status:** Local PostgreSQL release-state implementation and integration tests are present in PR #5. Anchor/recovery design is in draft PR #8. Provider-neutral protocol core is in draft PR #9. End-to-end production immutable-witness assurance is **not implemented/validated**.

### GIGA-SEC-03 — Medium: tenant and deployment boundaries

**Concern from review:** A tenant-scoped model must not be loaded using another tenant's or deployment's trust material or execution context.

**Implementation locations:**
- [`src/cybershield_ml/trust_context.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/src/cybershield_ml/trust_context.py) — authenticated deployment context and deployment-scoped trusted publisher keyring.
- [`src/cybershield_ml/model.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/src/cybershield_ml/model.py) — loader verifies requested tenant, deployment context, metadata deployment ID and keyring scope.
- [`tests/test_pipeline.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/tests/test_pipeline.py) — scope substitution and trust-context regression coverage.

**Remediation claim:** The loader requires a typed deployment trust context and a trusted publisher keyring scoped to the same tenant/deployment; it checks the metadata deployment ID and rejects a mismatch. An unscoped key dictionary cannot override the scoped keyring.

**Reviewer confirmation requested:** Please test tenant A/deployment A material against tenant B/deployment B contexts, keyring substitution, metadata substitution and any API path that can construct or bypass the trust context. Confirm how the deployment context is authenticated by the caller in the intended production integration; a Python type check alone is not an authentication mechanism.

**Status:** Scope checks and regression tests are implemented in PR #5; production caller authentication and end-to-end tenant isolation still require deployment-level assurance.

### GIGA-SEC-04 — Medium: key-ID spoofing

**Concern from review:** An attacker-controlled key identifier must not select an untrusted key or cause fallback to a different trust source.

**Implementation locations:**
- [`src/cybershield_ml/signing.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/src/cybershield_ml/signing.py) — trusted publisher key-ID resolution and signature verification.
- [`src/cybershield_ml/trust_context.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/src/cybershield_ml/trust_context.py) — deployment-scoped trusted keyring.
- [`tests/test_pipeline.py`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/tests/test_pipeline.py) — unknown/malformed key ID and untrusted-key rejection tests.

**Remediation claim:** Key selection is an exact lookup in the deployment-scoped trusted publisher keyring; unknown or malformed identifiers fail closed. The caller-supplied unscoped public-key mapping cannot replace the scoped keyring.

**Reviewer confirmation requested:** Please identify any concrete input/path that still allows a key-ID collision, alias, case/normalisation ambiguity, fallback or key substitution. Confirm key-ID uniqueness and rotation/revocation behaviour expected by the deployment.

**Status:** Implemented in PR #5; independent acceptance remains pending.

### GIGA-SEC-05 — Low: dependency pinning

**Concern from review:** Reproducibility and supply-chain integrity require locked dependencies rather than unconstrained installs.

**Implementation locations:**
- [`pyproject.toml`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/pyproject.toml) — dependency declarations and tool configuration.
- [`uv.lock`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/uv.lock) — resolved dependency versions and hashes.
- [`.github/workflows/ci.yml`](https://github.com/ooluboyede/cephas-ai-cybershield/blob/milestone/cybershield-0.3.3-cryptographic-model-signing/.github/workflows/ci.yml) — locked CI installation/check command.

**Remediation claim:** CI installs from the lockfile in locked mode; the lockfile records resolved versions and artifact hashes.

**Reviewer confirmation requested:** Please confirm all CI and documented developer installation paths use the lockfile and that dependency updates are deliberately regenerated/reviewed.

**Status:** Implemented in PR #5; independent acceptance remains pending.

## 3. Current branch topology and review instructions

```text
main
 └── PR #5  (primary signed-model implementation)
      └── PR #8  (draft release-floor recovery / customer anchor)
           └── PR #9  (draft immutable-witness protocol core)
```

- PR #5: [open, not merged](https://github.com/ooluboyede/cephas-ai-cybershield/pull/5)
- PR #8: [draft, not merged](https://github.com/ooluboyede/cephas-ai-cybershield/pull/8)
- PR #9: [draft, not merged](https://github.com/ooluboyede/cephas-ai-cybershield/pull/9)

Review each PR at its current head SHA shown by GitHub. CI must be green on the exact head under review. A previous successful run on a superseded commit is not evidence for the current head.

## 4. CI and validation evidence

The previous PR #5 head `5af395b2a8b5c80204588d6f5625955d58461701` had failing push and pull-request checks. Both failures were caused by Ruff `TRY004` at `src/cybershield_ml/model.py:233`, where a missing required signature file was raised as a generic `ValueError`.

A correction has been committed to PR #5 to raise `FileNotFoundError` for that missing-file condition. **The new commit must complete fresh push and pull-request CI before this pack can claim the lint failure is resolved.** Do not treat the prior failing runs as current-head validation.

The relevant automated test suites are:
- `tests/test_pipeline.py`
- `tests/test_postgres_release_state.py`
- `tests/test_postgres_release_state_integration.py`
- `tests/test_release_anchor.py` (PR #8)
- `tests/test_release_anchor_service.py` and `tests/test_release_anchor_service_integration.py` (PR #8)
- `tests/test_release_witness.py` (PR #9)

Tests and CI establish only the behaviours exercised by those tests. They do not prove production deployment security, immutable witness guarantees, external administrative separation, or customer recovery readiness.

## 5. Explicit residual risks / production gates

1. Select and independently administer a real immutable witness backend; verify its documented and tested consistency, durability, idempotency and restore guarantees.
2. Complete end-to-end anchor/witness tests, including backup/restore of both application and anchor databases, witness unavailability, ambiguous timeouts, concurrent writers and disaster recovery.
3. Establish authenticated deployment-context provisioning and tenant isolation at the production service boundary.
4. Define publisher key provisioning, rotation, revocation, compromise recovery and dual-control bootstrap.
5. Complete independent security review and penetration testing on the integrated deployment.
6. Complete customer-controlled operational recovery and break-glass drills.
7. Keep signed model artifacts restricted to trusted publishers; Joblib deserialisation remains unsafe for untrusted artifacts even when a file is syntactically valid.

## 6. Requested independent reviewer response

For each GIGA-SEC-01 through GIGA-SEC-05, please provide one of:
- **ACCEPTED** — evidence closes the finding;
- **PARTIALLY REMEDIATED** — identify the residual risk and required evidence;
- **REJECTED** — provide the exploit input, affected code path and expected security property;
- **NOT TESTED** — state the missing precondition or test.

For every non-accepted finding, please include:
1. exact source path and function;
2. reproducible input or attack sequence;
3. expected secure behaviour;
4. test or evidence required for closure.

Please also provide a separate decision on whether the PR #8/#9 witness work adequately addresses rollback of the anchor itself, or whether a production immutable witness backend remains a mandatory release gate.

**No merge is requested by this pack.** The requested outcome is a written, finding-by-finding independent reassessment of the exact current code and test evidence.
