# Independent Immutable Release-Floor Witness — Design Gate

Status: **design proposal; no witness adapter or production backend implemented**.

## 1. Purpose and threat boundary

The HTTPS release-floor service in `services/release_anchor/` is currently backed by PostgreSQL. Its separate administration and backup boundary protects against rollback of the CyberShield application database, but an administrator or restore of the anchor database can roll back both the current floor and its local audit table.

This design adds a customer-selected witness in a third, independently administered durability and recovery boundary. The witness—not either PostgreSQL database—must be the final authority for the highest accepted release checkpoint. The anchor PostgreSQL database becomes a recoverable operational mirror.

The witness must provide an independently verifiable, append-only record. A second ordinary database, a WORM-labelled bucket without enforceable retention, or a service sharing the anchor administrators and backup credentials is not sufficient.

## 2. Required witness contract

Define a narrow adapter contract with these logical operations:

- `read_checkpoint(scope) -> checkpoint | None`: retrieve the latest accepted checkpoint and its immutable witness receipt.
- `compare_and_append(scope, expected_previous, candidate) -> receipt`: atomically append a strictly newer checkpoint only if the current checkpoint equals `expected_previous`.
- `verify_receipt(receipt, checkpoint) -> bool`: verify the receipt using a separately provisioned witness verification key or authenticated provider proof.

The concrete API may differ, but it MUST provide the same guarantees. The compare-and-append operation must be linearizable per scope, durable before success is returned, and idempotent for an exact retry. It must reject stale predecessors, sequence rollback, same-sequence/different-version conflicts, and conflicting concurrent candidates.

A timeout after append is an ambiguous outcome. The client must read the witness again and reconcile by exact checkpoint identity; it must not blindly issue a different candidate or fall back to PostgreSQL.

## 3. Checkpoint format

Each checkpoint is a canonical, versioned record containing:

- protocol identifier and protocol version;
- tenant ID, deployment ID and product;
- strictly increasing release sequence and release version;
- SHA-256 digest of the signed model metadata bytes;
- SHA-256 digest of the model artifact;
- publisher key ID and signature digest/reference;
- previous checkpoint digest (or an explicit genesis marker);
- unique operation/idempotency identifier;
- creation timestamp for audit only (never as the monotonicity authority).

The canonical checkpoint digest is SHA-256 over a documented deterministic encoding. Do not include secrets, private keys, model contents, customer telemetry or customer data. Scope identifiers must be validated and bound to the authenticated witness identity; callers must not be able to write arbitrary tenant scopes.

The witness receipt must bind the checkpoint digest, scope, accepted sequence, previous checkpoint digest and witness identity. It must be cryptographically verifiable independently of the mutable anchor database. The witness signing key must be held outside the application and anchor database administration boundary.

## 4. Authority and update ordering

The witness is the source of truth. For each model acceptance:

1. Verify publisher signature and all artifact/metadata bindings before deserialization.
2. Authenticate to the witness and read the latest checkpoint for the exact tenant/deployment/product scope.
3. Read the anchor PostgreSQL floor and application PostgreSQL floor.
4. If either database is ahead of the witness, fail closed and require an independently approved investigation. Never auto-promote either database.
5. If either database is behind the witness, reconcile it forward to the witness checkpoint and verify equality.
6. Construct a candidate checkpoint that binds the exact signed metadata and artifact digests.
7. Atomically compare-and-append the candidate against the witness's previously read checkpoint.
8. Verify the returned receipt and re-read the witness to confirm the candidate is still the latest checkpoint.
9. Advance the anchor PostgreSQL mirror, then the application PostgreSQL mirror, using atomic compare-and-set. Verify both equal the witness.
10. Only then permit model deserialization/use.

If a mirror update fails after the witness append, the operation fails closed. A retry must read the witness and reconcile both mirrors forward. It must not append a second checkpoint for the same operation. If witness availability or receipt verification fails, do not load a model.

A candidate release sequence is strictly greater than the current witness sequence. An exact idempotent retry may return the existing receipt only when every checkpoint field and operation ID matches. A same-sequence record with any different digest is a conflict.

## 5. Bootstrap, restore and break-glass

**Bootstrap:** provision the witness identity and scope through a customer-controlled, dual-approved process. Record the genesis checkpoint and its receipt before enabling model loading. If the databases contain state but the witness is empty, fail closed; do not silently bootstrap from either database.

**Restore/failover:** query the witness first. Reconcile lower database copies to the exact witness checkpoint. If any database is ahead, or the witness history is missing, forked or unverifiable, stop model loading and raise a security incident. Preserve snapshot IDs, witness receipts, operator/approver identities and reconciliation evidence in the customer's independent audit system.

**Break-glass:** rollback is not an ordinary recovery action. It requires separate policy, at least two authorized approvers, a signed authorization, a documented target artifact digest and sequence, and a new immutable witness event that explicitly records the exceptional transition. The normal monotonic update API must never permit deletion or lowering of history.

## 6. Independence and backend acceptance requirements

Before selecting a backend, verify all of the following from provider documentation and a customer-controlled test:

- retention is enforced against ordinary administrators and cannot be shortened/deleted by the application or anchor-service identity;
- the witness's current head can be queried after a complete restore of both PostgreSQL databases;
- compare-and-append is atomic or a trusted serialization service supplies equivalent linearizable semantics;
- accepted writes survive process restart, service failover and the provider's documented disaster-recovery events;
- receipts/proofs can be verified independently of the witness database;
- writer, retention administrator, recovery administrator and application identities are separated;
- credentials and signing keys are customer-managed, rotatable and revocable;
- immutable audit export, retention period, legal hold and incident access are documented;
- availability failure causes model loading to fail closed, with a documented operational recovery path.

A generic WORM object store must not be treated as a compare-and-set ledger unless its conditional-write and read-after-write guarantees are explicitly established. If the selected service cannot provide atomic per-scope sequencing, place a separately trusted sequencing authority in front of it and document that authority as part of the threat boundary.

## 7. Required test plan

Use synthetic tenant/deployment identifiers, disposable databases and test keys.

1. Append sequence 45, restore both PostgreSQL mirrors to sequence 40, restart all services, and prove the witness still reports 45 and both mirrors reconcile to 45.
2. Attempt sequence 44, sequence 45 with a different version, and sequence 46 with a stale predecessor; all must be rejected.
3. Submit two concurrent sequence-46 candidates; exactly one checkpoint may become the head.
4. Simulate timeout after a successful witness append; retry with the same operation ID and prove exactly one immutable event exists.
5. Restore the anchor database from an old snapshot; prove the witness detects the lower mirror and restores it forward.
6. Restore the witness test environment from an older snapshot; prove the chosen backend's independent retention/recovery mechanism prevents head rollback, or explicitly fail backend acceptance.
7. Remove, alter or replay a receipt; verification must fail before model deserialization.
8. Make witness unavailable, unauthenticated or ambiguous; model deserialization must not run.
9. Present either PostgreSQL mirror ahead of the witness; recovery must fail closed without promoting the mirror.
10. Verify tenant/deployment/product scope isolation and unauthorized access rejection at the witness boundary.
11. Exercise process restart, service failover, key rotation/revocation and independent audit export.
12. Run a customer-like restore/failover drill and have the independent assessor inspect the evidence.

## 8. Delivery sequence and exit criteria

- **Design review:** approve the checkpoint canonicalization, witness contract, trust boundaries, idempotency and update ordering with the independent assessor.
- **Backend selection:** choose a customer-approved immutable ledger/WORM or hardware-backed monotonic service only after its actual guarantees are evidenced.
- **Adapter implementation:** add a production adapter behind the protocol; test doubles must be labelled test-only.
- **Integration:** make the witness authoritative and both PostgreSQL stores mirrors; ensure every failure path blocks model loading.
- **Recovery proof:** complete restore, failover, concurrency and ambiguous-timeout drills against the real selected backend.
- **Independent closure:** Gigabrute (or another independent assessor) reviews the implementation and evidence before GIGA-SEC-02 is marked closed or PR #5/#8 is considered merge-ready.

Until these criteria pass, the witness remains a design proposal. The current HTTPS/PostgreSQL anchor is still a reference implementation and CyberShield is not production-certified.
