# Release-Floor Backup, Restore and Failover Security Gate

Status: **reference implementation in progress**. The repository now includes an HTTPS/mTLS anchor client, a customer-operated WSGI reference service, a separate anchor PostgreSQL schema, and a fail-closed anchor-first adapter. Live service/database/TLS deployment validation and independent customer recovery drills are not yet complete.

## Objective

Prevent a PostgreSQL backup restore, replica promotion, failover, or operator action from silently lowering the minimum accepted signed model release sequence.

The current `PostgresReleaseStateStore` is atomic during normal database operation. It is not independently protected against restoration of an older database snapshot. A database cannot be the sole authority for its own anti-rollback recovery record.

## Security decision

Use a **customer-controlled, independently administered HTTPS release-floor service** as the recovery authority. The reference service requires mutual TLS plus a bearer token scoped to tenant/deployment, and persists monotonic floors by tenant/deployment/product in a separate PostgreSQL database. The anchor database must be outside the application PostgreSQL backup/restore and administrative boundary.

The reference implementation is in services/release_anchor/; client and composition code are in src/cybershield_ml/release_anchor.py. The service uses a dedicated PostgreSQL database, mTLS, scoped bearer tokens, and an append-only audit table. This is a reference implementation, not a certified production service. Customer deployment must independently validate service HA, database durability, audit retention, backup/restore separation, certificate/token lifecycle and operational controls. **Threat boundary:** this protects an application-database restore only while the anchor remains trustworthy. Restoring the anchor database itself from an old snapshot would also roll back its local audit table. An independent immutable/WORM witness or hardware-backed monotonic checkpoint is still required to protect against rollback or compromise of the anchor's own database/admin boundary; that integration is not implemented.

A process-local dictionary, ordinary file on the same database host, second table in the same PostgreSQL cluster, or copy included in the same backup set is **not** an independent anchor.

## Implemented reference components

- HttpReleaseFloorAnchor: HTTPS-only client, server-certificate verification, mandatory mTLS client certificate, scoped bearer token, no redirects, bounded timeout and strict response validation.
- services/release_anchor/app.py: threaded WSGI reference service requiring TLS client certificates and per-request bearer-token scope authorization.
- services/release_anchor/schema.sql: separate tenant/deployment/product release floor and append-only audit table.
- AnchoredReleaseStateStore: anchor-first state coordination; reconciles a lower PostgreSQL floor forward, refuses database-ahead-of-anchor ambiguity, and fails closed when the anchor is unavailable.
- PostgreSQL application state now keys by (tenant_id, deployment_id, product). Existing customer databases require the controlled V2 migration in release_state.py; review deployment mapping before applying.

## Required anchor contract

The future adapter must provide operations equivalent to:

- `read_floor(tenant_id, product) -> (release_sequence, version) | None`
- `advance_floor(tenant_id, product, release_sequence, version)`

`advance_floor` must be an atomic compare-and-set:
- accept a strictly higher positive sequence;
- allow an idempotent repeat of the same sequence and version;
- reject a lower sequence;
- reject the same sequence paired with a different version;
- never delete or lower an existing floor;
- fail closed on unavailable, corrupt, unauthenticated, or ambiguous state.

The anchor must authenticate callers, enforce tenant/product scoping server-side, protect administrative access separately from the application database, and produce an auditable record of accepted advances. Its implementation-specific durability, backup, retention, access-control and availability guarantees require independent validation.

## Safe installation ordering

The anchor is authoritative. The database is a transactional operational copy.

1. Verify publisher signature, metadata, artifact digest, tenant and deployment context before deserialization.
2. Read the anchor floor. If the anchor is unavailable or cannot authenticate the request, stop; do not load the model.
3. Read the PostgreSQL floor for the same tenant/product.
4. If PostgreSQL is below the anchor, advance PostgreSQL to the anchor's exact sequence/version before considering the candidate. This repairs a database restored from an older backup.
5. If PostgreSQL is ahead of the anchor, **fail closed** and require audited recovery reconciliation. Do not automatically trust a database-only higher value; it may reflect tampering or an interrupted/legacy workflow.
6. Ask the anchor to atomically advance to the candidate sequence/version. A stale candidate or same-sequence/different-version conflict is rejected.
7. Persist the resulting anchor floor into PostgreSQL using its atomic compare-and-set.
8. Only after both stores agree at the accepted floor may the loader deserialize the signed model.

This ordering intentionally makes the anchor advance first. If the anchor advances but the PostgreSQL write fails, the operation fails closed; a retry sees the higher anchor and repairs PostgreSQL forward. The model is not loaded during the partial state. Do not reverse this ordering: committing PostgreSQL first could leave a database-only floor that disappears on restore.

## Restore and failover recovery

After any restore, replica promotion, failover, or suspected state loss:

1. Keep model loading disabled until the anchor is reachable and authenticated.
2. Read the anchor and restored PostgreSQL floors for each affected tenant/product.
3. If PostgreSQL is lower, reconcile it upward to the anchor's exact floor.
4. If PostgreSQL is higher, stop and open a security incident/recovery ticket. Require an authorized, independently evidenced decision before changing either record.
5. Record database snapshot identifier, restore/failover event, anchor floor, database floor, actor, approver, reason, and reconciliation result in the customer's audit system.
6. Re-enable loading only after equality is verified and the recovery event is audited.

An emergency downgrade is not an ordinary restore. It requires a separate, explicit break-glass policy, independent approvers, a signed authorization, a documented target digest and sequence, and an immutable audit trail. This design does not authorize or implement emergency downgrade.

## Required automated tests

Use synthetic tenant IDs, test keys and disposable infrastructure only.

- Anchor rejects lower sequence and same-sequence/different-version values.
- Anchor accepts an idempotent same-sequence/same-version repeat.
- Anchor state survives a new process and independent client instance.
- Simulated backup restore: anchor records sequence 45; PostgreSQL is restored to sequence 40; recovery reconciles PostgreSQL to 45; sequence 40 and all lower releases remain rejected.
- Anchor unavailable, unauthenticated, malformed, or ambiguous: loader fails closed and does not call Joblib.
- PostgreSQL ahead of anchor: loader fails closed and does not auto-promote the anchor.
- Anchor advances to 46 but PostgreSQL write fails: no model deserialization; retry reconciles PostgreSQL to 46.
- Concurrent installation attempts cannot lower either floor.
- Tenant/product boundaries are enforced by the anchor itself, not merely by caller-supplied keys.
- Failover to a second application instance observes the same anchor floor.
- Restore and failover drills produce the required audit evidence.

## Acceptance criteria

This gate is not complete until all of the following are true:

1. A concrete customer-approved anchor backend is selected and its atomicity, durability, authentication, authorization, audit and recovery properties are documented.
2. An implementation is added behind a narrow interface; test doubles are not represented as production adapters.
3. The loader enforces the anchor-before-database ordering and fails closed for every ambiguous state.
4. Automated tests cover the failure cases above, including a real independent anchor service or hardware-backed test environment where available.
5. A restore from a snapshot older than the current release floor is executed successfully in a disposable customer-like environment.
6. A failover drill proves the promoted instance cannot accept a stale model.
7. Recovery evidence is reviewed by the independent assessor before GIGA-SEC-02 is marked closed.

## Current implementation boundary

The repository now has a PostgreSQL adapter with atomic per-tenant/deployment/product compare-and-set, an HTTPS/mTLS reference anchor service, an anchor client, and fail-closed composition tests. The reference tests simulate a restored lower database floor and prove reconciliation to the independent anchor. They do not yet prove live HTTPS/mTLS interoperability, a real separate anchor PostgreSQL instance, service failover, independent anchor backup/restore, an external immutable witness, immutable audit retention, or a customer-environment recovery drill. Do not describe production backup/restore anti-rollback as certified until those gates pass.
