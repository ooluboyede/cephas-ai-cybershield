# DIRMC durable association storage — 0.4.4

## Implemented

The DIRMC reference store now persists pseudonymous device-to-case associations in a
customer-local SQLite database.

- Scope keys include tenant, deployment, environment, product and business unit.
- Device keys remain versioned HMAC-SHA-256 pseudonyms; raw identifiers are not accepted.
- A device/case association is unique within its full scope.
- Exact retries are idempotent; a retry that changes an existing case association is rejected.
- Association insertion and its audit row are committed in one SQLite transaction.
- The audit table has database triggers that reject update and delete operations.
- Reads require the server-authenticated `TrustedProductScope` and filter every scope dimension.
- Database files are created with best-effort owner-only POSIX permissions.

## Scope and operational limitations

This SQLite adapter is an initial single-node reference implementation. It is not a
production multi-node database, tamper-proof ledger, or independently administered witness.
A privileged host/database administrator can still alter or replace the SQLite file and
its WAL. Filesystem permissions and append-only triggers are not a substitute for encrypted
storage, independent backups, external audit export, or a separately administered witness.

For production:
- Use a customer-managed PostgreSQL adapter with database-enforced tenant and business-unit
  isolation (RLS where appropriate), least-privilege roles and server-verified context.
- Use customer-managed encryption at rest and key lifecycle controls.
- Define retention, deletion, legal hold, backup and restore procedures.
- Export audit evidence to an independently administered append-only system.
- Test concurrent writes, backup restoration, tamper detection and tenant/deployment isolation.

## Not yet implemented

- PostgreSQL adapter and RLS policies.
- Retention/deletion lifecycle and privacy erasure workflow.
- Durable human-review records and reviewer RBAC.
- Product-source adapters and HMAC secret provisioning/rotation.
- API/service-layer integration with authenticated request context.
- Operational monitoring, external audit export and independent security review.

No automatic device blocking is performed. Storage does not change the DIRMC human-review
requirement.
