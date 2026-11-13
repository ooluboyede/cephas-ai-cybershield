# DIRMC 0.4.7 — PostgreSQL durability and recovery validation

## CI coverage

The disposable PostgreSQL 16 CI job now performs a logical backup/restore round trip using PostgreSQL's `pg_dump` and `pg_restore` tools. The validation script is deliberately restricted to a local CI database named `postgres`; it refuses non-local hosts and any other source database name. It is not a customer backup/restore utility.

The gate verifies:

1. A committed association remains readable after the writer connection is closed and a fresh connection is opened (connection/process-restart durability).
2. A custom-format logical backup can be restored into a newly created, separate database.
3. Restored association data remains readable through the restricted runtime login.
4. Restored RLS remains fail-closed for a business-unit scope that is not mapped to that authenticated database login.
5. The restored audit trigger still creates exactly one audit row for a post-restore association insert.
6. The post-restore write is readable through a further fresh connection.

The restore test reapplies least-privilege grants to the restored database because it deliberately excludes ACLs and ownership from the dump. It relies on the restored database's principal-scope mapping data, RLS policies, functions and triggers.

## Important limitations

- This is a logical backup/restore smoke test in an ephemeral single-node PostgreSQL service. It is not a physical backup, point-in-time recovery, WAL archive, replica promotion, HA/failover, cross-region DR or customer restore rehearsal.
- It does not prove protection against a privileged database administrator rolling back both the association and audit tables.
- It does not certify customer backup encryption, retention, key custody, recovery-point/recovery-time objectives, network/TLS/mTLS, connection pools, or operational runbooks.
- The reference PostgreSQL audit table remains inside the same database trust domain. An independently administered immutable witness and independently verified restore/rollback evidence remain production gates.
- Device actions remain recommendations only; human review is mandatory and no enforcement path is added.

## Acceptance

The 0.4.7 CI gate requires the PostgreSQL backup/restore script, Ruff, and the complete pytest suite to pass on the exact PR head. Passing CI is not customer-environment certification or independent security approval.
