# DIRMC 0.4.7 — PostgreSQL durability and recovery validation

## CI coverage

The disposable PostgreSQL 16 CI job performs a logical backup/restore round trip using the matching `postgres:16` container's `pg_dump` and `pg_restore` binaries. The script is restricted to a local CI database named `postgres`; it refuses non-local hosts, unexpected source database names, and missing admin credentials. The restore database is a fixed disposable CI name. This is not a customer backup/restore utility.

The gate verifies:

1. A committed association remains readable after the writer connection closes and a fresh connection is opened.
2. A PostgreSQL 16 custom-format logical backup is created and restored into a separate disposable database.
3. Restored association data remains readable through the restricted runtime login.
4. Restored RLS remains fail-closed for a business-unit scope not mapped to that authenticated database login.
5. The restored audit trigger creates exactly one audit row for a post-restore association insert.
6. The post-restore write remains readable through a further fresh connection.

The restore test reapplies least-privilege grants because ownership and ACLs are excluded from the dump. The restored principal-scope mapping, RLS policies, functions and triggers are exercised.

## Important limitations

- This is a logical backup/restore smoke test in an ephemeral single-node PostgreSQL service. It is not a physical backup, point-in-time recovery, WAL archive, replica promotion, HA/failover, cross-region DR or customer restore rehearsal.
- It does not prove protection against a privileged database administrator rolling back both association and audit tables.
- It does not certify customer backup encryption, retention, key custody, recovery objectives, network/TLS/mTLS, connection pools or operational runbooks.
- The reference audit table remains within the same database trust domain. An independently administered immutable witness and independently verified restore/rollback evidence remain production gates.
- Device actions remain recommendations only; human review is mandatory and no enforcement path is added.

## Acceptance

The 0.4.7 CI gate requires the PostgreSQL backup/restore script, Ruff and the complete pytest suite to pass on the exact PR head. Passing CI is not customer-environment certification or independent security approval.
