# DIRMC PostgreSQL storage — 0.4.5

## Implemented in this gate

- A PostgreSQL DB-API adapter accepting a customer-supplied connection factory (compatible with psycopg-style transaction/cursor APIs).
- A customer-applied schema migration defining association and audit tables, uniqueness, device-key format checks and lookup index.
- Transaction-local scope settings for tenant, deployment, environment, allowed products and business unit.
- Forced row-level security policies on both tables. Scope values are installed inside each transaction and parameterized.
- Atomic association insertion and audit insertion in one transaction. Exact retries are idempotent; conflicting case replays are rejected.
- Audit UPDATE and DELETE triggers; runtime-role grants are intentionally a separate customer-admin provisioning step.

## Required deployment configuration

1. Apply the migration with a dedicated schema-owner/migration identity.
2. Create a separate runtime role that does not own the tables, has no BYPASSRLS, and cannot alter schema or triggers.
3. Grant association SELECT/INSERT only. Grant audit SELECT/INSERT only; do not grant UPDATE, DELETE, TRUNCATE, DDL or trigger-management privileges.
4. Configure TLS, database authentication, secret rotation, encrypted storage and customer-managed backups.
5. Construct TrustedProductScope only from authenticated server-side session/mTLS identity. Never accept tenant, deployment, product allowlist or business-unit scope from request payloads.
6. Use a fresh connection per operation or a safely pooled connection that resets transaction state; adapter settings are transaction-local.

## Validation boundary

The migration and adapter are a reference implementation. A real PostgreSQL service is required to validate RLS behavior, least-privilege role grants, concurrent insert races, restart durability, backup/restore and cross-tenant/deployment/BU isolation. Unit tests without PostgreSQL cannot certify those controls. Audit triggers are not an independent immutable witness: a database owner/superuser can alter schema or data. Production still requires independent audit export/witnessing and restore/rollback testing.

No automatic device blocking is implemented. Recommendations remain pending human review; this adapter only persists associations.
