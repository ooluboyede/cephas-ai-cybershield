# DIRMC PostgreSQL storage — 0.4.5

## Implemented in this gate

- A PostgreSQL DB-API adapter accepting a customer-supplied connection factory (compatible with psycopg-style transaction/cursor APIs).
- A customer-applied schema migration defining association and audit tables, uniqueness, device-key format checks and lookup index.
- Transaction-local scope settings for tenant, deployment, environment, allowed products and business unit.
- Forced row-level security policies on both tables. Transaction-local scope settings are parameterized and additionally checked against a database-admin-maintained mapping from the actual `session_user` login principal to tenant/deployment/environment/product/business-unit scope. GUCs alone are not treated as an authorization boundary.
- Atomic association insertion and audit insertion in one transaction. Exact retries are idempotent; conflicting case replays are rejected.
- Audit UPDATE and DELETE triggers; runtime-role grants are intentionally a separate customer-admin provisioning step.

## Required deployment configuration

1. Apply the migration with a dedicated schema-owner/migration identity.
2. Create a distinct login principal for each authorised tenant/deployment/business-unit/product boundary (or use a trusted database proxy that establishes an equivalent non-spoofable `session_user`). Register its exact scope in `dirmc_runtime_principal_scope` with the migration identity. Grant it EXECUTE on `dirmc_principal_scope_authorized`, but no access to the scope-mapping table. The runtime role must not own tables, have BYPASSRLS, or alter schema/triggers.
3. Grant association SELECT/INSERT only. Grant audit SELECT/INSERT only; do not grant UPDATE, DELETE, TRUNCATE, DDL or trigger-management privileges.
4. Configure TLS, database authentication, secret rotation, encrypted storage and customer-managed backups.
5. Construct TrustedProductScope only from authenticated server-side session/mTLS identity. Never accept tenant, deployment, product allowlist or business-unit scope from request payloads.
6. Use a fresh connection per operation or a safely pooled connection that preserves the correct database login principal and resets transaction state; adapter settings are transaction-local. Do not multiplex unrelated tenant scopes through one shared login principal.

## Validation boundary

The migration and adapter are a reference implementation. A real PostgreSQL service is required to validate RLS behavior, principal-to-scope provisioning, least-privilege role grants, concurrent insert races, restart durability, backup/restore and cross-tenant/deployment/BU isolation. Unit tests without PostgreSQL cannot certify those controls. Audit triggers are not an independent immutable witness: a database owner/superuser can alter schema or data. Production still requires independent audit export/witnessing and restore/rollback testing.

No automatic device blocking is implemented. Recommendations remain pending human review; this adapter only persists associations.
