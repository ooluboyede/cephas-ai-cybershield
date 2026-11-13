# DIRMC 0.4.6 — PostgreSQL isolation and audit validation

## CI implementation
The CyberShield GitHub Actions workflow now starts an ephemeral PostgreSQL 16 service. It installs psycopg, applies the DIRMC 0.4.5 migration using the database administrator, provisions a dedicated non-owner login, maps that login to exactly one tenant/deployment/environment/product/business-unit scope, and grants only the permissions required by the adapter.

The runtime principal receives:
- USAGE on the public schema
- SELECT and INSERT on the association table
- SELECT on the audit table
- EXECUTE on the principal-to-scope authorization function

It does not receive:
- access to the principal-scope mapping table
- direct audit INSERT permission
- UPDATE, DELETE, TRUNCATE, DDL, schema CREATE, table ownership or BYPASSRLS

## Live assertions
The PostgreSQL test verifies:
1. Eight concurrent identical association submissions result in exactly one inserted association.
2. An exact replay is idempotent and does not create another audit event.
3. The database trigger creates exactly one audit row for the accepted association.
4. The runtime login cannot create an audit-only row.
5. A BU, tenant or deployment scope without an exact login mapping cannot read the association.
6. Writes under unmapped tenant/deployment scopes are rejected by PostgreSQL RLS.

## Boundaries still open
- This CI setup tests one provisioned runtime principal. It does not yet prove a matrix of multiple independently authenticated customer logins across several tenants, deployments, products and business units.
- It does not certify customer-managed connection pools, mTLS, backup/restore, restart durability, disaster recovery, database failover or rollback resistance.
- The PostgreSQL audit table is still controlled by the same database trust domain. A privileged database administrator can alter it; independent immutable witness/export remains a separate production gate.
- No automatic device enforcement is introduced. Recommendations remain subject to human review.

## Acceptance
The 0.4.6 CI gate passes only when Ruff and the complete pytest suite pass on the exact PR head, including the live PostgreSQL test. Customer-environment validation and independent security review remain required before production acceptance.
