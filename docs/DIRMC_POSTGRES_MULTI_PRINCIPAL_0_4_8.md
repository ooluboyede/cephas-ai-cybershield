# DIRMC 0.4.8 — Multi-principal PostgreSQL isolation

## Matrix

The disposable PostgreSQL 16 CI environment provisions five separate LOGIN identities, each configured NOSUPERUSER, NOCREATEDB, NOCREATEROLE and NOINHERIT:

| Principal boundary | Provisioned scope |
|---|---|
| Baseline | tenant-a / deployment-a / test / cybershield / bu-a |
| Deployment | tenant-a / deployment-b / test / cybershield / bu-a |
| Business unit | tenant-a / deployment-a / test / cybershield / bu-b |
| Tenant | tenant-b / deployment-a / test / cybershield / bu-a |
| Product | tenant-a / deployment-a / test / payroll / bu-a |

Each login is independently mapped by the database administrator to one exact row in `dirmc_runtime_principal_scope`. Each role receives only schema USAGE, association SELECT/INSERT, audit SELECT and EXECUTE on the scope-check function. No matrix role is granted membership in another matrix role, BYPASSRLS, table ownership, mapping-table access, schema CREATE or audit INSERT.

## Assertions

The validator logs in separately as every principal, writes and reads its own scoped association, then attempts every other principal's exact scope. Every cross-principal read must return no rows; every forged-scope write must be rejected by PostgreSQL RLS.

It queries role memberships specifically among the five matrix identities and attempts `SET ROLE` to every peer identity from each login. Every peer-role switch must fail. PostgreSQL predefined roles outside the matrix are not incorrectly treated as customer matrix identities; the test explicitly rejects membership or switching to any other provisioned matrix login.

This tests the database enforcement boundary, not just application-level scope validation. It does not prove security against database superusers, trusted migration owners, compromised credentials, a misconfigured connection proxy, or a customer application that authenticates the wrong user.

## Production boundary

The matrix is disposable CI evidence. Customer deployment still requires independently provisioned login identities or a trusted DB proxy that preserves authenticated principal identity, tested connection-pool reset behaviour, TLS/mTLS, least-privilege grants and customer security review. Database audit rows remain in the same trust domain; independent immutable witness remains a separate production gate. Device decisions remain human-reviewed recommendations; no automatic blocking is introduced.
