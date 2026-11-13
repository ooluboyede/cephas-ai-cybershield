# DIRMC 0.4.9 — Connection-pool security and principal preservation

## Implementation

`PostgresDeviceAssociationStore` now accepts an optional connection releaser. For psycopg_pool, supply `pool.getconn` and `pool.putconn`; for direct connections, the default releaser closes the connection. Transaction-local PostgreSQL GUCs continue to be set only inside the operation transaction.

The caller remains responsible for a pool reset policy. The CI validator uses a one-connection pool per independently authenticated matrix principal and a reset callback that rolls back any open transaction, runs `RESET ALL` and `RESET ROLE`, and commits before reuse.

## Live PostgreSQL assertions

The PostgreSQL 16 CI test:
- Performs a legitimate write and read through each pool.
- Captures `pg_backend_pid()`, `session_user` and `current_user`.
- Deliberately writes an attacker-controlled session-level tenant GUC, returns the connection, and verifies the pool reset removes it.
- Attempts a forged cross-principal write and requires PostgreSQL RLS to reject it.
- Performs a legitimate write after the failed transaction.
- Verifies the same backend is reused, authenticated `session_user` and `current_user` are unchanged, transaction status is idle, and transaction-local DIRMC scope GUCs are cleared.

## Deployment requirements and limitations

This test is a controlled reference configuration, not proof that every pool/proxy implementation is safe. Production deployments must configure and test equivalent reset-on-return semantics, use separate authenticated principals per tenant/deployment/environment/product/BU or a trusted proxy that preserves the original authenticated identity, and prohibit caller-controlled `SET ROLE`/principal switching. A pool must never be shared across security principals unless it authenticates and preserves the intended principal per checkout under a separately reviewed design.

This does not certify customer TLS/mTLS, HA, failover, backup encryption, external immutable witness, or protection against database superusers and trusted migration owners. DIRMC still produces recommendations for human review; it does not automatically block devices.
