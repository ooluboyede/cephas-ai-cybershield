"""Validate DIRMC connection-pool reset and authenticated-principal isolation."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.pq import TransactionStatus
from psycopg_pool import ConnectionPool

from cybershield_ml.contracts import TrustedProductScope
from cybershield_ml.device_intelligence import DeviceFraudAssociation
from cybershield_ml.device_postgres_storage import PostgresDeviceAssociationStore

ADMIN_DSN = os.environ.get(
    "CEPHAS_DIRMC_ADMIN_DSN",
    "postgresql://postgres:postgres@localhost:5432/postgres",
)
PASSWORD = os.environ.get("CEPHAS_DIRMC_MATRIX_PASSWORD", "ci-only-matrix-password")
BASE = conninfo_to_dict(ADMIN_DSN)
DEVICE = "hmac-sha256:v1:" + "f" * 64
NOW = datetime.now(timezone.utc)
PRINCIPALS = (
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_a_cyber", "tenant-a", "deployment-a", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_b_bu_a_cyber", "tenant-a", "deployment-b", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_b_cyber", "tenant-a", "deployment-a", "cybershield", "bu-b"),
    ("dirmc_ci_matrix_tenant_b_deploy_a_bu_a_cyber", "tenant-b", "deployment-a", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_a_payroll", "tenant-a", "deployment-a", "payroll", "bu-a"),
)


def scope_for(tenant: str, deployment: str, product: str, business_unit: str):
    return TrustedProductScope(
        tenant_id=tenant,
        deployment_id=deployment,
        environment="test",
        allowed_products=frozenset({product}),
        business_unit_id=business_unit,
    )


def item_for(scope: TrustedProductScope, case_id: str) -> DeviceFraudAssociation:
    product = next(iter(scope.allowed_products))
    return DeviceFraudAssociation(
        tenant_id=scope.tenant_id,
        deployment_id=scope.deployment_id,
        environment=scope.environment,
        product_id=product,
        business_unit_id=scope.business_unit_id or "",
        device_key=DEVICE,
        case_id=case_id,
        association_status="confirmed",
        evidence_ref="dirmc-pool-security-ci",
        occurred_at=NOW,
    )


def dsn_for(role: str) -> str:
    return make_conninfo(**{
        **BASE,
        "dbname": "postgres",
        "user": role,
        "password": PASSWORD,
    })


def reset_connection(connection: psycopg.Connection) -> None:
    """Remove session-level state before a connection is reused."""
    if connection.info.transaction_status != TransactionStatus.IDLE:
        connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute("RESET ALL")
        cursor.execute("RESET ROLE")
    connection.commit()


def assert_scope_gucs_cleared(connection: psycopg.Connection) -> None:
    values = connection.execute(
        """SELECT
            current_setting('cephas.tenant_id', true),
            current_setting('cephas.deployment_id', true),
            current_setting('cephas.environment', true),
            current_setting('cephas.allowed_products', true),
            current_setting('cephas.business_unit_id', true)"""
    ).fetchone()
    assert all(value in (None, "") for value in values), (
        f"transaction-local scope leaked into pooled session: {values}"
    )


def main() -> None:
    checked = 0
    for role, tenant, deployment, product, business_unit in PRINCIPALS:
        scope = scope_for(tenant, deployment, product, business_unit)
        with ConnectionPool(
            conninfo=dsn_for(role),
            min_size=1,
            max_size=1,
            timeout=10,
            reset=reset_connection,
        ) as pool:
            store = PostgresDeviceAssociationStore(pool.getconn, pool.putconn)
            first_case = f"pool-own-{uuid4().hex}"
            assert store.append(scope, item_for(scope, first_case)) is True
            assert any(
                row.case_id == first_case
                for row in store.list_for_device(
                    scope, product_id=product, device_key=DEVICE
                )
            )

            # Capture the backend and authenticated principal, then poison a
            # session-level GUC. Pool reset must remove it before next checkout.
            connection = pool.getconn()
            try:
                backend_pid, session_user, current_user = connection.execute(
                    "SELECT pg_backend_pid(), session_user, current_user"
                ).fetchone()
                assert session_user == role
                assert current_user == role
                connection.execute(
                    "SELECT set_config('cephas.tenant_id', 'attacker-session-value', false)"
                )
                connection.commit()
            finally:
                pool.putconn(connection)

            # A forged scope from another principal must fail at RLS. The
            # failed transaction is returned/reset, and the same backend must
            # remain usable for its own authenticated scope afterwards.
            other = next(entry for entry in PRINCIPALS if entry[0] != role)
            _, other_tenant, other_deployment, other_product, other_bu = other
            forged_scope = scope_for(
                other_tenant, other_deployment, other_product, other_bu
            )
            try:
                store.append(forged_scope, item_for(forged_scope, f"forged-{uuid4().hex}"))
            except psycopg.errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError(f"{role} wrote under another principal's scope")

            second_case = f"pool-after-failure-{uuid4().hex}"
            assert store.append(scope, item_for(scope, second_case)) is True

            connection = pool.getconn()
            try:
                pid, session_user_after, current_user_after = connection.execute(
                    "SELECT pg_backend_pid(), session_user, current_user"
                ).fetchone()
                assert pid == backend_pid, "test did not reuse the same pooled backend"
                assert session_user_after == role
                assert current_user_after == role
                assert connection.info.transaction_status == TransactionStatus.IDLE
                assert_scope_gucs_cleared(connection)
            finally:
                pool.putconn(connection)
            checked += 1

    print(
        "DIRMC pool security passed: "
        f"{checked} authenticated principal pools; backend reuse, GUC reset, "
        "failed-transaction recovery and principal preservation verified"
    )


if __name__ == "__main__":
    main()
