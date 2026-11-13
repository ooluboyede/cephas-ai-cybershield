"""Provision isolated non-owner PostgreSQL principals for DIRMC matrix CI.

Disposable CI only. This creates fixed dirmc_ci_matrix_* login roles.
"""
from __future__ import annotations

import os

import psycopg
from psycopg import sql

ADMIN_DSN = os.environ.get(
    "CEPHAS_DIRMC_ADMIN_DSN",
    "postgresql://postgres:postgres@localhost:5432/postgres",
)
PASSWORD = os.environ.get("CEPHAS_DIRMC_MATRIX_PASSWORD", "ci-only-matrix-password")

SCOPES = (
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_a_cyber", "tenant-a", "deployment-a", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_b_bu_a_cyber", "tenant-a", "deployment-b", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_b_cyber", "tenant-a", "deployment-a", "cybershield", "bu-b"),
    ("dirmc_ci_matrix_tenant_b_deploy_a_bu_a_cyber", "tenant-b", "deployment-a", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_a_payroll", "tenant-a", "deployment-a", "payroll", "bu-a"),
)


def main() -> None:
    with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
        for role, tenant, deployment, product, business_unit in SCOPES:
            exists = connection.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
            ).fetchone()
            if exists:
                connection.execute(
                    sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
                    .format(sql.Identifier(role), sql.Literal(PASSWORD))
                )
            else:
                connection.execute(
                    sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
                    .format(sql.Identifier(role), sql.Literal(PASSWORD))
                )
            connection.execute(
                sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role))
            )
            connection.execute(
                sql.SQL("GRANT SELECT, INSERT ON public.dirmc_device_fraud_associations TO {}")
                .format(sql.Identifier(role))
            )
            connection.execute(
                sql.SQL("GRANT SELECT ON public.dirmc_device_association_audit TO {}")
                .format(sql.Identifier(role))
            )
            connection.execute(
                sql.SQL(
                    "GRANT EXECUTE ON FUNCTION "
                    "public.dirmc_principal_scope_authorized(TEXT,TEXT,TEXT,TEXT,TEXT) TO {}"
                ).format(sql.Identifier(role))
            )
            connection.execute(
                """INSERT INTO public.dirmc_runtime_principal_scope
                   (db_role, tenant_id, deployment_id, environment, product_id, business_unit_id)
                   VALUES (%s, %s, %s, 'test', %s, %s)
                   ON CONFLICT DO NOTHING""",
                (role, tenant, deployment, product, business_unit),
            )
    print(f"Provisioned {len(SCOPES)} distinct least-privilege DIRMC matrix principals")


if __name__ == "__main__":
    main()
