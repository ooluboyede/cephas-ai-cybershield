"""Provision an ephemeral PostgreSQL role for the DIRMC CI integration test.

This script is for disposable CI databases only. It is not a customer deployment tool.
"""
from __future__ import annotations

import os
from pathlib import Path

import psycopg
from psycopg import sql

ADMIN_DSN = os.environ.get(
    "CEPHAS_DIRMC_ADMIN_DSN",
    "postgresql://postgres:postgres@localhost:5432/postgres",
)
RUNTIME_ROLE = "dirmc_ci_runtime"
RUNTIME_PASSWORD = os.environ.get("CEPHAS_DIRMC_TEST_PASSWORD", "ci-only-dirmc-password")
TENANT = os.environ.get("CEPHAS_DIRMC_TEST_TENANT", "dirmc-ci-tenant")
MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "migrations"
    / "0001_dirmc_device_storage_0_4_5.sql"
)


def main() -> None:
    with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
        connection.execute(MIGRATION.read_text(encoding="utf-8"), prepare=False)
        exists = connection.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (RUNTIME_ROLE,)
        ).fetchone()
        if exists:
            connection.execute(
                sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(
                    sql.Identifier(RUNTIME_ROLE), sql.Literal(RUNTIME_PASSWORD)
                )
            )
        else:
            connection.execute(
                sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD {}").format(
                    sql.Identifier(RUNTIME_ROLE), sql.Literal(RUNTIME_PASSWORD)
                )
            )

        connection.execute(
            sql.SQL("REVOKE ALL ON public.dirmc_runtime_principal_scope FROM {}").format(
                sql.Identifier(RUNTIME_ROLE)
            )
        )
        connection.execute(
            sql.SQL("REVOKE ALL ON public.dirmc_device_fraud_associations FROM {}").format(
                sql.Identifier(RUNTIME_ROLE)
            )
        )
        connection.execute(
            sql.SQL("REVOKE ALL ON public.dirmc_device_association_audit FROM {}").format(
                sql.Identifier(RUNTIME_ROLE)
            )
        )
        connection.execute(
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                sql.Identifier(RUNTIME_ROLE)
            )
        )
        connection.execute(
            sql.SQL(
                "GRANT SELECT, INSERT ON public.dirmc_device_fraud_associations TO {}"
            ).format(sql.Identifier(RUNTIME_ROLE))
        )
        connection.execute(
            sql.SQL("GRANT SELECT ON public.dirmc_device_association_audit TO {}").format(
                sql.Identifier(RUNTIME_ROLE)
            )
        )
        connection.execute(
            sql.SQL(
                "GRANT EXECUTE ON FUNCTION "
                "public.dirmc_principal_scope_authorized(TEXT,TEXT,TEXT,TEXT,TEXT) TO {}"
            ).format(sql.Identifier(RUNTIME_ROLE))
        )
        connection.execute(
            """
            INSERT INTO public.dirmc_runtime_principal_scope
                (db_role, tenant_id, deployment_id, environment, product_id, business_unit_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (RUNTIME_ROLE, TENANT, "deployment-a", "test", "cybershield", "bu-a"),
        )


if __name__ == "__main__":
    main()
