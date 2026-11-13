"""Exercise DIRMC PostgreSQL durability and logical backup/restore in disposable CI.

Uses the matching PostgreSQL 16 client tools from the postgres:16 container,
avoiding accidental cross-major-version pg_dump/pg_restore incompatibility.
This is destructive to the named restore database and is not a customer operation.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from cybershield_ml.contracts import TrustedProductScope
from cybershield_ml.device_intelligence import DeviceFraudAssociation
from cybershield_ml.device_postgres_storage import PostgresDeviceAssociationStore

ADMIN_DSN = os.environ.get(
    "CEPHAS_DIRMC_ADMIN_DSN",
    "postgresql://postgres:postgres@localhost:5432/postgres",
)
RUNTIME_DSN = os.environ["CEPHAS_DIRMC_TEST_DSN"]
TENANT = os.environ["CEPHAS_DIRMC_TEST_TENANT"]
ADMIN = conninfo_to_dict(ADMIN_DSN)
RUNTIME_ROLE = conninfo_to_dict(RUNTIME_DSN)["user"]
RESTORE_DATABASE = "dirmc_restore_validation"
POSTGRES_CLIENT_IMAGE = os.environ.get("CEPHAS_POSTGRES_CLIENT_IMAGE", "postgres:16")


def require_disposable_local_database() -> None:
    if ADMIN.get("dbname") != "postgres":
        raise RuntimeError("refusing backup/restore test unless admin DSN targets postgres")
    if ADMIN.get("host") not in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("refusing backup/restore test against a non-local database")
    if conninfo_to_dict(RUNTIME_DSN).get("dbname") != "postgres":
        raise RuntimeError("runtime DSN must target the disposable postgres CI database")
    if not ADMIN.get("user") or not ADMIN.get("password"):
        raise RuntimeError("admin DSN must supply a database user and password")


def runtime_dsn(database: str) -> str:
    values = conninfo_to_dict(RUNTIME_DSN)
    values["dbname"] = database
    return make_conninfo(**values)


def run_pg_tool(tool: str, directory: str, *arguments: str) -> None:
    # The job runner has Docker available. --network host lets the matching
    # postgres:16 client connect to the disposable local PostgreSQL 16 service.
    command = [
        "docker", "run", "--rm", "--network", "host",
        "--volume", f"{directory}:/backup",
        "--env", f"PGPASSWORD={ADMIN['password']}",
        "--env", f"PGUSER={ADMIN['user']}",
        "--env", "PGHOST=127.0.0.1",
        "--env", f"PGPORT={ADMIN.get('port', '5432')}",
        POSTGRES_CLIENT_IMAGE, tool, *arguments,
    ]
    subprocess.run(command, check=True)


def grant_runtime_access(connection: psycopg.Connection) -> None:
    connection.execute(
        sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(RUNTIME_ROLE))
    )
    connection.execute(
        sql.SQL("GRANT SELECT, INSERT ON public.dirmc_device_fraud_associations TO {}").format(
            sql.Identifier(RUNTIME_ROLE)
        )
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


def main() -> None:
    require_disposable_local_database()
    scope = TrustedProductScope(
        tenant_id=TENANT,
        deployment_id="deployment-a",
        environment="test",
        allowed_products=frozenset({"cybershield"}),
        business_unit_id="bu-a",
    )
    device_key = "hmac-sha256:v1:" + "d" * 64
    case_id = f"backup-source-{uuid4().hex}"
    item = DeviceFraudAssociation(
        tenant_id=TENANT,
        deployment_id="deployment-a",
        environment="test",
        product_id="cybershield",
        business_unit_id="bu-a",
        device_key=device_key,
        case_id=case_id,
        association_status="confirmed",
        evidence_ref="backup-restore-ci",
        occurred_at=datetime.now(timezone.utc),
    )
    source_store = PostgresDeviceAssociationStore(lambda: psycopg.connect(RUNTIME_DSN))
    assert source_store.append(scope, item) is True

    # A fresh connection proves committed durability beyond connection-local state.
    restarted_store = PostgresDeviceAssociationStore(lambda: psycopg.connect(RUNTIME_DSN))
    assert len(restarted_store.list_for_device(
        scope, product_id="cybershield", device_key=device_key
    )) == 1

    with tempfile.TemporaryDirectory(prefix="dirmc-backup-") as directory:
        dump_path = Path(directory) / "dirmc.dump"
        run_pg_tool(
            "pg_dump", directory, "--format=custom", "--no-owner", "--no-privileges",
            "--dbname=postgres", "--file=/backup/dirmc.dump",
        )
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {}").format(
                    sql.Identifier(RESTORE_DATABASE)
                )
            )
            admin.execute(
                sql.SQL("CREATE DATABASE {}").format(sql.Identifier(RESTORE_DATABASE))
            )
        run_pg_tool(
            "pg_restore", directory, "--exit-on-error", "--no-owner",
            "--no-privileges", "--dbname=" + RESTORE_DATABASE, "/backup/dirmc.dump",
        )
        if not dump_path.is_file() or dump_path.stat().st_size == 0:
            raise RuntimeError("PostgreSQL 16 backup archive was not created")
        restored_admin_dsn = make_conninfo(
            **{**ADMIN, "dbname": RESTORE_DATABASE}
        )
        with psycopg.connect(restored_admin_dsn, autocommit=True) as restored_admin:
            grant_runtime_access(restored_admin)

    restored_dsn = runtime_dsn(RESTORE_DATABASE)
    restored_store = PostgresDeviceAssociationStore(lambda: psycopg.connect(restored_dsn))
    restored_records = restored_store.list_for_device(
        scope, product_id="cybershield", device_key=device_key
    )
    assert [record.case_id for record in restored_records] == [case_id]

    post_restore_item = item.model_copy(
        update={"case_id": f"post-restore-{uuid4().hex}"}
    )
    assert restored_store.append(scope, post_restore_item) is True
    verify_connection = psycopg.connect(restored_dsn)
    try:
        with verify_connection.transaction(), verify_connection.cursor() as cursor:
            PostgresDeviceAssociationStore._set_scope(cursor, scope)
            cursor.execute(
                """SELECT COUNT(*) FROM public.dirmc_device_association_audit
                   WHERE tenant_id=%s AND deployment_id=%s AND environment=%s
                   AND product_id=%s AND business_unit_id=%s AND device_key=%s
                   AND case_id=%s""",
                (
                    TENANT, "deployment-a", "test", "cybershield", "bu-a",
                    device_key, post_restore_item.case_id,
                ),
            )
            assert cursor.fetchone()[0] == 1
    finally:
        verify_connection.close()

    other_scope = scope.model_copy(update={"business_unit_id": "bu-unmapped"})
    assert restored_store.list_for_device(
        other_scope, product_id="cybershield", device_key=device_key
    ) == ()
    print("DIRMC PostgreSQL restart, backup/restore, trigger and restored-RLS checks passed")


if __name__ == "__main__":
    main()
