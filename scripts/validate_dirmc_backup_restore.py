"""Exercise DIRMC PostgreSQL durability and logical backup/restore in disposable CI.

This is destructive to the named restore database and is not a customer operation.
It refuses non-local hosts and non-CI database names.
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
RUNTIME_ROLE = conninfo_to_dict(RUNTIME_DSN)["user"]
RESTORE_DATABASE = "dirmc_restore_validation"


def require_disposable_local_database() -> None:
    admin = conninfo_to_dict(ADMIN_DSN)
    if admin.get("dbname") != "postgres":
        raise RuntimeError("refusing backup/restore test unless admin DSN targets postgres")
    if admin.get("host") not in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("refusing backup/restore test against a non-local database")
    if conninfo_to_dict(RUNTIME_DSN).get("dbname") != "postgres":
        raise RuntimeError("runtime DSN must target the disposable postgres CI database")


def runtime_dsn(database: str) -> str:
    values = conninfo_to_dict(RUNTIME_DSN)
    values["dbname"] = database
    return make_conninfo(**values)


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

    # A new connection after the writer has closed proves committed durability
    # across process/connection restart rather than connection-local state.
    restarted_store = PostgresDeviceAssociationStore(lambda: psycopg.connect(RUNTIME_DSN))
    assert len(restarted_store.list_for_device(
        scope, product_id="cybershield", device_key=device_key
    )) == 1

    dump_path: Path
    with tempfile.TemporaryDirectory(prefix="dirmc-backup-") as directory:
        dump_path = Path(directory) / "dirmc.dump"
        subprocess.run(
            ["pg_dump", "--format=custom", "--no-owner", "--no-privileges",
             "--dbname", ADMIN_DSN, "--file", str(dump_path)],
            check=True,
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
        restored_admin_dsn = make_conninfo(
            **{**conninfo_to_dict(ADMIN_DSN), "dbname": RESTORE_DATABASE}
        )
        subprocess.run(
            ["pg_restore", "--exit-on-error", "--no-owner", "--no-privileges",
             "--dbname", restored_admin_dsn, str(dump_path)],
            check=True,
        )
        with psycopg.connect(restored_admin_dsn, autocommit=True) as restored_admin:
            grant_runtime_access(restored_admin)

    restored_dsn = runtime_dsn(RESTORE_DATABASE)
    restored_store = PostgresDeviceAssociationStore(lambda: psycopg.connect(restored_dsn))
    restored_records = restored_store.list_for_device(
        scope, product_id="cybershield", device_key=device_key
    )
    assert [record.case_id for record in restored_records] == [case_id]

    # The restored trigger must still atomically generate an audit row for a
    # post-restore insert, and a fresh connection must read it.
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

    # Restored RLS remains fail-closed for a scope not provisioned to this login.
    other_scope = scope.model_copy(update={"business_unit_id": "bu-unmapped"})
    assert restored_store.list_for_device(
        other_scope, product_id="cybershield", device_key=device_key
    ) == ()

    print("DIRMC PostgreSQL restart, backup/restore, trigger and restored-RLS checks passed")


if __name__ == "__main__":
    main()
