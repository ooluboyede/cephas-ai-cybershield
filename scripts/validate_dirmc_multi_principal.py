"""Prove DIRMC RLS isolation using separate authenticated PostgreSQL logins."""
from __future__ import annotations

import os
from datetime import datetime, timezone
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
PASSWORD = os.environ.get("CEPHAS_DIRMC_MATRIX_PASSWORD", "ci-only-matrix-password")
BASE = conninfo_to_dict(ADMIN_DSN)
DEVICE = "hmac-sha256:v1:" + "e" * 64
NOW = datetime.now(timezone.utc)

PRINCIPALS = (
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_a_cyber", "tenant-a", "deployment-a", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_b_bu_a_cyber", "tenant-a", "deployment-b", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_b_cyber", "tenant-a", "deployment-a", "cybershield", "bu-b"),
    ("dirmc_ci_matrix_tenant_b_deploy_a_bu_a_cyber", "tenant-b", "deployment-a", "cybershield", "bu-a"),
    ("dirmc_ci_matrix_tenant_a_deploy_a_bu_a_payroll", "tenant-a", "deployment-a", "payroll", "bu-a"),
)
MATRIX_ROLES = {entry[0] for entry in PRINCIPALS}


def make_scope(tenant: str, deployment: str, product: str, business_unit: str):
    return TrustedProductScope(
        tenant_id=tenant,
        deployment_id=deployment,
        environment="test",
        allowed_products=frozenset({product}),
        business_unit_id=business_unit,
    )


def make_item(scope: TrustedProductScope, case_id: str) -> DeviceFraudAssociation:
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
        evidence_ref="dirmc-multi-principal-ci",
        occurred_at=NOW,
    )


def runtime_dsn(role: str) -> str:
    return make_conninfo(**{
        **BASE,
        "dbname": "postgres",
        "user": role,
        "password": PASSWORD,
    })


def make_store(role: str) -> PostgresDeviceAssociationStore:
    return PostgresDeviceAssociationStore(
        lambda: psycopg.connect(runtime_dsn(role))
    )


def assert_cannot_set_role(login_role: str, target_role: str) -> None:
    with psycopg.connect(runtime_dsn(login_role)) as connection:
        try:
            connection.execute(
                sql.SQL("SET ROLE {}").format(sql.Identifier(target_role))
            )
        except psycopg.errors.InsufficientPrivilege:
            return
        raise AssertionError(
            f"{login_role} was able to SET ROLE to {target_role}"
        )


def main() -> None:
    entries = []
    for role, tenant, deployment, product, business_unit in PRINCIPALS:
        scope = make_scope(tenant, deployment, product, business_unit)
        store = make_store(role)
        case_id = f"matrix-{uuid4().hex}"
        assert store.append(scope, make_item(scope, case_id)) is True
        own = store.list_for_device(scope, product_id=product, device_key=DEVICE)
        assert any(record.case_id == case_id for record in own)
        entries.append((role, scope, store))

    # Every principal tries each other principal's exact scope. Reads must be
    # empty and writes must fail at PostgreSQL RLS, not merely app validation.
    for role, _, store in entries:
        for target_role, target_scope, _ in entries:
            if target_role == role:
                continue
            target_product = next(iter(target_scope.allowed_products))
            visible = store.list_for_device(
                target_scope, product_id=target_product, device_key=DEVICE
            )
            assert visible == (), f"{role} read rows belonging to {target_role}"
            forged_item = make_item(target_scope, f"forged-{uuid4().hex}")
            try:
                store.append(target_scope, forged_item)
            except psycopg.errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError(
                    f"{role} wrote using forged scope belonging to {target_role}"
                )

    # Inspect only memberships in the five isolated matrix roles. PostgreSQL
    # has predefined/special roles outside this matrix; they are not alternate
    # customer principals. Also attempt SET ROLE directly for every peer.
    with psycopg.connect(ADMIN_DSN) as admin:
        for role, _, _ in entries:
            memberships = admin.execute(
                """SELECT granted_role.rolname
                   FROM pg_auth_members AS membership
                   JOIN pg_roles AS granted_role
                     ON granted_role.oid = membership.roleid
                   JOIN pg_roles AS member_role
                     ON member_role.oid = membership.member
                   WHERE member_role.rolname = %s
                     AND granted_role.rolname LIKE 'dirmc_ci_matrix_%%'""",
                (role,),
            ).fetchall()
            assert memberships == (), (
                f"{role} has matrix-role memberships: {memberships}"
            )
            for target_role in MATRIX_ROLES - {role}:
                assert_cannot_set_role(role, target_role)

    print(
        "DIRMC multi-principal isolation passed: "
        f"{len(entries)} principals, {len(entries) * (len(entries) - 1)} "
        "cross-principal read/write denial pairs and denied SET ROLE attempts"
    )


if __name__ == "__main__":
    main()
