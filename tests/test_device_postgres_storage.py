import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from cybershield_ml.contracts import TrustedProductScope
from cybershield_ml.device_intelligence import DeviceFraudAssociation
from cybershield_ml.device_postgres_storage import PostgresDeviceAssociationStore

NOW = datetime(2026, 11, 13, 8, 0, tzinfo=timezone.utc)
DEVICE = "hmac-sha256:v1:" + "c" * 64


def scope(tenant="tenant-a", business_unit="bu-a"):
    return TrustedProductScope(
        tenant_id=tenant,
        deployment_id="deployment-a",
        environment="test",
        allowed_products=frozenset({"cybershield"}),
        business_unit_id=business_unit,
    )


def association(tenant="tenant-a", case_id="case-1"):
    return DeviceFraudAssociation(
        tenant_id=tenant,
        deployment_id="deployment-a",
        environment="test",
        product_id="cybershield",
        business_unit_id="bu-a",
        device_key=DEVICE,
        case_id=case_id,
        association_status="confirmed",
        evidence_ref="evidence-1",
        occurred_at=NOW,
    )


def test_postgres_adapter_rejects_cross_scope_before_connecting():
    def forbidden_connection():
        pytest.fail("connection must not be opened for invalid scope")

    store = PostgresDeviceAssociationStore(forbidden_connection)
    with pytest.raises(ValueError, match="outside the authenticated scope"):
        store.append(scope(), association(tenant="tenant-b"))


def test_postgres_adapter_rejects_raw_device_key_before_connecting():
    def forbidden_connection():
        pytest.fail("connection must not be opened for invalid device key")

    store = PostgresDeviceAssociationStore(forbidden_connection)
    with pytest.raises(ValueError, match="versioned HMAC"):
        store.list_for_device(scope(), product_id="cybershield", device_key="raw-device-id")


def test_postgres_canonical_payload_and_digest_are_deterministic():
    canonical_a, digest_a = PostgresDeviceAssociationStore._canonical(association())
    canonical_b, digest_b = PostgresDeviceAssociationStore._canonical(association())
    assert canonical_a == canonical_b
    assert len(digest_a) == 64
    assert digest_a == digest_b


def test_postgres_adapter_rejects_unapproved_product_before_connecting():
    def forbidden_connection():
        pytest.fail("connection must not be opened for unapproved product")

    store = PostgresDeviceAssociationStore(forbidden_connection)
    with pytest.raises(ValueError, match="not authorised"):
        store.list_for_device(scope(), product_id="payroll", device_key=DEVICE)


def test_postgres_live_rls_idempotency_and_concurrency():
    dsn = os.environ.get("CEPHAS_DIRMC_TEST_DSN")
    if not dsn:
        pytest.skip("requires customer-provisioned PostgreSQL test database")
    psycopg = pytest.importorskip("psycopg")

    tenant = os.environ.get("CEPHAS_DIRMC_TEST_TENANT")
    if not tenant:
        pytest.skip("requires a pre-provisioned tenant scope for the dedicated test login")
    trusted_scope = scope(tenant)
    case_id = f"case-{uuid4().hex}"
    item = association(tenant, case_id)

    def make_store():
        return PostgresDeviceAssociationStore(lambda: psycopg.connect(dsn))

    # The database administrator must pre-provision CEPHAS_DIRMC_TEST_TENANT for
    # this dedicated login in dirmc_runtime_principal_scope. The DSN must authenticate
    # as that login, not a table owner.
    store = make_store()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: make_store().append(trusted_scope, item), range(8)))
    assert sum(results) == 1
    assert store.append(trusted_scope, item) is False

    records = store.list_for_device(
        trusted_scope, product_id="cybershield", device_key=DEVICE
    )
    assert len(records) == 1
    assert records[0].case_id == case_id

    # The database trigger, not the application adapter, must create exactly
    # one audit record for the winning association insert.
    audit_connection = psycopg.connect(dsn)
    try:
        with audit_connection.transaction(), audit_connection.cursor() as cursor:
            PostgresDeviceAssociationStore._set_scope(cursor, trusted_scope)
            cursor.execute(
                """SELECT COUNT(*) FROM dirmc_device_association_audit
                   WHERE tenant_id=%s AND deployment_id=%s AND environment=%s
                   AND product_id=%s AND business_unit_id=%s
                   AND device_key=%s AND case_id=%s""",
                (
                    tenant, "deployment-a", "test", "cybershield", "bu-a",
                    DEVICE, case_id,
                ),
            )
            assert cursor.fetchone()[0] == 1
    finally:
        audit_connection.close()

    # Runtime login must not be able to fabricate audit-only records.
    denied_connection = psycopg.connect(dsn)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with denied_connection.transaction(), denied_connection.cursor() as cursor:
            PostgresDeviceAssociationStore._set_scope(cursor, trusted_scope)
            cursor.execute(
                """INSERT INTO dirmc_device_association_audit (
                    tenant_id, deployment_id, environment, product_id,
                    business_unit_id, device_key, case_id, action, record_sha256
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,'association_inserted',%s)""",
                (
                    tenant, "deployment-a", "test", "cybershield", "bu-a",
                    DEVICE, f"audit-forgery-{case_id}", "0" * 64,
                ),
            )
    denied_connection.close()

    other_bu_scope = scope(tenant, business_unit="bu-b")
    assert store.list_for_device(
        other_bu_scope, product_id="cybershield", device_key=DEVICE
    ) == ()

    with pytest.raises(ValueError, match="outside the authenticated scope"):
        store.append(trusted_scope, association(tenant="different-tenant", case_id="case-2"))
