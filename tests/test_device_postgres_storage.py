import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

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
    item = association(tenant, "case-1")

    def make_store():
        return PostgresDeviceAssociationStore(lambda: psycopg.connect(dsn))

    # The database administrator must pre-provision CEPHAS_DIRMC_TEST_TENANT for
    # this dedicated login in dirmc_runtime_principal_scope. The DSN must authenticate
    # as that login, not a table owner.
    store = make_store()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: make_store().append(trusted_scope, item), range(8)))
    assert sum(results) == 1

    records = store.list_for_device(
        trusted_scope, product_id="cybershield", device_key=DEVICE
    )
    assert len(records) == 1
    assert records[0].case_id == "case-1"

    other_bu_scope = scope(tenant, business_unit="bu-b")
    assert store.list_for_device(
        other_bu_scope, product_id="cybershield", device_key=DEVICE
    ) == ()

    with pytest.raises(ValueError, match="outside the authenticated scope"):
        store.append(trusted_scope, association(tenant="different-tenant", case_id="case-2"))
