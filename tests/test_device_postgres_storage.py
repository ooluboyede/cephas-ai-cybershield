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


def scope(tenant, business_unit="bu-a"):
    return TrustedProductScope(
        tenant_id=tenant,
        deployment_id="deployment-a",
        environment="test",
        allowed_products=frozenset({"cybershield"}),
        business_unit_id=business_unit,
    )


def association(tenant, case_id):
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


def test_postgres_live_rls_idempotency_and_concurrency():
    dsn = os.environ.get("CEPHAS_DIRMC_TEST_DSN")
    if not dsn:
        pytest.skip("requires customer-provisioned PostgreSQL test database")
    psycopg = pytest.importorskip("psycopg")

    tenant = f"dirmc-test-{uuid4().hex}"
    trusted_scope = scope(tenant)
    item = association(tenant, "case-1")

    def make_store():
        return PostgresDeviceAssociationStore(lambda: psycopg.connect(dsn))

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
        store.append(trusted_scope, association("different-tenant", "case-2"))
