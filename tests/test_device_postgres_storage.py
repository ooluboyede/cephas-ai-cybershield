from datetime import datetime, timezone

import pytest

from cybershield_ml.contracts import TrustedProductScope
from cybershield_ml.device_intelligence import DeviceFraudAssociation
from cybershield_ml.device_postgres_storage import PostgresDeviceAssociationStore

NOW = datetime(2026, 11, 13, 8, 0, tzinfo=timezone.utc)
DEVICE = "hmac-sha256:v1:" + "c" * 64


def scope(**overrides):
    values = {
        "tenant_id": "tenant-a",
        "deployment_id": "deployment-a",
        "environment": "test",
        "allowed_products": frozenset({"cybershield"}),
        "business_unit_id": "bu-a",
    }
    values.update(overrides)
    return TrustedProductScope(**values)


def association(**overrides):
    values = {
        "tenant_id": "tenant-a",
        "deployment_id": "deployment-a",
        "environment": "test",
        "product_id": "cybershield",
        "business_unit_id": "bu-a",
        "device_key": DEVICE,
        "case_id": "case-1",
        "association_status": "confirmed",
        "evidence_ref": "evidence-1",
        "occurred_at": NOW,
    }
    values.update(overrides)
    return DeviceFraudAssociation(**values)


def test_postgres_adapter_rejects_cross_scope_write_before_connecting():
    def forbidden_connection():
        pytest.fail("connection must not be opened for invalid scope")

    store = PostgresDeviceAssociationStore(forbidden_connection)
    with pytest.raises(ValueError, match="outside the authenticated scope"):
        store.append(scope(), association(tenant_id="tenant-b"))


def test_postgres_adapter_rejects_raw_device_key_before_connecting():
    def forbidden_connection():
        pytest.fail("connection must not be opened for invalid device key")

    store = PostgresDeviceAssociationStore(forbidden_connection)
    with pytest.raises(ValueError, match="versioned HMAC"):
        store.list_for_device(
            scope(), product_id="cybershield", device_key="raw-device-id"
        )


def test_postgres_canonical_payload_and_digest_are_deterministic():
    canonical_a, digest_a = PostgresDeviceAssociationStore._canonical(association())
    canonical_b, digest_b = PostgresDeviceAssociationStore._canonical(association())
    assert canonical_a == canonical_b
    assert len(digest_a) == 64
    assert digest_a == digest_b


@pytest.mark.skipif(
    not __import__("os").environ.get("CEPHAS_DIRMC_TEST_DSN"),
    reason="requires customer-provisioned PostgreSQL test database and applied migration",
)
def test_postgres_live_integration_requires_customer_database():
    pytest.skip(
        "Live PostgreSQL isolation/concurrency suite is provisioned and run by the customer deployment pipeline"
    )
