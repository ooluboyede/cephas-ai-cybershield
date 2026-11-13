import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from cybershield_ml.contracts import TrustedProductScope
from cybershield_ml.device_intelligence import DeviceFraudAssociation
from cybershield_ml.device_storage import (
    DeviceAssociationConflict,
    SQLiteDeviceAssociationStore,
)

NOW = datetime(2026, 11, 13, 8, 0, tzinfo=timezone.utc)
DEVICE = "hmac-sha256:v1:" + "b" * 64


def make_scope(
    tenant="tenant-a",
    deployment="deployment-a",
    business_unit="bu-a",
):
    return TrustedProductScope(
        tenant_id=tenant,
        deployment_id=deployment,
        environment="test",
        allowed_products=frozenset({"cybershield"}),
        business_unit_id=business_unit,
    )


def make_association(
    *,
    tenant="tenant-a",
    deployment="deployment-a",
    business_unit="bu-a",
    case_id="case-1",
    status="confirmed",
    evidence="evidence-1",
    occurred_at=None,
):
    return DeviceFraudAssociation(
        tenant_id=tenant,
        deployment_id=deployment,
        environment="test",
        product_id="cybershield",
        business_unit_id=business_unit,
        device_key=DEVICE,
        case_id=case_id,
        association_status=status,
        evidence_ref=evidence,
        occurred_at=occurred_at or NOW - timedelta(days=1),
    )


def test_store_persists_association_across_instances(tmp_path):
    path = tmp_path / "customer" / "dirmc.sqlite3"
    first = SQLiteDeviceAssociationStore(path)
    assert first.append(make_scope(), make_association()) is True

    reopened = SQLiteDeviceAssociationStore(path)
    records = reopened.list_for_device(
        make_scope(), product_id="cybershield", device_key=DEVICE
    )
    assert len(records) == 1
    assert records[0].case_id == "case-1"
    assert reopened.audit_count(make_scope()) == 1


def test_exact_replay_is_idempotent_and_does_not_duplicate_audit(tmp_path):
    store = SQLiteDeviceAssociationStore(tmp_path / "dirmc.sqlite3")
    record = make_association()
    assert store.append(make_scope(), record) is True
    assert store.append(make_scope(), record) is False
    assert store.audit_count(make_scope()) == 1


def test_conflicting_replay_is_rejected_without_mutating_original(tmp_path):
    store = SQLiteDeviceAssociationStore(tmp_path / "dirmc.sqlite3")
    store.append(make_scope(), make_association())
    with pytest.raises(DeviceAssociationConflict):
        store.append(
            make_scope(),
            make_association(status="suspected", evidence="changed-evidence"),
        )
    records = store.list_for_device(
        make_scope(), product_id="cybershield", device_key=DEVICE
    )
    assert records[0].association_status == "confirmed"
    assert store.audit_count(make_scope()) == 1


def test_cross_tenant_and_cross_deployment_writes_fail_closed(tmp_path):
    store = SQLiteDeviceAssociationStore(tmp_path / "dirmc.sqlite3")
    with pytest.raises(ValueError, match="outside the authenticated scope"):
        store.append(make_scope(), make_association(tenant="tenant-b"))
    with pytest.raises(ValueError, match="outside the authenticated scope"):
        store.append(make_scope(), make_association(deployment="deployment-b"))


def test_reads_are_isolated_by_tenant_and_deployment(tmp_path):
    store = SQLiteDeviceAssociationStore(tmp_path / "dirmc.sqlite3")
    scope_a = make_scope()
    scope_b = make_scope(tenant="tenant-b")
    scope_other_deployment = make_scope(deployment="deployment-b")
    store.append(scope_a, make_association())
    store.append(
        scope_b,
        make_association(tenant="tenant-b", case_id="case-b"),
    )
    store.append(
        scope_other_deployment,
        make_association(deployment="deployment-b", case_id="case-c"),
    )
    assert len(store.list_for_device(
        scope_a, product_id="cybershield", device_key=DEVICE
    )) == 1
    assert len(store.list_for_device(
        scope_b, product_id="cybershield", device_key=DEVICE
    )) == 1
    assert len(store.list_for_device(
        scope_other_deployment, product_id="cybershield", device_key=DEVICE
    )) == 1


def test_business_unit_isolation(tmp_path):
    store = SQLiteDeviceAssociationStore(tmp_path / "dirmc.sqlite3")
    scope_a = make_scope(business_unit="bu-a")
    scope_b = make_scope(business_unit="bu-b")
    store.append(scope_a, make_association())
    store.append(
        scope_b,
        make_association(business_unit="bu-b", case_id="case-b"),
    )
    assert len(store.list_for_device(
        scope_a, product_id="cybershield", device_key=DEVICE
    )) == 1
    assert len(store.list_for_device(
        scope_b, product_id="cybershield", device_key=DEVICE
    )) == 1


def test_audit_table_rejects_update_and_delete(tmp_path):
    path = tmp_path / "dirmc.sqlite3"
    store = SQLiteDeviceAssociationStore(path)
    store.append(make_scope(), make_association())
    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE device_association_audit SET action='tampered'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM device_association_audit")
    finally:
        connection.close()


def test_unknown_product_and_raw_device_key_reads_are_rejected(tmp_path):
    store = SQLiteDeviceAssociationStore(tmp_path / "dirmc.sqlite3")
    with pytest.raises(ValueError, match="not authorised"):
        store.list_for_device(
            make_scope(), product_id="other-product", device_key=DEVICE
        )
    with pytest.raises(ValueError, match="versioned HMAC"):
        store.list_for_device(
            make_scope(), product_id="cybershield", device_key="raw-device-id"
        )
