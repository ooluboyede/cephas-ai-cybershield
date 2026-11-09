import pytest

from cybershield_ml.release_state import (
    POSTGRES_RELEASE_STATE_SCHEMA,
    PostgresReleaseStateStore,
)


class FakeCursor:
    def __init__(self, result):
        self.result = result
        self.sql = None
        self.params = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params):
        self.sql = sql
        self.params = params

    def fetchone(self):
        return self.result


class FakeConnection:
    def __init__(self, result):
        self.fake_cursor = FakeCursor(result)
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self.fake_cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


SCOPE = {
    "tenant_id": "tenant-a",
    "deployment_id": "deployment-a",
    "product": "CyberShield",
}


def test_postgres_release_store_uses_atomic_tenant_deployment_product_upsert():
    connection = FakeConnection((7, "0.3.3"))
    store = PostgresReleaseStateStore(lambda: connection)

    store.accept_release(
        **SCOPE, release_sequence=7, version="0.3.3"
    )

    sql = connection.fake_cursor.sql
    assert "ON CONFLICT (tenant_id, deployment_id, product) DO UPDATE" in sql
    assert "release_sequence < EXCLUDED.release_sequence" in sql
    assert "release_sequence = EXCLUDED.release_sequence" in sql
    assert "version = EXCLUDED.version" in sql
    assert "RETURNING release_sequence, version" in sql
    assert connection.fake_cursor.params == (
        "tenant-a", "deployment-a", "CyberShield", 7, "0.3.3"
    )
    assert connection.committed
    assert not connection.rolled_back
    assert connection.closed


def test_postgres_release_store_rolls_back_stale_or_conflicting_release():
    connection = FakeConnection(None)
    store = PostgresReleaseStateStore(lambda: connection)

    with pytest.raises(ValueError, match="stale or conflicts"):
        store.accept_release(**SCOPE, release_sequence=6, version="0.3.2")

    assert connection.rolled_back
    assert not connection.committed
    assert connection.closed


def test_postgres_release_store_reads_deployment_scoped_floor():
    connection = FakeConnection((12, "0.3.12"))
    store = PostgresReleaseStateStore(lambda: connection)

    assert store.get_release(**SCOPE) == (12, "0.3.12")
    assert "tenant_id = %s AND deployment_id = %s AND product = %s" in connection.fake_cursor.sql
    assert connection.fake_cursor.params == ("tenant-a", "deployment-a", "CyberShield")
    assert connection.closed


def test_postgres_release_store_validates_input_before_opening_connection():
    called = False

    def factory():
        nonlocal called
        called = True
        return FakeConnection((1, "0.3.1"))

    store = PostgresReleaseStateStore(factory)
    with pytest.raises(ValueError, match="positive integer"):
        store.accept_release(**SCOPE, release_sequence=True, version="0.3.3")
    assert not called


def test_postgres_release_state_schema_is_tenant_deployment_product_scoped():
    assert "PRIMARY KEY (tenant_id, deployment_id, product)" in POSTGRES_RELEASE_STATE_SCHEMA
    assert "release_sequence BIGINT NOT NULL CHECK (release_sequence >= 1)" in POSTGRES_RELEASE_STATE_SCHEMA
