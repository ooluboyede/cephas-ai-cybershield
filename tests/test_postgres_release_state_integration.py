"""Real PostgreSQL integration tests for durable anti-rollback state.

Set CYBERSHIELD_TEST_DATABASE_URL to a disposable PostgreSQL database. CI supplies
an isolated PostgreSQL service container. These tests never use customer data.
"""
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import psycopg
import pytest

from cybershield_ml.release_state import (
    POSTGRES_RELEASE_STATE_SCHEMA,
    PostgresReleaseStateStore,
)


@pytest.fixture
def postgres_store():
    dsn = os.environ.get("CYBERSHIELD_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("CYBERSHIELD_TEST_DATABASE_URL is not configured")

    def connect():
        return psycopg.connect(dsn)

    with connect() as connection:
        connection.execute(POSTGRES_RELEASE_STATE_SCHEMA)
        connection.execute("TRUNCATE TABLE cephas_model_release_state")
        connection.commit()

    yield PostgresReleaseStateStore(connect)

    with connect() as connection:
        connection.execute("TRUNCATE TABLE cephas_model_release_state")
        connection.commit()


def read_state(dsn, tenant_id, product):
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            """
            SELECT release_sequence, version
            FROM cephas_model_release_state
            WHERE tenant_id = %s AND product = %s
            """,
            (tenant_id, product),
        ).fetchone()


def test_release_state_persists_across_new_store_and_connection(postgres_store):
    dsn = os.environ["CYBERSHIELD_TEST_DATABASE_URL"]
    postgres_store.accept_release(
        tenant_id="tenant-persist", product="CyberShield", release_sequence=8, version="0.3.8"
    )

    # A fresh adapter instance and connection prove state is database-backed, not process-local.
    restarted_store = PostgresReleaseStateStore(lambda: psycopg.connect(dsn))
    with pytest.raises(ValueError, match="stale or conflicts"):
        restarted_store.accept_release(
            tenant_id="tenant-persist", product="CyberShield", release_sequence=7, version="0.3.7"
        )
    assert read_state(dsn, "tenant-persist", "CyberShield") == (8, "0.3.8")


def test_release_floor_survives_a_separate_python_process(postgres_store):
    dsn = os.environ["CYBERSHIELD_TEST_DATABASE_URL"]
    postgres_store.accept_release(
        tenant_id="tenant-process-restart",
        product="CyberShield",
        release_sequence=31,
        version="0.3.31",
    )

    # The child process has no access to the parent's adapter or in-memory state.
    child_code = """
import os
import psycopg
from cybershield_ml.release_state import PostgresReleaseStateStore

dsn = os.environ["CYBERSHIELD_TEST_DATABASE_URL"]
store = PostgresReleaseStateStore(lambda: psycopg.connect(dsn))
try:
    store.accept_release(
        tenant_id="tenant-process-restart",
        product="CyberShield",
        release_sequence=30,
        version="0.3.30",
    )
except ValueError as exc:
    if "stale or conflicts" not in str(exc):
        raise
else:
    raise SystemExit("stale release unexpectedly accepted")
"""
    subprocess.run(
        [sys.executable, "-c", child_code],
        check=True,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert read_state(dsn, "tenant-process-restart", "CyberShield") == (31, "0.3.31")


def test_same_release_is_idempotent_but_conflicting_version_is_rejected(postgres_store):
    args = {"tenant_id": "tenant-idempotent", "product": "CyberShield", "release_sequence": 9}
    postgres_store.accept_release(**args, version="0.3.9")
    postgres_store.accept_release(**args, version="0.3.9")

    with pytest.raises(ValueError, match="stale or conflicts"):
        postgres_store.accept_release(**args, version="0.3.9-repacked")

    assert read_state(
        os.environ["CYBERSHIELD_TEST_DATABASE_URL"], "tenant-idempotent", "CyberShield"
    ) == (9, "0.3.9")


def test_release_state_isolated_by_tenant_and_product(postgres_store):
    postgres_store.accept_release(
        tenant_id="tenant-a", product="CyberShield", release_sequence=5, version="5"
    )
    postgres_store.accept_release(
        tenant_id="tenant-b", product="CyberShield", release_sequence=2, version="2"
    )
    postgres_store.accept_release(
        tenant_id="tenant-a", product="WeatherShield", release_sequence=1, version="1"
    )

    dsn = os.environ["CYBERSHIELD_TEST_DATABASE_URL"]
    assert read_state(dsn, "tenant-a", "CyberShield") == (5, "5")
    assert read_state(dsn, "tenant-b", "CyberShield") == (2, "2")
    assert read_state(dsn, "tenant-a", "WeatherShield") == (1, "1")


def test_concurrent_competing_releases_never_lower_accepted_sequence(postgres_store):
    barrier = Barrier(2)

    def install(sequence, version):
        barrier.wait(timeout=10)
        try:
            postgres_store.accept_release(
                tenant_id="tenant-race",
                product="CyberShield",
                release_sequence=sequence,
                version=version,
            )
            return "accepted"
        except ValueError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda item: install(*item), [(20, "0.3.20"), (21, "0.3.21")]))

    assert outcomes.count("accepted") >= 1
    dsn = os.environ["CYBERSHIELD_TEST_DATABASE_URL"]
    assert read_state(dsn, "tenant-race", "CyberShield") == (21, "0.3.21")

    with pytest.raises(ValueError, match="stale or conflicts"):
        postgres_store.accept_release(
            tenant_id="tenant-race", product="CyberShield", release_sequence=20, version="0.3.20"
        )
