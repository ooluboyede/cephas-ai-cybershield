"""PostgreSQL integration tests for DIRCM RLS and durable identity registry."""
import os

import psycopg
import pytest

from cybershield_ml.dircm_registry import POSTGRES_DIRCM_SCHEMA, PostgresDeviceIdentityRegistry


@pytest.fixture
def dircm_database():
    dsn = os.environ.get("CYBERSHIELD_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("CYBERSHIELD_TEST_DATABASE_URL is not configured")

    with psycopg.connect(dsn) as connection:
        connection.execute(POSTGRES_DIRCM_SCHEMA)
        connection.execute("""
            REVOKE ALL ON dircm_devices, dircm_verified_identifiers, dircm_match_candidates
            FROM dircm_test_app
        """)
        connection.execute("DROP ROLE IF EXISTS dircm_test_app")
        connection.execute("CREATE ROLE dircm_test_app NOLOGIN")
        connection.execute("""
            GRANT SELECT, INSERT, UPDATE, DELETE ON
            dircm_devices, dircm_verified_identifiers, dircm_match_candidates
            TO dircm_test_app
        """)
        connection.execute("TRUNCATE dircm_match_candidates, dircm_verified_identifiers, dircm_devices")
        connection.commit()

    def connect_as_app():
        connection = psycopg.connect(dsn)
        connection.execute("SET ROLE dircm_test_app")
        connection.commit()
        return connection

    yield dsn, connect_as_app

    with psycopg.connect(dsn) as connection:
        connection.execute("TRUNCATE dircm_match_candidates, dircm_verified_identifiers, dircm_devices")
        connection.execute("DROP ROLE IF EXISTS dircm_test_app")
        connection.commit()


def test_postgres_registry_persists_verified_identity(dircm_database):
    _dsn, connect = dircm_database
    registry = PostgresDeviceIdentityRegistry(connect)
    args = {
        "tenant_id": "tenant-persist",
        "source_id": "managed-edr",
        "identifier_type": "managed_agent_id",
        "identifier_digest": "a" * 64,
    }
    first = registry.get_or_create_verified_device(**args)
    second = PostgresDeviceIdentityRegistry(connect).get_or_create_verified_device(**args)
    assert first == second


def test_postgres_registry_enforces_tenant_row_level_security(dircm_database):
    _dsn, connect = dircm_database
    registry = PostgresDeviceIdentityRegistry(connect)
    registry.get_or_create_verified_device(
        tenant_id="tenant-a", source_id="edr", identifier_type="managed_agent_id",
        identifier_digest="b" * 64,
    )
    registry.get_or_create_verified_device(
        tenant_id="tenant-b", source_id="edr", identifier_type="managed_agent_id",
        identifier_digest="c" * 64,
    )

    with connect() as connection:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", ("tenant-a",))
        rows = connection.execute("SELECT tenant_id FROM dircm_devices").fetchall()
        assert rows == [("tenant-a",)]
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute(
                "INSERT INTO dircm_devices (tenant_id, device_id) VALUES ('tenant-b', gen_random_uuid())"
            )
        connection.rollback()


def test_probabilistic_candidate_is_idempotent_and_tenant_scoped(dircm_database):
    _dsn, connect = dircm_database
    registry = PostgresDeviceIdentityRegistry(connect)
    from datetime import datetime, timezone

    first = registry.create_match_candidate(
        tenant_id="tenant-a", source_id="sensor", identifier_type="probabilistic_signal",
        identifier_digest="d" * 64, observed_at=datetime(2026, 11, 13, tzinfo=timezone.utc),
    )
    second = registry.create_match_candidate(
        tenant_id="tenant-a", source_id="sensor", identifier_type="probabilistic_signal",
        identifier_digest="d" * 64, observed_at=datetime(2026, 11, 14, tzinfo=timezone.utc),
    )
    assert first == second
    with psycopg.connect(os.environ["CYBERSHIELD_TEST_DATABASE_URL"]) as connection:
        count = connection.execute(
            "SELECT count(*) FROM dircm_match_candidates WHERE tenant_id = %s",
            ("tenant-a",),
        ).fetchone()[0]
        assert count == 1
