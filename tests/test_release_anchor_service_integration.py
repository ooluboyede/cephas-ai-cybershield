"""PostgreSQL integration tests for the customer-operated anchor WSGI service."""

import hashlib
import io
import json
import os

import psycopg
import pytest

from services.release_anchor import app


@pytest.fixture
def anchor_database(monkeypatch):
    dsn = os.environ.get("CYBERSHIELD_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("CYBERSHIELD_TEST_DATABASE_URL is not configured")
    monkeypatch.setenv("CEPHAS_ANCHOR_DATABASE_URL", dsn)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cephas_release_floor (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                product TEXT NOT NULL,
                release_sequence BIGINT NOT NULL CHECK (release_sequence >= 1),
                version TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (tenant_id, deployment_id, product)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cephas_release_floor_audit (
                event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                client_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                product TEXT NOT NULL,
                release_sequence BIGINT NOT NULL CHECK (release_sequence >= 1),
                version TEXT NOT NULL
            )
            """
        )
        connection.execute("TRUNCATE cephas_release_floor, cephas_release_floor_audit RESTART IDENTITY")
    yield dsn
    with psycopg.connect(dsn) as connection:
        connection.execute("TRUNCATE cephas_release_floor, cephas_release_floor_audit RESTART IDENTITY")


def call_service(monkeypatch, method, token, payload=None):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    monkeypatch.setenv(
        "CEPHAS_ANCHOR_CLIENTS_JSON",
        json.dumps({
            token_hash: {
                "client_id": "postgres-integration-test",
                "scopes": [{
                    "tenant_id": "tenant-pg",
                    "deployment_id": "deployment-pg",
                    "products": ["CyberShield"],
                }],
            }
        }),
    )
    body = b"" if payload is None else json.dumps(payload).encode()
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": "/v1/floors/tenant-pg/deployment-pg/CyberShield",
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "wsgi.input": io.BytesIO(body),
    }
    captured = []

    def start_response(status, headers):
        captured.append(status)

    response = b"".join(app.application(environ, start_response))
    return captured[0], json.loads(response.decode())


def test_anchor_service_persists_monotonic_floor_and_audit_atomically(anchor_database, monkeypatch):
    status, payload = call_service(
        monkeypatch, "PUT", "integration-token",
        {"release_sequence": 45, "version": "0.3.45"},
    )
    assert status == "200 OK"
    assert payload["accepted"] is True

    status, payload = call_service(monkeypatch, "GET", "integration-token")
    assert status == "200 OK"
    assert payload == {"release_sequence": 45, "version": "0.3.45"}

    status, payload = call_service(
        monkeypatch, "PUT", "integration-token",
        {"release_sequence": 44, "version": "0.3.44"},
    )
    assert status == "409 Conflict"
    assert payload["error"] == "stale_or_conflicting_release"

    with psycopg.connect(anchor_database) as connection:
        floor = connection.execute(
            """SELECT release_sequence, version FROM cephas_release_floor
               WHERE tenant_id = %s AND deployment_id = %s AND product = %s""",
            ("tenant-pg", "deployment-pg", "CyberShield"),
        ).fetchone()
        audit_count = connection.execute(
            """SELECT COUNT(*) FROM cephas_release_floor_audit
               WHERE tenant_id = %s AND deployment_id = %s AND product = %s""",
            ("tenant-pg", "deployment-pg", "CyberShield"),
        ).fetchone()[0]

    assert floor == (45, "0.3.45")
    assert audit_count == 1
