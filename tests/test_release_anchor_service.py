import hashlib
import io
import json

from services.release_anchor import app


class FakeCursor:
    def __init__(self, result):
        self.result = result
        self.statements = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params):
        self.statements.append((sql, params))

    def fetchone(self):
        return self.result


class FakeConnection:
    def __init__(self, result):
        self.cursor_instance = FakeCursor(result)
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def invoke(monkeypatch, method, token, payload=None, db_connection=None, scope=None):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    monkeypatch.setenv(
        "CEPHAS_ANCHOR_CLIENTS_JSON",
        json.dumps({
            token_hash: {
                "client_id": "unit-test-client",
                "scopes": [scope or {
                    "tenant_id": "tenant-a",
                    "deployment_id": "deployment-a",
                    "products": ["CEPHAS AI CyberShield"],
                }],
            }
        }),
    )
    calls = []
    if db_connection is not None:
        monkeypatch.setattr(app, "connect_database", lambda: db_connection)
    elif hasattr(app, "connect_database"):
        monkeypatch.setattr(app, "connect_database", lambda: (_ for _ in ()).throw(AssertionError("database must not be accessed")))
    body = b"" if payload is None else json.dumps(payload).encode()
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": "/v1/floors/tenant-a/deployment-a/CEPHAS%20AI%20CyberShield",
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "wsgi.input": io.BytesIO(body),
    }

    def start_response(status, headers):
        calls.append((status, dict(headers)))

    result = b"".join(app.application(environ, start_response))
    return calls[0][0], json.loads(result.decode()), db_connection


def test_anchor_service_denies_invalid_token_before_database_access(monkeypatch):
    status, payload, _ = invoke(monkeypatch, "GET", "wrong-token")
    assert status == "403 Forbidden"
    assert payload["error"] == "not_authorized"


def test_anchor_service_enforces_deployment_scope(monkeypatch):
    status, payload, _ = invoke(
        monkeypatch,
        "GET",
        "valid-token",
        scope={"tenant_id": "tenant-a", "deployment_id": "another-deployment"},
    )
    assert status == "403 Forbidden"
    assert payload["error"] == "not_authorized"


def test_anchor_service_gets_current_floor(monkeypatch):
    connection = FakeConnection((17, "0.3.17"))
    status, payload, _ = invoke(monkeypatch, "GET", "valid-token", db_connection=connection)
    assert status == "200 OK"
    assert payload == {"release_sequence": 17, "version": "0.3.17"}
    assert connection.cursor_instance.statements[0][1] == (
        "tenant-a", "deployment-a", "CEPHAS AI CyberShield"
    )


def test_anchor_service_updates_floor_and_writes_audit_in_same_transaction(monkeypatch):
    connection = FakeConnection((18, "0.3.18"))
    status, payload, _ = invoke(
        monkeypatch, "PUT", "valid-token",
        {"release_sequence": 18, "version": "0.3.18"}, connection,
    )
    assert status == "200 OK"
    assert payload["accepted"] is True
    assert len(connection.cursor_instance.statements) == 2
    assert "INSERT INTO cephas_release_floor_audit" in connection.cursor_instance.statements[1][0]
    assert connection.committed
    assert not connection.rolled_back


def test_anchor_service_rejects_conflicting_or_stale_floor(monkeypatch):
    connection = FakeConnection(None)
    status, payload, _ = invoke(
        monkeypatch, "PUT", "valid-token",
        {"release_sequence": 16, "version": "0.3.16"}, connection,
    )
    assert status == "409 Conflict"
    assert payload["error"] == "stale_or_conflicting_release"
    assert connection.rolled_back
    assert not connection.committed


def test_anchor_service_rejects_invalid_sequence_before_database_access(monkeypatch):
    status, payload, _ = invoke(
        monkeypatch, "PUT", "valid-token",
        {"release_sequence": True, "version": "0.3.18"},
    )
    assert status == "400 Bad Request"
    assert payload["error"] == "invalid_release_floor"
