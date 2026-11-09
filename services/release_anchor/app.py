"""Minimal customer-operated HTTPS release-floor authority (WSGI reference service).

Run behind the TLS server in this module. Do not expose the WSGI application
through an unauthenticated reverse proxy or public plaintext listener.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import psycopg

from socketserver import ThreadingMixIn
from urllib.parse import unquote
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

logger = logging.getLogger("cephas.release_anchor")
MAX_BODY_BYTES = 4096
_SCOPE_COMPONENT_RE = re.compile(r"^[^/\\\\]{1,200}$")


def _json_response(start_response, status, payload):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    start_response(
        status,
        [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
         ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")],
    )
    return [body]


def _load_clients():
    try:
        configured = json.loads(os.environ["CEPHAS_ANCHOR_CLIENTS_JSON"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError("CEPHAS_ANCHOR_CLIENTS_JSON is missing or invalid") from exc
    if not isinstance(configured, dict) or not configured:
        raise RuntimeError("anchor client configuration must be a non-empty object")
    for token_hash, client in configured.items():
        if not re.fullmatch(r"[0-9a-f]{64}", token_hash) or not isinstance(client, dict):
            raise RuntimeError("anchor client entries must use SHA-256 token hashes")
        if not isinstance(client.get("client_id"), str) or not client["client_id"].strip():
            raise RuntimeError("each anchor client requires a client_id")
        if not isinstance(client.get("scopes"), list):
            raise TypeError("each anchor client requires a scopes list")
        for scope in client["scopes"]:
            if (
                not isinstance(scope, dict)
                or not isinstance(scope.get("tenant_id"), str)
                or not isinstance(scope.get("deployment_id"), str)
                or not scope["tenant_id"].strip()
                or not scope["deployment_id"].strip()
                or ("products" in scope and (
                    not isinstance(scope["products"], list)
                    or not all(isinstance(item, str) and item.strip() for item in scope["products"])
                ))
            ):
                raise RuntimeError("anchor client scope configuration is invalid")
    return configured


def _authenticate(environ, tenant_id, deployment_id, product):
    header = environ.get("HTTP_AUTHORIZATION", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    try:
        clients = _load_clients()
    except (RuntimeError, TypeError):
        return None
    matched = None
    for expected_hash, client in clients.items():
        if hmac.compare_digest(digest, expected_hash):
            matched = client
    if matched is None:
        return None
    for scope in matched["scopes"]:
        if (
            scope.get("tenant_id") == tenant_id
            and scope.get("deployment_id") == deployment_id
            and (not scope.get("products") or product in scope["products"])
        ):
            return matched["client_id"]
    return None


def connect_database():
    dsn = os.environ.get("CEPHAS_ANCHOR_DATABASE_URL")
    if not dsn:
        raise RuntimeError("CEPHAS_ANCHOR_DATABASE_URL is required")
    return psycopg.connect(dsn)


def application(environ, start_response):
    if environ.get("REQUEST_METHOD") not in {"GET", "PUT"}:
        return _json_response(start_response, "405 Method Not Allowed", {"error": "method_not_allowed"})
    parts = [unquote(part) for part in environ.get("PATH_INFO", "").split("/") if part]
    if len(parts) != 5 or parts[0] != "v1" or parts[1] != "floors":
        return _json_response(start_response, "404 Not Found", {"error": "not_found"})
    tenant_id, deployment_id, product = parts[2:]
    if not all(_SCOPE_COMPONENT_RE.fullmatch(part) for part in (tenant_id, deployment_id, product)):
        return _json_response(start_response, "400 Bad Request", {"error": "invalid_scope"})
    client_id = _authenticate(environ, tenant_id, deployment_id, product)
    if client_id is None:
        return _json_response(start_response, "403 Forbidden", {"error": "not_authorized"})

    method = environ["REQUEST_METHOD"]
    payload = None
    if method == "PUT":
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            return _json_response(start_response, "400 Bad Request", {"error": "invalid_content_length"})
        if length < 1 or length > MAX_BODY_BYTES:
            return _json_response(start_response, "413 Payload Too Large", {"error": "invalid_body_size"})
        try:
            payload = json.loads(environ["wsgi.input"].read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _json_response(start_response, "400 Bad Request", {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return _json_response(start_response, "400 Bad Request", {"error": "invalid_payload"})
        sequence, version = payload.get("release_sequence"), payload.get("version")
        if (
            isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1
            or not isinstance(version, str) or not version.strip()
        ):
            return _json_response(start_response, "400 Bad Request", {"error": "invalid_release_floor"})

    try:
        with connect_database() as connection:
            with connection.cursor() as cursor:
                if method == "GET":
                    cursor.execute(
                        """SELECT release_sequence, version FROM cephas_release_floor
                           WHERE tenant_id = %s AND deployment_id = %s AND product = %s""",
                        (tenant_id, deployment_id, product),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        return _json_response(start_response, "404 Not Found", {"error": "floor_not_found"})
                    return _json_response(
                        start_response, "200 OK",
                        {"release_sequence": int(row[0]), "version": str(row[1])},
                    )

                cursor.execute(
                    """INSERT INTO cephas_release_floor
                       (tenant_id, deployment_id, product, release_sequence, version)
                       VALUES (%s, %s, %s, %s, %s)
                       ON CONFLICT (tenant_id, deployment_id, product) DO UPDATE
                       SET release_sequence = EXCLUDED.release_sequence,
                           version = EXCLUDED.version,
                           updated_at = CURRENT_TIMESTAMP
                       WHERE cephas_release_floor.release_sequence < EXCLUDED.release_sequence
                          OR (cephas_release_floor.release_sequence = EXCLUDED.release_sequence
                              AND cephas_release_floor.version = EXCLUDED.version)
                       RETURNING release_sequence, version""",
                    (tenant_id, deployment_id, product, sequence, version),
                )
                accepted = cursor.fetchone()
                if accepted is None:
                    connection.rollback()
                    return _json_response(
                        start_response, "409 Conflict", {"error": "stale_or_conflicting_release"}
                    )
                cursor.execute(
                    """INSERT INTO cephas_release_floor_audit
                       (client_id, tenant_id, deployment_id, product, release_sequence, version)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (client_id, tenant_id, deployment_id, product, sequence, version),
                )
            connection.commit()
        return _json_response(
            start_response, "200 OK",
            {"release_sequence": sequence, "version": version, "accepted": True},
        )
    except (psycopg.Error, RuntimeError, OSError, ValueError) as exc:
        # Log only the exception class; never log DSNs, SQL parameters, or tokens.
        logger.error("anchor operation failed (%s)", type(exc).__name__)
        return _json_response(start_response, "503 Service Unavailable", {"error": "anchor_unavailable"})


class _ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def serve():
    cert = os.environ["CEPHAS_ANCHOR_TLS_CERT_FILE"]
    key = os.environ["CEPHAS_ANCHOR_TLS_KEY_FILE"]
    client_ca = os.environ["CEPHAS_ANCHOR_CLIENT_CA_FILE"]
    host = os.environ.get("CEPHAS_ANCHOR_BIND", "127.0.0.1")
    port = int(os.environ.get("CEPHAS_ANCHOR_PORT", "9443"))
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.load_verify_locations(cafile=client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    server = make_server(host, port, application, server_class=_ThreadedWSGIServer,
                         handler_class=WSGIRequestHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    serve()
