"""Customer-hosted PostgreSQL registry adapter for DIRCM device identity."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from .dircm_identity import DeviceIdentityRegistry


class PostgresDeviceIdentityRegistry(DeviceIdentityRegistry):
    """Tenant-RLS-backed registry using a customer-supplied connection factory.

    The connection role must not own the tables and must not have BYPASSRLS.
    Every operation sets transaction-local tenant context before accessing data.
    """

    def __init__(self, connection_factory):
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        self._connection_factory = connection_factory

    @staticmethod
    def _set_tenant_context(cursor, tenant_id: str) -> None:
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id is required")
        cursor.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))

    def get_or_create_verified_device(
        self, *, tenant_id: str, source_id: str, identifier_type: str, identifier_digest: str
    ) -> str:
        if not all(isinstance(value, str) and value.strip() for value in (
            tenant_id, source_id, identifier_type, identifier_digest
        )):
            raise ValueError("verified device identity fields are required")
        if len(identifier_digest) != 64:
            raise ValueError("identifier_digest must be a SHA-256 HMAC hex digest")

        connection = self._connection_factory()
        try:
            with connection.cursor() as cursor:
                self._set_tenant_context(cursor, tenant_id)
                lock_key = "\x00".join((tenant_id, source_id, identifier_type, identifier_digest))
                cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,))
                cursor.execute(
                    """
                    SELECT device_id
                    FROM dircm_verified_identifiers
                    WHERE tenant_id = %s AND source_id = %s
                      AND identifier_type = %s AND identifier_digest = %s
                    """,
                    (tenant_id, source_id, identifier_type, identifier_digest),
                )
                row = cursor.fetchone()
                if row is not None:
                    device_id = str(row[0])
                else:
                    device_id = str(uuid4())
                    cursor.execute(
                        "INSERT INTO dircm_devices (tenant_id, device_id) VALUES (%s, %s)",
                        (tenant_id, device_id),
                    )
                    cursor.execute(
                        """
                        INSERT INTO dircm_verified_identifiers
                            (tenant_id, source_id, identifier_type, identifier_digest, device_id)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (tenant_id, source_id, identifier_type, identifier_digest, device_id),
                    )
            connection.commit()
            return device_id
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def create_match_candidate(
        self, *, tenant_id: str, source_id: str, identifier_type: str, identifier_digest: str,
        observed_at: datetime
    ) -> str:
        if not all(isinstance(value, str) and value.strip() for value in (
            tenant_id, source_id, identifier_type, identifier_digest
        )):
            raise ValueError("match candidate fields are required")
        if len(identifier_digest) != 64:
            raise ValueError("identifier_digest must be a SHA-256 HMAC hex digest")
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")

        connection = self._connection_factory()
        try:
            with connection.cursor() as cursor:
                self._set_tenant_context(cursor, tenant_id)
                cursor.execute(
                    """
                    INSERT INTO dircm_match_candidates
                        (tenant_id, candidate_id, source_id, identifier_type,
                         identifier_digest, first_seen_at, last_seen_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, source_id, identifier_type, identifier_digest)
                    DO UPDATE SET last_seen_at = GREATEST(
                        dircm_match_candidates.last_seen_at, EXCLUDED.last_seen_at
                    )
                    RETURNING candidate_id
                    """,
                    (tenant_id, str(uuid4()), source_id, identifier_type,
                     identifier_digest, observed_at, observed_at),
                )
                candidate_id = str(cursor.fetchone()[0])
            connection.commit()
            return candidate_id
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


POSTGRES_DIRCM_SCHEMA = """
CREATE TABLE IF NOT EXISTS dircm_devices (
    tenant_id TEXT NOT NULL,
    device_id UUID NOT NULL,
    lifecycle_state TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (lifecycle_state IN ('ACTIVE', 'RETIRED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS dircm_verified_identifiers (
    tenant_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    identifier_type TEXT NOT NULL,
    identifier_digest CHAR(64) NOT NULL
        CHECK (identifier_digest ~ '^[0-9a-f]{64}$'),
    device_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, source_id, identifier_type, identifier_digest),
    FOREIGN KEY (tenant_id, device_id)
        REFERENCES dircm_devices (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS dircm_match_candidates (
    tenant_id TEXT NOT NULL,
    candidate_id UUID NOT NULL,
    source_id TEXT NOT NULL,
    identifier_type TEXT NOT NULL,
    identifier_digest CHAR(64) NOT NULL
        CHECK (identifier_digest ~ '^[0-9a-f]{64}$'),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'CONFIRMED', 'REJECTED', 'EXPIRED')),
    PRIMARY KEY (tenant_id, candidate_id),
    UNIQUE (tenant_id, source_id, identifier_type, identifier_digest)
);

ALTER TABLE dircm_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE dircm_devices FORCE ROW LEVEL SECURITY;
ALTER TABLE dircm_verified_identifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE dircm_verified_identifiers FORCE ROW LEVEL SECURITY;
ALTER TABLE dircm_match_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE dircm_match_candidates FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dircm_devices_tenant_policy ON dircm_devices;
CREATE POLICY dircm_devices_tenant_policy ON dircm_devices
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS dircm_verified_identifiers_tenant_policy ON dircm_verified_identifiers;
CREATE POLICY dircm_verified_identifiers_tenant_policy ON dircm_verified_identifiers
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS dircm_match_candidates_tenant_policy ON dircm_match_candidates;
CREATE POLICY dircm_match_candidates_tenant_policy ON dircm_match_candidates
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
"""
