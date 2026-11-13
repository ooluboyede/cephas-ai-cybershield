"""Customer-local durable storage for DIRMC device associations.

SQLite is an initial single-node reference adapter. Production multi-node deployments
must use a customer-managed database adapter with equivalent constraints and isolation.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from .contracts import TrustedProductScope
from .device_intelligence import DeviceFraudAssociation


_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_fraud_associations (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_id TEXT NOT NULL,
    business_unit_id TEXT NOT NULL DEFAULT '',
    device_key TEXT NOT NULL,
    case_id TEXT NOT NULL,
    association_status TEXT NOT NULL CHECK (
        association_status IN ('suspected', 'confirmed', 'cleared')
    ),
    evidence_ref TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (
        tenant_id, deployment_id, environment, product_id,
        business_unit_id, device_key, case_id
    )
);
CREATE INDEX IF NOT EXISTS idx_device_association_lookup
ON device_fraud_associations (
    tenant_id, deployment_id, environment, product_id,
    business_unit_id, device_key, occurred_at
);
CREATE TABLE IF NOT EXISTS device_association_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    product_id TEXT NOT NULL,
    business_unit_id TEXT NOT NULL DEFAULT '',
    device_key TEXT NOT NULL,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action = 'association_inserted'),
    record_sha256 TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TRIGGER IF NOT EXISTS device_association_audit_no_update
BEFORE UPDATE ON device_association_audit
BEGIN
    SELECT RAISE(ABORT, 'device association audit is append-only');
END;
CREATE TRIGGER IF NOT EXISTS device_association_audit_no_delete
BEFORE DELETE ON device_association_audit
BEGIN
    SELECT RAISE(ABORT, 'device association audit is append-only');
END;
"""


class DeviceAssociationConflict(ValueError):
    """An existing case/device association was replayed with different content."""


class SQLiteDeviceAssociationStore:
    """Single-node customer-controlled store; no cross-customer access methods."""

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(_SCHEMA)
        finally:
            connection.close()
        # Best-effort owner-only permissions on POSIX; Windows ACLs must be managed
        # by the customer deployment operator.
        try:
            os.chmod(self.database_path, 0o600)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(self.database_path) + suffix)
                if sidecar.exists():
                    os.chmod(sidecar, 0o600)
        except OSError:
            pass

    @staticmethod
    def _business_unit(scope: TrustedProductScope) -> str:
        return scope.business_unit_id or ""

    @staticmethod
    def _validate_scope(
        scope: TrustedProductScope,
        association: DeviceFraudAssociation,
    ) -> None:
        if (
            association.tenant_id != scope.tenant_id
            or association.deployment_id != scope.deployment_id
            or association.environment != scope.environment
            or association.product_id not in scope.allowed_products
            or association.business_unit_id != scope.business_unit_id
        ):
            raise ValueError("device association is outside the authenticated scope")

    def append(
        self,
        scope: TrustedProductScope,
        association: DeviceFraudAssociation,
    ) -> bool:
        """Insert once; exact replay is idempotent, conflicting replay is rejected."""
        self._validate_scope(scope, association)
        payload = association.model_dump(mode="json")
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        import hashlib
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        values = (
            association.tenant_id,
            association.deployment_id,
            association.environment,
            association.product_id,
            self._business_unit(scope),
            association.device_key,
            association.case_id,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT record_json FROM device_fraud_associations
                   WHERE tenant_id=? AND deployment_id=? AND environment=?
                   AND product_id=? AND business_unit_id=? AND device_key=? AND case_id=?""",
                values,
            ).fetchone()
            if existing:
                if existing["record_json"] == canonical:
                    connection.commit()
                    return False
                raise DeviceAssociationConflict(
                    "case/device association already exists with different content"
                )
            connection.execute(
                """INSERT INTO device_fraud_associations (
                    tenant_id, deployment_id, environment, product_id,
                    business_unit_id, device_key, case_id, association_status,
                    evidence_ref, occurred_at, record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values + (
                    association.association_status,
                    association.evidence_ref,
                    association.occurred_at.isoformat(),
                    canonical,
                ),
            )
            connection.execute(
                """INSERT INTO device_association_audit (
                    tenant_id, deployment_id, environment, product_id,
                    business_unit_id, device_key, case_id, action, record_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'association_inserted', ?)""",
                values + (digest,),
            )
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_for_device(
        self,
        scope: TrustedProductScope,
        *,
        product_id: str,
        device_key: str,
    ) -> tuple[DeviceFraudAssociation, ...]:
        """Read associations only within the caller's server-authenticated scope."""
        if product_id not in scope.allowed_products:
            raise ValueError("device product is not authorised for this deployment")
        if not device_key.startswith("hmac-sha256:v"):
            raise ValueError("device key must be a versioned HMAC pseudonym")
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT record_json FROM device_fraud_associations
                   WHERE tenant_id=? AND deployment_id=? AND environment=?
                   AND product_id=? AND business_unit_id=? AND device_key=?
                   ORDER BY occurred_at, case_id""",
                (
                    scope.tenant_id,
                    scope.deployment_id,
                    scope.environment,
                    product_id,
                    self._business_unit(scope),
                    device_key,
                ),
            ).fetchall()
            return tuple(
                DeviceFraudAssociation.model_validate_json(row["record_json"])
                for row in rows
            )
        finally:
            connection.close()

    def audit_count(self, scope: TrustedProductScope) -> int:
        """Return audit-row count for operational tests and scoped diagnostics."""
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT COUNT(*) AS count FROM device_association_audit
                   WHERE tenant_id=? AND deployment_id=? AND environment=?
                   AND business_unit_id=?""",
                (
                    scope.tenant_id,
                    scope.deployment_id,
                    scope.environment,
                    self._business_unit(scope),
                ),
            ).fetchone()
            return int(row["count"])
        finally:
            connection.close()
