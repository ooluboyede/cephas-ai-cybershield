"""PostgreSQL DIRMC storage adapter using caller-supplied psycopg connection factory.

The factory must return a fresh connection to the customer-managed database. The
application must construct TrustedProductScope only from authenticated server context.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

from .contracts import TrustedProductScope
from .device_intelligence import DeviceFraudAssociation
from .device_storage import DeviceAssociationConflict

_DEVICE_KEY = re.compile(r"^hmac-sha256:v[1-9][0-9]*:[a-f0-9]{64}$")


class PostgresDeviceAssociationStore:
    """Customer-managed PostgreSQL adapter; transaction-local scope drives RLS."""

    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    @staticmethod
    def _set_scope(cursor: Any, scope: TrustedProductScope) -> None:
        cursor.execute(
            """SELECT
                set_config('cephas.tenant_id', %s, true),
                set_config('cephas.deployment_id', %s, true),
                set_config('cephas.environment', %s, true),
                set_config('cephas.allowed_products', %s, true),
                set_config('cephas.business_unit_id', %s, true)""",
            (
                scope.tenant_id,
                scope.deployment_id,
                scope.environment,
                ",".join(sorted(scope.allowed_products)),
                scope.business_unit_id or "",
            ),
        )

    @staticmethod
    def _validate(scope: TrustedProductScope, item: DeviceFraudAssociation) -> None:
        if (
            item.tenant_id != scope.tenant_id
            or item.deployment_id != scope.deployment_id
            or item.environment != scope.environment
            or item.product_id not in scope.allowed_products
            or item.business_unit_id != scope.business_unit_id
        ):
            raise ValueError("device association is outside the authenticated scope")
        if not _DEVICE_KEY.fullmatch(item.device_key):
            raise ValueError("device key must be a versioned HMAC-SHA256 pseudonym")

    @staticmethod
    def _canonical(item: DeviceFraudAssociation) -> tuple[str, str]:
        payload = item.model_dump(mode="json")
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        return canonical, hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append(self, scope: TrustedProductScope, item: DeviceFraudAssociation) -> bool:
        """Atomically insert association + audit; exact retry is idempotent."""
        self._validate(scope, item)
        canonical, digest = self._canonical(item)
        connection = self._connection_factory()
        try:
            with connection.transaction():
                with connection.cursor() as cursor:
                    self._set_scope(cursor, scope)
                    cursor.execute(
                        """INSERT INTO dirmc_device_fraud_associations (
                            tenant_id, deployment_id, environment, product_id,
                            business_unit_id, device_key, case_id, association_status,
                            evidence_ref, occurred_at, record_json
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                        ON CONFLICT DO NOTHING RETURNING case_id""",
                        (
                            item.tenant_id, item.deployment_id, item.environment,
                            item.product_id, scope.business_unit_id or "", item.device_key,
                            item.case_id, item.association_status, item.evidence_ref,
                            item.occurred_at, canonical,
                        ),
                    )
                    inserted = cursor.fetchone()
                    if inserted is None:
                        cursor.execute(
                            """SELECT record_json::text FROM dirmc_device_fraud_associations
                            WHERE tenant_id=%s AND deployment_id=%s AND environment=%s
                            AND product_id=%s AND business_unit_id=%s
                            AND device_key=%s AND case_id=%s""",
                            (
                                item.tenant_id, item.deployment_id, item.environment,
                                item.product_id, scope.business_unit_id or "",
                                item.device_key, item.case_id,
                            ),
                        )
                        existing = cursor.fetchone()
                        if existing is None:
                            raise RuntimeError("conflicting association exists outside visible RLS scope")
                        existing_payload = existing[0]
                        if isinstance(existing_payload, str):
                            existing_payload = json.loads(existing_payload)
                        if existing_payload != json.loads(canonical):
                            raise DeviceAssociationConflict(
                                "case/device association already exists with different content"
                            )
                        return False
                    cursor.execute(
                        """INSERT INTO dirmc_device_association_audit (
                            tenant_id, deployment_id, environment, product_id,
                            business_unit_id, device_key, case_id, action, record_sha256
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,'association_inserted',%s)""",
                        (
                            item.tenant_id, item.deployment_id, item.environment,
                            item.product_id, scope.business_unit_id or "",
                            item.device_key, item.case_id, digest,
                        ),
                    )
                    return True
        finally:
            connection.close()

    def list_for_device(
        self, scope: TrustedProductScope, *, product_id: str, device_key: str
    ) -> tuple[DeviceFraudAssociation, ...]:
        if product_id not in scope.allowed_products:
            raise ValueError("device product is not authorised for this deployment")
        if not _DEVICE_KEY.fullmatch(device_key):
            raise ValueError("device key must be a versioned HMAC-SHA256 pseudonym")
        connection = self._connection_factory()
        try:
            with connection.transaction():
                with connection.cursor() as cursor:
                    self._set_scope(cursor, scope)
                    cursor.execute(
                        """SELECT record_json FROM dirmc_device_fraud_associations
                        WHERE tenant_id=%s AND deployment_id=%s AND environment=%s
                        AND product_id=%s AND business_unit_id=%s AND device_key=%s
                        ORDER BY occurred_at, case_id""",
                        (
                            scope.tenant_id, scope.deployment_id, scope.environment,
                            product_id, scope.business_unit_id or "", device_key,
                        ),
                    )
                    rows = cursor.fetchall()
                    return tuple(
                        DeviceFraudAssociation.model_validate(
                            row[0] if isinstance(row[0], dict) else json.loads(row[0])
                        )
                        for row in rows
                    )
        finally:
            connection.close()
