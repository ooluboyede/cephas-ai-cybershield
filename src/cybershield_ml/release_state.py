"""Customer-owned durable anti-rollback state contract and PostgreSQL adapter."""

from typing import Protocol, runtime_checkable


@runtime_checkable
class ReleaseStateStore(Protocol):
    """Atomic customer state store for accepted signed model release sequences."""

    def get_release(
        self, *, tenant_id: str, deployment_id: str, product: str
    ) -> tuple[int, str] | None:
        """Return the stored floor, or None when no row exists."""
        ...

    def accept_release(
        self,
        *,
        tenant_id: str,
        deployment_id: str,
        product: str,
        release_sequence: int,
        version: str,
    ) -> None:
        """Atomically enforce and persist the minimum accepted release."""
        ...


class PostgresReleaseStateStore:
    """PostgreSQL-backed atomic release state keyed by tenant/deployment/product."""

    def __init__(self, connection_factory):
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        self._connection_factory = connection_factory

    @staticmethod
    def _validate_scope(tenant_id, deployment_id, product):
        if not all(
            isinstance(value, str) and value.strip()
            for value in (tenant_id, deployment_id, product)
        ):
            raise ValueError("tenant_id, deployment_id and product must be non-empty strings")

    def get_release(self, *, tenant_id: str, deployment_id: str, product: str):
        self._validate_scope(tenant_id, deployment_id, product)
        connection = self._connection_factory()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT release_sequence, version
                    FROM cephas_model_release_state
                    WHERE tenant_id = %s AND deployment_id = %s AND product = %s
                    """,
                    (tenant_id, deployment_id, product),
                )
                row = cursor.fetchone()
            return (int(row[0]), str(row[1])) if row is not None else None
        finally:
            connection.close()

    def accept_release(
        self,
        *,
        tenant_id: str,
        deployment_id: str,
        product: str,
        release_sequence: int,
        version: str,
    ) -> None:
        self._validate_scope(tenant_id, deployment_id, product)
        if not isinstance(version, str) or not version.strip():
            raise ValueError("version must be a non-empty string")
        if isinstance(release_sequence, bool) or not isinstance(release_sequence, int) or release_sequence < 1:
            raise ValueError("release_sequence must be a positive integer")

        connection = self._connection_factory()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO cephas_model_release_state
                        (tenant_id, deployment_id, product, release_sequence, version)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, deployment_id, product) DO UPDATE
                    SET release_sequence = EXCLUDED.release_sequence,
                        version = EXCLUDED.version,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE cephas_model_release_state.release_sequence < EXCLUDED.release_sequence
                       OR (
                           cephas_model_release_state.release_sequence = EXCLUDED.release_sequence
                           AND cephas_model_release_state.version = EXCLUDED.version
                       )
                    RETURNING release_sequence, version
                    """,
                    (tenant_id, deployment_id, product, release_sequence, version),
                )
                accepted = cursor.fetchone()
                if accepted is None:
                    raise ValueError("model release is stale or conflicts with the accepted sequence")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


POSTGRES_RELEASE_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cephas_model_release_state (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    product TEXT NOT NULL,
    release_sequence BIGINT NOT NULL CHECK (release_sequence >= 1),
    version TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, deployment_id, product)
);
"""

# Run as a controlled customer migration for an existing pre-deployment-scoped table.
# Review duplicate scope requirements before applying to a database with multiple deployments.
POSTGRES_RELEASE_STATE_MIGRATION_V2 = """
ALTER TABLE cephas_model_release_state
    ADD COLUMN IF NOT EXISTS deployment_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE cephas_model_release_state
    DROP CONSTRAINT IF EXISTS cephas_model_release_state_pkey;
ALTER TABLE cephas_model_release_state
    ADD CONSTRAINT cephas_model_release_state_pkey
    PRIMARY KEY (tenant_id, deployment_id, product);
"""
