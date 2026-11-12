"""Customer-owned durable anti-rollback state contract.

Production adapters must implement accept_release with a durable, tenant-scoped,
transactional compare-and-set. Do not use process-local memory for deployments.
"""
from typing import Protocol, runtime_checkable


@runtime_checkable
class ReleaseStateStore(Protocol):
    """Atomic customer state store for accepted signed model release sequences."""

    def accept_release(
        self,
        *,
        tenant_id: str,
        product: str,
        release_sequence: int,
        version: str,
    ) -> None:
        """Atomically enforce and persist the minimum accepted release.

        Implementations must reject a lower sequence and reject reuse of the
        current sequence for a different version. Repeating the same sequence
        and version is idempotent. State must survive process restarts and be
        shared by every CyberShield instance for the same deployment/tenant.
        Raise ValueError when the release is stale or conflicts with stored
        state; raise an operational exception if durable state is unavailable.
        """
        ...


class PostgresReleaseStateStore:
    """PostgreSQL-backed atomic anti-rollback store using a DB-API connection factory.

    The supplied factory must return a connection to the customer's PostgreSQL
    database. The table must be provisioned using POSTGRES_RELEASE_STATE_SCHEMA.
    No customer database credentials or data are stored by this package.
    """

    def __init__(self, connection_factory):
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        self._connection_factory = connection_factory

    def accept_release(
        self,
        *,
        tenant_id: str,
        product: str,
        release_sequence: int,
        version: str,
    ) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (tenant_id, product, version)):
            raise ValueError("tenant_id, product and version must be non-empty strings")
        if isinstance(release_sequence, bool) or not isinstance(release_sequence, int) or release_sequence < 1:
            raise ValueError("release_sequence must be a positive integer")

        connection = self._connection_factory()
        cursor = None
        try:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO cephas_model_release_state
                    (tenant_id, product, release_sequence, version)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant_id, product) DO UPDATE
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
                (tenant_id, product, release_sequence, version),
            )
            accepted = cursor.fetchone()
            if accepted is None:
                raise ValueError("model release is stale or conflicts with the accepted sequence")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()


POSTGRES_RELEASE_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cephas_model_release_state (
    tenant_id TEXT NOT NULL,
    product TEXT NOT NULL,
    release_sequence BIGINT NOT NULL CHECK (release_sequence >= 1),
    version TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, product)
);
"""
