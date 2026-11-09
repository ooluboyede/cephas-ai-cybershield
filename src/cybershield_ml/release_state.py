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
