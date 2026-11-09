"""Deployment-bound trust configuration for customer-hosted CyberShield.

The hosting service must construct DeploymentTrustContext only from its verified
server-side authentication/session layer, never from request JSON or model metadata.
The publisher keyring must be provisioned through a separate authenticated
administrative channel and bound to the same tenant and deployment.
"""
from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Mapping


@dataclass(frozen=True)
class DeploymentTrustContext:
    tenant_id: str
    deployment_id: str

    def __post_init__(self):
        if not isinstance(self.tenant_id, str) or not self.tenant_id.strip():
            raise ValueError("tenant_id must be a non-empty string")
        if not isinstance(self.deployment_id, str) or not self.deployment_id.strip():
            raise ValueError("deployment_id must be a non-empty string")


@dataclass(frozen=True)
class TrustedPublisherKeyring:
    tenant_id: str
    deployment_id: str
    public_keys: Mapping[str, bytes | str]

    def __post_init__(self):
        if not self.tenant_id.strip() or not self.deployment_id.strip():
            raise ValueError("keyring tenant_id and deployment_id are required")
        if not self.public_keys:
            raise ValueError("deployment keyring cannot be empty")
        object.__setattr__(self, "public_keys", MappingProxyType(dict(self.public_keys)))
